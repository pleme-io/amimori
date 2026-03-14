mod collector;
mod config;
mod convergence;
mod daemon;
mod db;
mod enrichment;
mod error;
mod export;
mod event_bus;
mod grpc;
mod mcp;
mod model;
mod platform;
mod state;
mod topology;
#[allow(dead_code)]
mod traits;

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "amimori",
    about = "amimori (網守) — continuous network profiler",
    version
)]
enum Cli {
    /// Run as persistent daemon with collectors + gRPC server
    Daemon {
        /// Path to YAML config file (omit to use XDG auto-discovery or defaults)
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Run as MCP server (queries daemon via gRPC)
    Mcp,
    /// One-shot network scan, output JSON to stdout
    Scan {
        /// Interfaces to scan (default: all non-loopback)
        #[arg(short, long)]
        interface: Vec<String>,
    },
    /// Query daemon status via gRPC
    Status,
    /// Check network scan convergence
    Convergence {
        /// Wait for convergence instead of returning immediately
        #[arg(long)]
        wait: bool,
        /// Convergence threshold (0.0-1.0, default 0.95)
        #[arg(long, default_value = "0.95")]
        threshold: f32,
        /// Max wait time in seconds (default 300)
        #[arg(long, default_value = "300")]
        timeout: u64,
        /// Output as JSON instead of human-readable
        #[arg(long)]
        json: bool,
    },
    /// List discovered hosts
    Hosts {
        /// Filter by vendor name (case-insensitive substring)
        #[arg(long)]
        vendor: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show detailed host info by MAC or IP
    Host {
        /// MAC or IP address
        address: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// List network interfaces
    Interfaces,
    /// List WiFi networks
    Wifi,
    /// Show network topology
    Topology,
    /// Export host inventory
    Export {
        /// Format: csv or json (default: json)
        #[arg(long, default_value = "json")]
        format: String,
    },
    /// Send Wake-on-LAN packet
    Wake {
        /// MAC address of host to wake
        mac: String,
    },
    /// Show current configuration (defaults + overrides)
    Config,
    /// Show recent network changes
    Changes {
        /// Max events to show
        #[arg(long, default_value = "20")]
        limit: u32,
    },
}

impl Default for Cli {
    fn default() -> Self {
        Self::Mcp
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install rustls crypto provider before any TLS usage (reqwest, tonic, etc.)
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = if std::env::args().len() <= 1 {
        Cli::Mcp
    } else {
        Cli::parse()
    };

    match cli {
        Cli::Daemon { config: path } => {
            let cfg = match path {
                Some(p) => config::Config::load(&p)?,
                None => config::Config::discover()?,
            };
            init_daemon_logging(&cfg);
            daemon::run(cfg).await?;
        }
        Cli::Mcp => {
            tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .with_writer(std::io::stderr)
                .init();
            mcp::run().await?;
        }
        Cli::Scan { interface } => {
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "amimori=warn".into()),
                )
                .with_writer(std::io::stderr)
                .init();

            let mut cfg = config::Config::discover()?;
            if !interface.is_empty() {
                cfg.interfaces = interface;
            }
            run_scan(&cfg).await?;
        }
        Cli::Status => {
            let grpc_url = std::env::var("AMIMORI_GRPC_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:50051".to_string());

            match grpc::proto::network_profiler_client::NetworkProfilerClient::connect(
                grpc_url.clone(),
            )
            .await
            {
                Ok(mut client) => {
                    let resp = client
                        .get_snapshot(grpc::proto::SnapshotRequest::default())
                        .await?;
                    let s = resp.into_inner();
                    println!("amimori: running");
                    println!("  endpoint: {grpc_url}");
                    println!("  sequence: {}", s.sequence);
                    println!("  interfaces: {}", s.interfaces.len());
                    println!("  hosts: {}", s.hosts.len());
                    println!("  wifi: {}", s.wifi_networks.len());
                }
                Err(e) => {
                    eprintln!("amimori: not running ({grpc_url}: {e})");
                    std::process::exit(1);
                }
            }
        }
        Cli::Convergence { wait, threshold, timeout, json } => {
            let grpc_url = std::env::var("AMIMORI_GRPC_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:50051".to_string());

            let mut client = match grpc::proto::network_profiler_client::NetworkProfilerClient::connect(
                grpc_url.clone(),
            ).await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("amimori: not running ({grpc_url}: {e})");
                    std::process::exit(1);
                }
            };

            let resp = if wait {
                client.wait_for_convergence(grpc::proto::ConvergenceRequest {
                    threshold,
                    timeout_secs: timeout as u32,
                }).await?
            } else {
                client.get_convergence(grpc::proto::Empty {}).await?
            };

            let c = resp.into_inner();

            if json {
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                    "score": c.score,
                    "phase": c.phase,
                    "converged": c.phase == "converged",
                    "uptime_secs": c.uptime_secs,
                    "total_hosts": c.total_hosts,
                    "enriched_hosts": c.enriched_hosts,
                    "since_new_host_secs": c.since_new_host_secs,
                    "since_new_service_secs": c.since_new_service_secs,
                    "stable_arp_cycles": c.stable_arp_cycles,
                    "stable_nmap_cycles": c.stable_nmap_cycles,
                    "collectors_reported": c.collectors_reported,
                    "expected_collectors": c.expected_collectors,
                }))?);
            } else {
                println!("convergence: {:.0}% ({})", c.score * 100.0, c.phase);
                println!("  hosts: {} ({} enriched)", c.total_hosts, c.enriched_hosts);
                println!("  since new host: {}s", c.since_new_host_secs);
                println!("  since new service: {}s", c.since_new_service_secs);
                println!("  stable ARP cycles: {}", c.stable_arp_cycles);
                println!("  stable nmap cycles: {}", c.stable_nmap_cycles);
                println!("  collectors: {}/{}", c.collectors_reported, c.expected_collectors);
                println!("  uptime: {}s", c.uptime_secs);
                if c.phase == "converged" {
                    println!("\n✓ Network converged — safe to analyze.");
                } else {
                    println!("\n⏳ Not yet converged.");
                }
            }

            // Exit code 0 if converged, 1 if not
            if c.phase != "converged" && !wait {
                std::process::exit(1);
            }
        }
        Cli::Hosts { vendor, json } => {
            let mut client = grpc_client().await;
            let resp = client.get_snapshot(grpc::proto::SnapshotRequest::default()).await?;
            let mut hosts = resp.into_inner().hosts;
            if let Some(ref v) = vendor {
                let v = v.to_lowercase();
                hosts.retain(|h| h.vendor.to_lowercase().contains(&v));
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&hosts.iter().map(|h| serde_json::json!({
                    "mac": h.mac, "vendor": h.vendor, "hostname": h.hostname,
                    "ipv4": h.ipv4, "outlier_score": h.outlier_score,
                })).collect::<Vec<_>>())?);
            } else {
                println!("{} hosts", hosts.len());
                for h in &hosts {
                    let name = if h.hostname.is_empty() { &h.vendor } else { &h.hostname };
                    println!("  {} | {} | {:?}", h.mac, name, h.ipv4);
                }
            }
        }
        Cli::Host { address, json } => {
            let mut client = grpc_client().await;
            match client.get_host(grpc::proto::HostRequest { address }).await {
                Ok(resp) => {
                    let h = resp.into_inner();
                    if json {
                        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                            "mac": h.mac, "vendor": h.vendor, "hostname": h.hostname,
                            "ipv4": h.ipv4, "ipv6": h.ipv6, "os": h.os_hint,
                            "interface": h.interface, "outlier_score": h.outlier_score,
                            "services": h.services.iter().map(|s| serde_json::json!({
                                "port": s.port, "protocol": s.protocol, "name": s.name,
                                "version": s.version, "state": s.state,
                            })).collect::<Vec<_>>(),
                            "fingerprints": h.fingerprints.iter().map(|f| serde_json::json!({
                                "source": f.source, "category": f.category,
                                "key": f.key, "value": f.value, "confidence": f.confidence,
                            })).collect::<Vec<_>>(),
                        }))?);
                    } else {
                        println!("MAC: {}", h.mac);
                        println!("Vendor: {}", h.vendor);
                        println!("Hostname: {}", h.hostname);
                        println!("IPv4: {:?}", h.ipv4);
                        println!("OS: {}", h.os_hint);
                        println!("Outlier: {:.1}/5.0", h.outlier_score);
                        for s in &h.services {
                            println!("  {}/{} {} {} [{}]", s.port, s.protocol, s.name, s.version, s.state);
                        }
                        for f in &h.fingerprints {
                            println!("  {}.{} = {} ({} {:.0}%)", f.category, f.key, f.value, f.source, f.confidence * 100.0);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("host not found: {e}");
                    std::process::exit(1);
                }
            }
        }
        Cli::Interfaces => {
            let mut client = grpc_client().await;
            let resp = client.list_interfaces(grpc::proto::Empty {}).await?;
            for i in &resp.into_inner().interfaces {
                let status = if i.is_up { "UP" } else { "DOWN" };
                println!("  {} [{}] {status} ipv4={:?} gw={} dns={:?}", i.name, i.kind, i.ipv4, i.gateway, i.dns);
            }
        }
        Cli::Wifi => {
            let mut client = grpc_client().await;
            let resp = client.list_wifi_networks(grpc::proto::Empty {}).await?;
            for w in &resp.into_inner().networks {
                let snr = w.rssi - w.noise;
                println!("  {} ch{} {} rssi={} snr={} {}", w.ssid, w.channel, w.band, w.rssi, snr, w.security);
            }
        }
        Cli::Topology => {
            let mut client = grpc_client().await;
            let resp = client.get_snapshot(grpc::proto::SnapshotRequest::default()).await?;
            let s = resp.into_inner();
            let hosts: Vec<_> = s.hosts.iter().map(grpc::proto_to_host_info).collect();
            let interfaces: Vec<_> = s.interfaces.iter().map(grpc::proto_to_interface_info).collect();
            print!("{}", crate::topology::format_topology(&crate::topology::build_topology(&hosts, &interfaces)));
        }
        Cli::Export { format } => {
            let mut client = grpc_client().await;
            let resp = client.get_snapshot(grpc::proto::SnapshotRequest::default()).await?;
            let hosts: Vec<_> = resp.into_inner().hosts.iter()
                .map(grpc::proto_to_host_info).collect();
            match format.as_str() {
                "csv" => print!("{}", crate::export::to_csv(&hosts)),
                _ => print!("{}", crate::export::to_json(&hosts)),
            }
        }
        Cli::Wake { mac } => {
            let mac_bytes: Vec<u8> = mac.split(':').filter_map(|s| u8::from_str_radix(s, 16).ok()).collect();
            if mac_bytes.len() != 6 {
                eprintln!("invalid MAC address: {mac}");
                std::process::exit(1);
            }
            let mut arr = [0u8; 6];
            arr.copy_from_slice(&mac_bytes);
            match wake_on_lan::MagicPacket::new(&arr).send() {
                Ok(()) => println!("WoL sent to {mac}"),
                Err(e) => { eprintln!("WoL failed: {e}"); std::process::exit(1); }
            }
        }
        Cli::Config => {
            let cfg = config::Config::discover().unwrap_or_default();
            println!("{}", serde_yaml::to_string(&cfg)?);
        }
        Cli::Changes { limit } => {
            let mut client = grpc_client().await;
            let resp = client.get_changes(grpc::proto::ChangesRequest {
                since_sequence: 0, limit,
            }).await?;
            let r = resp.into_inner();
            if r.events.is_empty() {
                println!("No changes (sequence: {})", r.current_sequence);
            } else {
                println!("{} events (sequence: {})", r.events.len(), r.current_sequence);
                for e in &r.events {
                    let desc = match &e.change {
                        Some(grpc::proto::delta_update::Change::HostAdded(h)) => format!("+ host {} {}", h.mac, h.vendor),
                        Some(grpc::proto::delta_update::Change::HostRemoved(h)) => format!("- host {}", h.mac),
                        Some(grpc::proto::delta_update::Change::HostUpdated(h)) => format!("~ host {} {}", h.mac, h.vendor),
                        Some(grpc::proto::delta_update::Change::WifiUpdated(w)) => format!("~ wifi rssi={}", w.rssi),
                        Some(grpc::proto::delta_update::Change::WifiAdded(w)) => format!("+ wifi {}", w.ssid),
                        Some(grpc::proto::delta_update::Change::WifiRemoved(w)) => format!("- wifi {}", w.bssid),
                        _ => "other".into(),
                    };
                    println!("  [{:>6}] {desc}", e.sequence);
                }
            }
        }
    }

    Ok(())
}

async fn grpc_client() -> grpc::proto::network_profiler_client::NetworkProfilerClient<tonic::transport::Channel> {
    let grpc_url = std::env::var("AMIMORI_GRPC_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:50051".to_string());
    match grpc::proto::network_profiler_client::NetworkProfilerClient::connect(grpc_url.clone()).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("amimori: not running ({grpc_url}: {e})");
            std::process::exit(1);
        }
    }
}

fn init_daemon_logging(cfg: &config::Config) {
    let log_dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("Library/Logs");

    let file_appender = tracing_appender::rolling::daily(&log_dir, "amimori-daemon.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| format!("amimori={}", cfg.logging.level).into());

    if cfg.logging.format == "json" {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_writer(non_blocking)
            .with_ansi(false)
            .json()
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_writer(non_blocking)
            .with_ansi(false)
            .init();
    }

    // Intentionally leak the guard so the log writer lives for the process lifetime.
    // This is the standard pattern for tracing-appender with long-lived processes.
    std::mem::forget(guard);
}

async fn run_scan(config: &config::Config) -> anyhow::Result<()> {
    use crate::collector::Collector;

    let iface_collector = collector::interface::InterfaceCollector::new(config);
    let interfaces = match iface_collector.collect().await? {
        collector::CollectorOutput::Interfaces(i) => i,
        _ => Vec::new(),
    };

    let cmd_runner: std::sync::Arc<dyn traits::CommandRunner> =
        std::sync::Arc::new(traits::SystemCommandRunner);
    let arp_collector = collector::arp::ArpCollector::new(config, cmd_runner);
    let arp_entries = match arp_collector.collect().await? {
        collector::CollectorOutput::Arp(e) => e,
        _ => Vec::new(),
    };

    let oui_db = mac_oui::Oui::default().ok();

    let mut output = serde_json::Map::new();
    output.insert("interfaces".into(), serde_json::to_value(&interfaces)?);
    output.insert(
        "hosts".into(),
        serde_json::to_value(
            &arp_entries
                .iter()
                .map(|e| {
                    let vendor = oui_db
                        .as_ref()
                        .and_then(|db| db.lookup_by_mac(&e.mac).ok().flatten())
                        .map(|entry| entry.company_name.as_str())
                        .unwrap_or("");
                    serde_json::json!({
                        "ip": e.ip.to_string(),
                        "mac": e.mac,
                        "interface": e.interface,
                        "hostname": e.hostname,
                        "vendor": vendor,
                    })
                })
                .collect::<Vec<_>>(),
        )?,
    );

    #[cfg(target_os = "macos")]
    {
        let wifi_collector = collector::wifi::WifiCollector::new(config);
        if let Ok(collector::CollectorOutput::Wifi(wifi)) = wifi_collector.collect().await {
            output.insert("wifi_networks".into(), serde_json::to_value(&wifi)?);
        }
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::Value::Object(output))?
    );
    Ok(())
}
