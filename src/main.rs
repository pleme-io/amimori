mod collector;
mod config;
mod daemon;
mod db;
mod enrichment;
mod error;
mod event_bus;
mod grpc;
mod mcp;
mod model;
mod platform;
mod state;
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
}

impl Default for Cli {
    fn default() -> Self {
        Self::Mcp
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    }

    Ok(())
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

    let arp_collector = collector::arp::ArpCollector::new(config);
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
