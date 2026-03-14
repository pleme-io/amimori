mod collector;
mod config;
mod daemon;
mod db;
mod grpc;
mod mcp;
mod model;
mod state;

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "amimori",
    about = "amimori (網守) — continuous network profiler with gRPC + MCP"
)]
enum Cli {
    /// Run as persistent daemon with gRPC server and collectors
    Daemon {
        /// Path to YAML config file
        #[arg(long)]
        config: PathBuf,
    },
    /// Run as MCP server (queries daemon via gRPC)
    Mcp,
    /// One-shot scan: print current network state as JSON
    Scan,
    /// Show daemon status
    Status,
}

impl Default for Cli {
    fn default() -> Self {
        Self::Mcp
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Default to MCP mode when invoked with no args (MCP stdio convention)
    let cli = if std::env::args().len() <= 1 {
        Cli::Mcp
    } else {
        Cli::parse()
    };

    match cli {
        Cli::Daemon { config: config_path } => {
            // File + console logging for long-running daemon
            let log_dir = dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("/tmp"))
                .join("Library/Logs");
            let file_appender =
                tracing_appender::rolling::daily(&log_dir, "amimori-daemon.log");
            let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "amimori=info".into()),
                )
                .with_writer(non_blocking)
                .with_ansi(false)
                .init();

            tracing::info!("amimori daemon starting");
            let cfg = config::Config::load(&config_path)?;
            daemon::run(cfg).await?;
        }
        Cli::Mcp => {
            // Stderr-only tracing for MCP mode (stdout is for MCP protocol)
            tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .with_writer(std::io::stderr)
                .init();

            tracing::info!("amimori MCP starting");
            mcp::run().await?;
        }
        Cli::Scan => {
            // One-shot scan using collectors directly
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "amimori=info".into()),
                )
                .with_writer(std::io::stderr)
                .init();

            let cfg = config::Config::discover()?;
            run_scan(&cfg).await?;
        }
        Cli::Status => {
            let grpc_url = std::env::var("AMIMORI_GRPC_URL")
                .unwrap_or_else(|_| "http://localhost:50051".to_string());

            match grpc::proto::network_profiler_client::NetworkProfilerClient::connect(
                grpc_url.clone(),
            )
            .await
            {
                Ok(mut client) => {
                    let resp = client
                        .get_snapshot(grpc::proto::SnapshotRequest::default())
                        .await?;
                    let snapshot = resp.into_inner();
                    println!("amimori daemon: running");
                    println!("  gRPC endpoint: {grpc_url}");
                    println!("  Event sequence: {}", snapshot.sequence);
                    println!("  Interfaces: {}", snapshot.interfaces.len());
                    println!("  Hosts: {}", snapshot.hosts.len());
                    println!("  WiFi networks: {}", snapshot.wifi_networks.len());
                }
                Err(e) => {
                    println!("amimori daemon: not running");
                    println!("  Error connecting to {grpc_url}: {e}");
                }
            }
        }
    }

    Ok(())
}

async fn run_scan(config: &config::Config) -> anyhow::Result<()> {
    use crate::collector::Collector;

    // Run interface collector
    let iface_collector = collector::interface::InterfaceCollector::new(config);
    let interfaces = match iface_collector.collect().await? {
        collector::CollectorOutput::Interfaces(i) => i,
        _ => Vec::new(),
    };

    // Run ARP collector
    let arp_collector = collector::arp::ArpCollector::new(config);
    let arp_entries = match arp_collector.collect().await? {
        collector::CollectorOutput::Arp(e) => e,
        _ => Vec::new(),
    };

    // Build output
    let mut output = serde_json::Map::new();

    output.insert(
        "interfaces".to_string(),
        serde_json::to_value(&interfaces)?,
    );
    let oui_db = mac_oui::Oui::default().ok();
    output.insert(
        "arp_hosts".to_string(),
        serde_json::to_value(&arp_entries.iter().map(|e| {
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
        }).collect::<Vec<_>>())?,
    );

    // WiFi scan (macOS only)
    #[cfg(target_os = "macos")]
    {
        let wifi_collector = collector::wifi::WifiCollector::new(config);
        let wifi = match wifi_collector.collect().await? {
            collector::CollectorOutput::Wifi(w) => w,
            _ => Vec::new(),
        };
        output.insert("wifi_networks".to_string(), serde_json::to_value(&wifi)?);
    }

    let json = serde_json::to_string_pretty(&serde_json::Value::Object(output))?;
    println!("{json}");

    Ok(())
}
