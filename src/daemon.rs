use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::collector::{self, Collector};
use crate::collector::arp::ArpCollector;
use crate::collector::interface::InterfaceCollector;
use crate::collector::scanner::NmapCollector;
use crate::config::Config;
use crate::grpc;
use crate::state::StateEngine;

pub async fn run(config: Config) -> anyhow::Result<()> {
    let db_path = config.resolved_db_path();
    let engine = Arc::new(StateEngine::new(&db_path, config.event_buffer_size).await?);

    // Build collectors based on config
    let mut collectors: Vec<Box<dyn Collector>> = vec![
        Box::new(ArpCollector::new(&config)),
        Box::new(InterfaceCollector::new(&config)),
    ];

    #[cfg(target_os = "macos")]
    {
        use crate::collector::wifi::WifiCollector;
        collectors.push(Box::new(WifiCollector::new(&config)));
    }

    if config.nmap.enable {
        collectors.push(Box::new(NmapCollector::new(&config)));
    }

    let cancel = CancellationToken::new();

    // Start gRPC server
    let grpc_engine = Arc::clone(&engine);
    let grpc_cancel = cancel.clone();
    let grpc_port = config.grpc_port;
    let grpc_handle = tokio::spawn(async move {
        if let Err(e) = grpc::serve(grpc_engine, grpc_port, grpc_cancel).await {
            tracing::error!("gRPC server error: {e}");
        }
    });

    // Start collectors
    let collect_engine = Arc::clone(&engine);
    let collect_cancel = cancel.clone();
    let collect_handle = tokio::spawn(async move {
        collector::run_collectors(collectors, collect_engine, collect_cancel).await;
    });

    tracing::info!(
        "amimori daemon running — gRPC on :{}, {} interfaces monitored",
        config.grpc_port,
        config.interfaces.len(),
    );

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutdown signal received");
    cancel.cancel();

    // Wait for tasks to finish
    let _ = grpc_handle.await;
    let _ = collect_handle.await;

    tracing::info!("amimori daemon stopped");
    Ok(())
}
