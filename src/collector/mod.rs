pub mod arp;
pub mod interface;
pub mod scanner;
#[cfg(target_os = "macos")]
pub mod wifi;

use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::model::{ArpEntry, InterfaceInfo, NmapHost, WifiInfo};
use crate::state::StateEngine;

/// Output produced by a collector.
pub enum CollectorOutput {
    Arp(Vec<ArpEntry>),
    Interfaces(Vec<InterfaceInfo>),
    Wifi(Vec<WifiInfo>),
    Nmap {
        interface: String,
        hosts: Vec<NmapHost>,
    },
}

/// Trait for periodic data collectors.
#[async_trait::async_trait]
pub trait Collector: Send + Sync {
    fn name(&self) -> &str;
    fn interval(&self) -> Duration;
    async fn collect(&self) -> anyhow::Result<CollectorOutput>;
}

/// Run all collectors on their configured intervals. Feeds results into the state engine.
pub async fn run_collectors(
    collectors: Vec<Box<dyn Collector>>,
    engine: Arc<StateEngine>,
    cancel: CancellationToken,
) {
    let mut handles = Vec::new();

    for collector in collectors {
        let engine = Arc::clone(&engine);
        let cancel = cancel.clone();
        let name = collector.name().to_string();

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(collector.interval());
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        tracing::info!("collector {name} shutting down");
                        break;
                    }
                    _ = interval.tick() => {
                        match collector.collect().await {
                            Ok(output) => {
                                if let Err(e) = apply_output(&engine, output).await {
                                    tracing::error!("collector {name}: failed to apply output: {e}");
                                }
                            }
                            Err(e) => {
                                tracing::warn!("collector {name}: {e}");
                            }
                        }
                    }
                }
            }
        });

        handles.push(handle);
    }

    // Wait for all collector tasks to finish
    for handle in handles {
        let _ = handle.await;
    }
}

async fn apply_output(engine: &StateEngine, output: CollectorOutput) -> anyhow::Result<()> {
    match output {
        CollectorOutput::Arp(entries) => {
            engine.apply_arp_results(&entries).await?;
        }
        CollectorOutput::Interfaces(ifaces) => {
            engine.apply_interface_state(&ifaces).await?;
        }
        CollectorOutput::Wifi(networks) => {
            engine.apply_wifi_scan(&networks).await?;
        }
        CollectorOutput::Nmap { interface, hosts } => {
            engine.apply_nmap_results(&interface, &hosts).await?;
        }
    }
    Ok(())
}
