use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::collector::arp::ArpCollector;
use crate::collector::interface::InterfaceCollector;
use crate::collector::scanner::NmapCollector;
use crate::collector::{self, ActorConfig, Collector};
use crate::config::Config;
use crate::event_bus::{EventBus, TriggerKind};
use crate::grpc;
use crate::state::StateEngine;

pub async fn run(config: Config) -> anyhow::Result<()> {
    // ── Phase 1: Validate environment ──────────────────────────────────
    tracing::info!("phase 1/5: validating environment");

    let db_path = config.resolved_db_path();
    if let Some(parent) = db_path.parent() {
        if !parent.exists() {
            tracing::info!(path = %parent.display(), "creating data directory");
        }
    }

    // ── Phase 2: Create event bus ──────────────────────────────────────
    tracing::info!("phase 2/5: creating event bus");

    let bus = EventBus::new(64);

    // ── Phase 3: Initialize database + state engine ────────────────────
    tracing::info!("phase 3/5: initializing database and state engine");

    let engine = Arc::new(
        StateEngine::new(&config, Some(bus.sender()))
            .await
            .map_err(|e| anyhow::anyhow!("state engine initialization failed: {e}"))?,
    );

    // ── Phase 4: Build actors (pre-flight checks) ──────────────────────
    tracing::info!("phase 4/5: initializing collector actors");

    let mut actors: Vec<(Box<dyn Collector>, ActorConfig)> = Vec::new();

    // Interface watcher — the root event source (interval-only, no reactive triggers)
    if config.collectors.interface.enable {
        actors.push((
            Box::new(InterfaceCollector::new(&config)),
            ActorConfig::interval_only(),
        ));
    }

    // ARP collector — reactive on interface/network changes
    if config.collectors.arp.enable {
        match tokio::process::Command::new("/usr/sbin/arp")
            .arg("-a")
            .output()
            .await
        {
            Ok(output) if output.status.success() => {
                let actor_cfg = if config.collectors.arp.reactive {
                    ActorConfig::reactive(
                        vec![TriggerKind::InterfaceChanged, TriggerKind::NetworkChanged],
                        config.collectors.arp.reactive_cooldown,
                    )
                } else {
                    ActorConfig::interval_only()
                };
                actors.push((Box::new(ArpCollector::new(&config)), actor_cfg));
            }
            _ => {
                tracing::warn!("arp command not available, collector disabled");
            }
        }
    }

    // WiFi collector — reactive on interface changes
    #[cfg(target_os = "macos")]
    if config.collectors.wifi.enable {
        use crate::collector::wifi::WifiCollector;
        let actor_cfg = if config.collectors.wifi.reactive {
            ActorConfig::reactive(
                vec![TriggerKind::InterfaceChanged],
                config.collectors.wifi.reactive_cooldown,
            )
        } else {
            ActorConfig::interval_only()
        };
        actors.push((Box::new(WifiCollector::new(&config)), actor_cfg));
    }

    #[cfg(not(target_os = "macos"))]
    if config.collectors.wifi.enable {
        tracing::info!("wifi collector only available on macOS, skipping");
    }

    // nmap collector — reactive on network changes
    if config.collectors.nmap.enable {
        match tokio::process::Command::new(&config.collectors.nmap.bin)
            .arg("--version")
            .output()
            .await
        {
            Ok(output) if output.status.success() => {
                let ver = String::from_utf8_lossy(&output.stdout);
                let first_line = ver.lines().next().unwrap_or("unknown");
                tracing::info!(version = first_line, "nmap available");

                let actor_cfg = if config.collectors.nmap.reactive {
                    ActorConfig::reactive(
                        vec![TriggerKind::NetworkChanged],
                        config.collectors.nmap.reactive_cooldown,
                    )
                } else {
                    ActorConfig::interval_only()
                };
                actors.push((
                    Box::new(NmapCollector::new(&config, Arc::clone(&engine))),
                    actor_cfg,
                ));
            }
            _ => {
                tracing::warn!(
                    bin = %config.collectors.nmap.bin,
                    "nmap not found, scanner disabled"
                );
            }
        }
    }

    if actors.is_empty() {
        anyhow::bail!(
            "no collector actors could be initialized — check config and tool availability"
        );
    }

    // ── Phase 5: Start services ────────────────────────────────────────
    tracing::info!("phase 5/5: starting services");

    let cancel = CancellationToken::new();

    // gRPC server
    let grpc_engine = Arc::clone(&engine);
    let grpc_cancel = cancel.clone();
    let grpc_addr = config.grpc.socket_addr();
    let grpc_handle = tokio::spawn(async move {
        if let Err(e) = grpc::serve(grpc_engine, &grpc_addr, grpc_cancel).await {
            tracing::error!(error = %e, "gRPC server error");
        }
    });

    // Stale host pruner
    engine.spawn_pruner(
        config.storage.retention.host_ttl,
        config.storage.retention.prune_interval,
        cancel.clone(),
    );

    // Collector actors (event-driven + fallback intervals)
    let actor_engine = Arc::clone(&engine);
    let actor_cancel = cancel.clone();
    let enabled: Vec<String> = actors.iter().map(|(c, _)| c.name().to_string()).collect();
    let reactive_count = actors
        .iter()
        .filter(|(_, cfg)| !cfg.triggers.is_empty())
        .count();

    // ── Ready ──────────────────────────────────────────────────────────
    tracing::info!(
        actors = ?enabled,
        reactive = reactive_count,
        grpc = %config.grpc.socket_addr(),
        interfaces = ?config.interfaces,
        db = %db_path.display(),
        retention_ttl = config.storage.retention.host_ttl,
        "amimori daemon ready (event-driven actor model)"
    );

    let actor_handle = tokio::spawn(async move {
        collector::run_actors(
            actors,
            || bus.subscribe(),
            actor_engine,
            actor_cancel,
        )
        .await;
    });

    // ── Await shutdown ─────────────────────────────────────────────────
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutdown signal received, stopping actors");
    cancel.cancel();

    let shutdown = async {
        let _ = grpc_handle.await;
        let _ = actor_handle.await;
    };

    match tokio::time::timeout(std::time::Duration::from_secs(10), shutdown).await {
        Ok(()) => tracing::info!("amimori daemon stopped cleanly"),
        Err(_) => tracing::warn!("shutdown timed out after 10s"),
    }

    Ok(())
}
