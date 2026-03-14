pub mod arp;
pub mod arp_scan;
pub mod banner;
pub mod dns;
pub mod interface;
pub mod lldp;
pub mod mdns;
pub mod netbios;
pub mod passive;
pub mod scanner;
pub mod ssdp;
pub mod tls;
#[cfg(target_os = "macos")]
pub mod wifi;

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::event_bus::{TriggerEvent, TriggerKind};
use crate::model::{ArpEntry, InterfaceInfo, NmapHost, WifiInfo};
use crate::collector::banner::BannerResult;
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
    Banners(Vec<BannerResult>),
}

/// Trait for data collectors. Pure collection logic — no scheduling.
#[async_trait::async_trait]
pub trait Collector: Send + Sync {
    fn name(&self) -> &str;
    fn interval(&self) -> Duration;
    fn max_failures(&self) -> u32;
    async fn collect(&self) -> anyhow::Result<CollectorOutput>;
}

// ── Actor scheduling configuration ────────────────────────────────────────

/// Defines how an actor is scheduled: fallback interval + reactive triggers.
pub struct ActorConfig {
    /// Which trigger events wake this actor immediately.
    pub triggers: Vec<TriggerKind>,
    /// Cooldown after a reactive trigger (debounce).
    pub cooldown: Duration,
}

impl ActorConfig {
    /// Interval-only actor (no reactive triggers). Used for the interface watcher.
    pub fn interval_only() -> Self {
        Self {
            triggers: Vec::new(),
            cooldown: Duration::ZERO,
        }
    }

    /// Reactive actor that responds to events with a cooldown.
    pub fn reactive(triggers: Vec<TriggerKind>, cooldown_secs: u64) -> Self {
        Self {
            triggers,
            cooldown: Duration::from_secs(cooldown_secs),
        }
    }
}

// ── Collector lifecycle state machine ──────────────────────────────────────

/// Formal state machine for collector lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CollectorState {
    /// Active and collecting.
    Active { consecutive_failures: u32 },
    /// Disabled after exceeding max_failures.
    Disabled { total_failures: u32 },
}

impl CollectorState {
    pub fn new() -> Self {
        Self::Active {
            consecutive_failures: 0,
        }
    }

    pub fn on_success(&self) -> Self {
        match self {
            Self::Active { .. } => Self::Active {
                consecutive_failures: 0,
            },
            Self::Disabled { .. } => self.clone(),
        }
    }

    pub fn on_failure(&self, max_failures: u32) -> Self {
        match self {
            Self::Active {
                consecutive_failures,
            } => {
                let new_count = consecutive_failures + 1;
                if new_count >= max_failures {
                    Self::Disabled {
                        total_failures: new_count,
                    }
                } else {
                    Self::Active {
                        consecutive_failures: new_count,
                    }
                }
            }
            Self::Disabled { .. } => self.clone(),
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active { .. })
    }

    pub fn failure_count(&self) -> u32 {
        match self {
            Self::Active {
                consecutive_failures,
            } => *consecutive_failures,
            Self::Disabled { total_failures } => *total_failures,
        }
    }
}

impl fmt::Display for CollectorState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active {
                consecutive_failures: 0,
            } => write!(f, "active"),
            Self::Active {
                consecutive_failures,
            } => write!(f, "active(failures={consecutive_failures})"),
            Self::Disabled { total_failures } => {
                write!(f, "disabled(failures={total_failures})")
            }
        }
    }
}

// ── Actor runner ───────────────────────────────────────────────────────────

/// Spawn each collector as an independent actor with a three-branch select loop:
/// 1. Cancellation (shutdown)
/// 2. Fallback interval tick (periodic collection)
/// 3. Reactive trigger from event bus (immediate collection with debounce)
///
/// Collectors without triggers (like interface watcher) run interval-only.
pub async fn run_actors(
    actors: Vec<(Box<dyn Collector>, ActorConfig)>,
    trigger_rx_factory: impl Fn() -> broadcast::Receiver<TriggerEvent>,
    engine: Arc<StateEngine>,
    cancel: CancellationToken,
) {
    let mut handles = Vec::with_capacity(actors.len());

    for (collector, actor_cfg) in actors {
        let engine = Arc::clone(&engine);
        let cancel = cancel.clone();
        let name = collector.name().to_string();
        let max_failures = collector.max_failures();
        let interval_dur = collector.interval();
        let triggers = actor_cfg.triggers;
        let cooldown = actor_cfg.cooldown;
        let mut trigger_rx = if triggers.is_empty() {
            None
        } else {
            Some(trigger_rx_factory())
        };

        let handle = tokio::spawn(async move {
            let mut state = CollectorState::new();
            // Use sleep + Instant instead of Interval so we can reset after reactive runs.
            let mut next_tick = tokio::time::Instant::now() + interval_dur;
            let mut last_reactive = tokio::time::Instant::now() - cooldown; // allow immediate first trigger

            loop {
                if !state.is_active() {
                    tracing::warn!(actor = %name, state = %state, "actor disabled, awaiting shutdown");
                    cancel.cancelled().await;
                    break;
                }

                // Build the three-branch select.
                // Branch 3 (trigger) is only active if we have triggers configured.
                let triggered = tokio::select! {
                    () = cancel.cancelled() => {
                        tracing::info!(actor = %name, state = %state, "shutting down");
                        break;
                    }
                    () = tokio::time::sleep_until(next_tick) => {
                        false // interval tick
                    }
                    result = async {
                        match trigger_rx.as_mut() {
                            Some(rx) => match rx.recv().await {
                                Ok(event) if event.matches(&triggers) => Ok(event),
                                Ok(_) => Err(false),  // wrong event type, loop again
                                Err(broadcast::error::RecvError::Lagged(n)) => {
                                    tracing::debug!(actor = %name, skipped = n, "trigger receiver lagged");
                                    Err(false) // loop again, fallback interval covers it
                                }
                                Err(broadcast::error::RecvError::Closed) => {
                                    tracing::debug!(actor = %name, "trigger bus closed");
                                    Err(true) // bus closed, run interval-only
                                }
                            },
                            None => std::future::pending().await, // no triggers configured, never resolves
                        }
                    } => {
                        match result {
                            Ok(event) => {
                                // Debounce: skip if within cooldown
                                let now = tokio::time::Instant::now();
                                if now.duration_since(last_reactive) < cooldown {
                                    tracing::trace!(actor = %name, "trigger debounced");
                                    continue;
                                }
                                tracing::debug!(
                                    actor = %name,
                                    trigger = ?event.kind(),
                                    "reactive trigger"
                                );
                                last_reactive = now;
                                true
                            }
                            Err(true) => {
                                // Bus closed — disable triggers, continue interval-only
                                trigger_rx = None;
                                continue;
                            }
                            Err(false) => continue, // wrong event or lagged, loop
                        }
                    }
                };

                // Run collection
                let run_kind = if triggered { "reactive" } else { "interval" };
                match collector.collect().await {
                    Ok(output) => {
                        let prev_failures = state.failure_count();
                        state = state.on_success();

                        if prev_failures > 0 {
                            tracing::info!(
                                actor = %name,
                                prior_failures = prev_failures,
                                kind = run_kind,
                                "recovered"
                            );
                        }

                        if let Err(e) = apply_output(&engine, output).await {
                            tracing::error!(
                                actor = %name,
                                error = %e,
                                kind = run_kind,
                                "failed to apply output"
                            );
                        }
                    }
                    Err(e) => {
                        state = state.on_failure(max_failures);
                        tracing::warn!(
                            actor = %name,
                            error = %e,
                            state = %state,
                            kind = run_kind,
                            "collection failed"
                        );
                    }
                }

                // Reset interval timer after any collection (reactive or periodic).
                // This prevents double-scanning (reactive run + interval tick close together).
                next_tick = tokio::time::Instant::now() + interval_dur;
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }
}

async fn apply_output(engine: &StateEngine, output: CollectorOutput) -> anyhow::Result<()> {
    match output {
        CollectorOutput::Arp(entries) => engine.apply_arp_results(&entries).await,
        CollectorOutput::Interfaces(ifaces) => engine.apply_interface_state(&ifaces).await,
        CollectorOutput::Wifi(networks) => engine.apply_wifi_scan(&networks).await,
        CollectorOutput::Nmap { interface, hosts } => {
            engine.apply_nmap_results(&interface, &hosts).await
        }
        CollectorOutput::Banners(results) => engine.apply_banners(&results).await,
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collector_state_starts_active() {
        let state = CollectorState::new();
        assert!(state.is_active());
        assert_eq!(state.failure_count(), 0);
    }

    #[test]
    fn collector_state_success_resets_failures() {
        let state = CollectorState::Active {
            consecutive_failures: 5,
        };
        let next = state.on_success();
        assert!(next.is_active());
        assert_eq!(next.failure_count(), 0);
    }

    #[test]
    fn collector_state_failure_increments() {
        let state = CollectorState::new();
        let next = state.on_failure(10);
        assert!(next.is_active());
        assert_eq!(next.failure_count(), 1);
    }

    #[test]
    fn collector_state_max_failures_disables() {
        let mut state = CollectorState::new();
        for _ in 0..5 {
            state = state.on_failure(5);
        }
        assert!(!state.is_active());
        assert_eq!(state.failure_count(), 5);
    }

    #[test]
    fn collector_state_max_failures_one_disables_immediately() {
        let state = CollectorState::new();
        let next = state.on_failure(1);
        assert!(!next.is_active());
    }

    #[test]
    fn collector_state_disabled_is_terminal() {
        let disabled = CollectorState::Disabled { total_failures: 3 };
        assert_eq!(disabled.on_success(), disabled);
        assert_eq!(disabled.on_failure(10), disabled);
    }

    #[test]
    fn collector_state_recovery_then_failure_again() {
        let mut state = CollectorState::new();
        state = state.on_failure(5);
        state = state.on_failure(5);
        assert_eq!(state.failure_count(), 2);
        state = state.on_success();
        assert_eq!(state.failure_count(), 0);
        state = state.on_failure(5);
        assert_eq!(state.failure_count(), 1);
    }

    #[test]
    fn collector_state_display() {
        assert_eq!(CollectorState::new().to_string(), "active");
        assert_eq!(
            CollectorState::Active {
                consecutive_failures: 3
            }
            .to_string(),
            "active(failures=3)"
        );
        assert_eq!(
            CollectorState::Disabled { total_failures: 5 }.to_string(),
            "disabled(failures=5)"
        );
    }

    #[test]
    fn actor_config_interval_only_has_no_triggers() {
        let cfg = ActorConfig::interval_only();
        assert!(cfg.triggers.is_empty());
    }

    #[test]
    fn actor_config_reactive_has_triggers() {
        let cfg = ActorConfig::reactive(
            vec![TriggerKind::NetworkChanged, TriggerKind::InterfaceChanged],
            2,
        );
        assert_eq!(cfg.triggers.len(), 2);
        assert_eq!(cfg.cooldown, Duration::from_secs(2));
    }
}
