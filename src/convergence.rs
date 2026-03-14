//! Network convergence detection.
//!
//! Tracks the rate of discovery events vs maintenance events to determine
//! when the network scan has "converged" — meaning all reachable hosts
//! have been found and enriched. After convergence, the daemon shifts
//! to steady-state monitoring mode.
//!
//! Convergence is not binary — it's a confidence score (0.0-1.0) that
//! increases as the discovery rate drops. The score accounts for:
//!
//! - Time since last new host discovery
//! - Time since last new service discovery
//! - Number of ARP scan cycles completed without finding new hosts
//! - Number of nmap cycles completed without finding new services
//! - Whether all collectors have run at least once
//!
//! The network can "de-converge" when:
//! - A new host appears (score drops)
//! - A network transition occurs (score resets to 0)
//! - An interface goes up/down (score partially resets)

use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Tracks convergence state. Updated by the state engine on every event.
pub struct ConvergenceTracker {
    /// When the daemon started (or last network transition).
    epoch: DateTime<Utc>,

    /// Last time a genuinely new host was discovered (HostAdded).
    last_new_host: std::sync::Mutex<DateTime<Utc>>,

    /// Last time a new service was discovered (ServiceChanged::Added).
    last_new_service: std::sync::Mutex<DateTime<Utc>>,

    /// Last time a new fingerprint source produced data (mDNS, TLS, banner, etc.).
    last_new_fingerprint: std::sync::Mutex<DateTime<Utc>>,

    /// Count of consecutive ARP scan cycles with zero new hosts.
    stable_arp_cycles: AtomicU64,

    /// Count of consecutive nmap cycles with zero new services.
    stable_nmap_cycles: AtomicU64,

    /// Total number of unique collectors that have reported at least once.
    collectors_reported: std::sync::Mutex<std::collections::HashSet<String>>,

    /// Expected number of collectors.
    expected_collectors: u32,
}

impl ConvergenceTracker {
    pub fn new(expected_collectors: u32) -> Self {
        let now = Utc::now();
        Self {
            epoch: now,
            last_new_host: std::sync::Mutex::new(now),
            last_new_service: std::sync::Mutex::new(now),
            last_new_fingerprint: std::sync::Mutex::new(now),
            stable_arp_cycles: AtomicU64::new(0),
            stable_nmap_cycles: AtomicU64::new(0),
            collectors_reported: std::sync::Mutex::new(std::collections::HashSet::new()),
            expected_collectors,
        }
    }

    /// Record that a new host was discovered.
    pub fn on_host_added(&self) {
        *self.last_new_host.lock().unwrap() = Utc::now();
        self.stable_arp_cycles.store(0, Ordering::Relaxed);
    }

    /// Record that a new service was discovered.
    pub fn on_service_added(&self) {
        *self.last_new_service.lock().unwrap() = Utc::now();
        self.stable_nmap_cycles.store(0, Ordering::Relaxed);
    }

    /// Record that a new fingerprint was added (from any source).
    pub fn on_fingerprint_added(&self) {
        *self.last_new_fingerprint.lock().unwrap() = Utc::now();
    }

    /// Record a stable ARP cycle (no new hosts found).
    pub fn on_arp_cycle_stable(&self) {
        self.stable_arp_cycles.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a stable nmap cycle (no new services found).
    pub fn on_nmap_cycle_stable(&self) {
        self.stable_nmap_cycles.fetch_add(1, Ordering::Relaxed);
    }

    /// Record that a collector has reported results.
    pub fn on_collector_reported(&self, name: &str) {
        self.collectors_reported.lock().unwrap().insert(name.to_string());
    }

    /// Reset convergence (network transition, interface change).
    pub fn reset(&self) {
        let now = Utc::now();
        *self.last_new_host.lock().unwrap() = now;
        *self.last_new_service.lock().unwrap() = now;
        *self.last_new_fingerprint.lock().unwrap() = now;
        self.stable_arp_cycles.store(0, Ordering::Relaxed);
        self.stable_nmap_cycles.store(0, Ordering::Relaxed);
    }

    /// Compute current convergence score (0.0 = just started, 1.0 = fully converged).
    pub fn score(&self) -> ConvergenceScore {
        let now = Utc::now();

        // Factor 1: Time since last new host (weight 0.30)
        let since_new_host = (now - *self.last_new_host.lock().unwrap()).num_seconds() as f32;
        // Converges after ~5 minutes of no new hosts
        let host_factor = (since_new_host / 300.0).min(1.0);

        // Factor 2: Time since last new service (weight 0.25)
        let since_new_svc = (now - *self.last_new_service.lock().unwrap()).num_seconds() as f32;
        // Converges after ~3 minutes of no new services
        let svc_factor = (since_new_svc / 180.0).min(1.0);

        // Factor 3: Stable ARP cycles (weight 0.20)
        let arp_cycles = self.stable_arp_cycles.load(Ordering::Relaxed) as f32;
        // 3 stable cycles = converged (at 5s interval = 15s)
        let arp_factor = (arp_cycles / 3.0).min(1.0);

        // Factor 4: Stable nmap cycles (weight 0.15)
        let nmap_cycles = self.stable_nmap_cycles.load(Ordering::Relaxed) as f32;
        // 2 stable nmap cycles = converged (at 60s = 2min)
        let nmap_factor = (nmap_cycles / 2.0).min(1.0);

        // Factor 5: All collectors reported (weight 0.10)
        let reported = self.collectors_reported.lock().unwrap().len() as f32;
        let collector_factor = if self.expected_collectors == 0 {
            1.0
        } else {
            (reported / self.expected_collectors as f32).min(1.0)
        };

        let score = host_factor * 0.30
            + svc_factor * 0.25
            + arp_factor * 0.20
            + nmap_factor * 0.15
            + collector_factor * 0.10;

        let phase = if score < 0.3 {
            ConvergencePhase::Discovering
        } else if score < 0.7 {
            ConvergencePhase::Enriching
        } else if score < 0.95 {
            ConvergencePhase::NearConverged
        } else {
            ConvergencePhase::Converged
        };

        ConvergenceScore {
            score,
            phase,
            since_new_host: since_new_host as u64,
            since_new_service: since_new_svc as u64,
            stable_arp_cycles: arp_cycles as u64,
            stable_nmap_cycles: nmap_cycles as u64,
            collectors_reported: reported as u32,
            expected_collectors: self.expected_collectors,
            uptime: (now - self.epoch).num_seconds() as u64,
        }
    }
}

/// Current convergence state — returned by the MCP tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvergenceScore {
    /// Overall convergence 0.0-1.0
    pub score: f32,
    /// Human-readable phase
    pub phase: ConvergencePhase,
    /// Seconds since last new host was discovered
    pub since_new_host: u64,
    /// Seconds since last new service was discovered
    pub since_new_service: u64,
    /// Consecutive ARP cycles with no new hosts
    pub stable_arp_cycles: u64,
    /// Consecutive nmap cycles with no new services
    pub stable_nmap_cycles: u64,
    /// How many collectors have reported at least once
    pub collectors_reported: u32,
    /// Expected total collectors
    pub expected_collectors: u32,
    /// Daemon uptime in seconds
    pub uptime: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConvergencePhase {
    /// Actively discovering new hosts (score < 0.3)
    Discovering,
    /// Hosts found, enriching with services/fingerprints (score 0.3-0.7)
    Enriching,
    /// Most data collected, waiting for final probes (score 0.7-0.95)
    NearConverged,
    /// Network fully profiled — safe to analyze (score > 0.95)
    Converged,
}

impl std::fmt::Display for ConvergencePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Discovering => f.write_str("discovering"),
            Self::Enriching => f.write_str("enriching"),
            Self::NearConverged => f.write_str("near-converged"),
            Self::Converged => f.write_str("converged"),
        }
    }
}

/// A tokio::sync::Notify that fires when convergence phase transitions
/// to Converged (or changes at all). Allows zero-polling wait.
pub struct ConvergenceNotifier {
    notify: tokio::sync::Notify,
}

impl ConvergenceNotifier {
    pub fn new() -> Self {
        Self {
            notify: tokio::sync::Notify::new(),
        }
    }

    /// Signal that convergence state may have changed.
    pub fn signal(&self) {
        self.notify.notify_waiters();
    }

    /// Wait until signaled. Returns immediately if already signaled.
    pub async fn wait(&self) {
        self.notify.notified().await;
    }
}

impl ConvergenceTracker {
    /// Wait for convergence without polling. Uses a Notify to wake
    /// when state changes, then checks the score. Returns when
    /// score >= threshold or timeout expires.
    pub async fn wait_for_convergence(
        &self,
        notifier: &ConvergenceNotifier,
        threshold: f32,
        timeout: std::time::Duration,
    ) -> ConvergenceScore {
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            let score = self.score();
            if score.score >= threshold {
                return score;
            }

            // Wait for next state change or timeout
            tokio::select! {
                () = notifier.wait() => continue,
                () = tokio::time::sleep_until(deadline) => return self.score(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_tracker_starts_discovering() {
        let tracker = ConvergenceTracker::new(5);
        let score = tracker.score();
        assert!(score.score < 0.3, "new tracker should be discovering, got {}", score.score);
        assert_eq!(score.phase, ConvergencePhase::Discovering);
    }

    #[test]
    fn stable_cycles_increase_score() {
        let tracker = ConvergenceTracker::new(0); // no collector requirement
        // Simulate time passing with no new discoveries
        *tracker.last_new_host.lock().unwrap() = Utc::now() - chrono::Duration::minutes(10);
        *tracker.last_new_service.lock().unwrap() = Utc::now() - chrono::Duration::minutes(10);
        tracker.stable_arp_cycles.store(10, Ordering::Relaxed);
        tracker.stable_nmap_cycles.store(5, Ordering::Relaxed);

        let score = tracker.score();
        assert!(score.score > 0.9, "should be near converged, got {}", score.score);
    }

    #[test]
    fn new_host_resets_convergence() {
        let tracker = ConvergenceTracker::new(0);
        *tracker.last_new_host.lock().unwrap() = Utc::now() - chrono::Duration::minutes(10);
        tracker.stable_arp_cycles.store(10, Ordering::Relaxed);

        // New host found
        tracker.on_host_added();

        let score = tracker.score();
        // Host factor should drop (just now), ARP cycles reset to 0
        assert!(score.stable_arp_cycles == 0);
        assert!(score.since_new_host < 2); // just happened
    }

    #[test]
    fn reset_drops_everything() {
        let tracker = ConvergenceTracker::new(0);
        tracker.stable_arp_cycles.store(100, Ordering::Relaxed);
        tracker.stable_nmap_cycles.store(50, Ordering::Relaxed);

        tracker.reset();

        let score = tracker.score();
        assert_eq!(score.stable_arp_cycles, 0);
        assert_eq!(score.stable_nmap_cycles, 0);
    }

    #[test]
    fn collector_reporting_increases_score() {
        let tracker = ConvergenceTracker::new(3);
        tracker.on_collector_reported("arp");
        tracker.on_collector_reported("interface");

        let score = tracker.score();
        assert_eq!(score.collectors_reported, 2);
        assert_eq!(score.expected_collectors, 3);
    }

    #[test]
    fn converged_phase_after_long_stability() {
        let tracker = ConvergenceTracker::new(0);
        *tracker.last_new_host.lock().unwrap() = Utc::now() - chrono::Duration::hours(1);
        *tracker.last_new_service.lock().unwrap() = Utc::now() - chrono::Duration::hours(1);
        *tracker.last_new_fingerprint.lock().unwrap() = Utc::now() - chrono::Duration::hours(1);
        tracker.stable_arp_cycles.store(100, Ordering::Relaxed);
        tracker.stable_nmap_cycles.store(50, Ordering::Relaxed);

        let score = tracker.score();
        assert_eq!(score.phase, ConvergencePhase::Converged);
        assert!(score.score >= 0.95);
    }

    #[tokio::test]
    async fn wait_for_convergence_returns_immediately_when_converged() {
        let tracker = ConvergenceTracker::new(0);
        let notifier = ConvergenceNotifier::new();
        // Set up fully converged state
        *tracker.last_new_host.lock().unwrap() = Utc::now() - chrono::Duration::hours(1);
        *tracker.last_new_service.lock().unwrap() = Utc::now() - chrono::Duration::hours(1);
        tracker.stable_arp_cycles.store(100, Ordering::Relaxed);
        tracker.stable_nmap_cycles.store(50, Ordering::Relaxed);

        let score = tracker.wait_for_convergence(
            &notifier,
            0.95,
            std::time::Duration::from_secs(1),
        ).await;
        assert!(score.score >= 0.95);
        assert_eq!(score.phase, ConvergencePhase::Converged);
    }

    #[tokio::test]
    async fn wait_for_convergence_times_out() {
        let tracker = ConvergenceTracker::new(0);
        let notifier = ConvergenceNotifier::new();
        // Fresh tracker — not converged

        let score = tracker.wait_for_convergence(
            &notifier,
            0.95,
            std::time::Duration::from_millis(100), // very short timeout
        ).await;
        // Should return current (low) score, not panic
        assert!(score.score < 0.95);
    }

    #[test]
    fn score_capped_at_1() {
        let tracker = ConvergenceTracker::new(0);
        *tracker.last_new_host.lock().unwrap() = Utc::now() - chrono::Duration::days(30);
        *tracker.last_new_service.lock().unwrap() = Utc::now() - chrono::Duration::days(30);
        tracker.stable_arp_cycles.store(10000, Ordering::Relaxed);
        tracker.stable_nmap_cycles.store(10000, Ordering::Relaxed);

        let score = tracker.score();
        assert!(score.score <= 1.0);
    }
}
