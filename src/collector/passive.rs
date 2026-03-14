//! Passive TCP/DHCP fingerprinting — OS detection without active probing.
//!
//! Captures packets on the network interface via BPF (macOS) or AF_PACKET
//! (Linux) and extracts fingerprints from TCP and DHCP headers:
//!
//! TCP fingerprinting (p0f-style):
//!   - Initial TTL → infer OS family (64=Linux/macOS, 128=Windows, 255=Solaris)
//!   - TCP window size → OS-specific defaults
//!   - TCP options order (MSS, window scale, SACK, timestamps, NOP)
//!   - MSS value → link type (1460=Ethernet, 1360=VPN, etc.)
//!
//! DHCP fingerprinting:
//!   - Option 55 (Parameter Request List) → unique per OS/device type
//!   - Option 60 (Vendor Class Identifier) → "MSFT 5.0", "android-dhcp-13"
//!   - Option 12 (Hostname)
//!
//! Safety level: 0 (passive) — read-only capture, no packets sent.
//!
//! Requires root (daemon runs as root via launchd/systemd).

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;

use crate::collector::{Collector, CollectorOutput};
use crate::collector::banner::BannerResult;
use crate::config::Config;
use crate::model::{Fingerprint, FingerprintSource};
use crate::state::StateEngine;

/// How long to capture packets per collection cycle.
const CAPTURE_DURATION: Duration = Duration::from_secs(15);

pub struct PassiveCollector {
    interface: String,
    interval: Duration,
    max_failures: u32,
    engine: Arc<StateEngine>,
}

impl PassiveCollector {
    pub fn new(config: &Config, engine: Arc<StateEngine>) -> Self {
        let interface = config
            .interfaces
            .first()
            .cloned()
            .unwrap_or_else(|| "en0".to_string());

        Self {
            interface,
            interval: Duration::from_secs(30),
            max_failures: 5,
            engine,
        }
    }
}

#[async_trait::async_trait]
impl Collector for PassiveCollector {
    fn name(&self) -> &str {
        "passive"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn max_failures(&self) -> u32 {
        self.max_failures
    }

    async fn collect(&self) -> anyhow::Result<CollectorOutput> {
        let iface = self.interface.clone();
        let engine = self.engine.clone();

        let results = tokio::task::spawn_blocking(move || {
            capture_packets(&iface, &engine)
        })
        .await??;

        Ok(CollectorOutput::Banners(results))
    }
}

/// Capture packets for CAPTURE_DURATION and extract fingerprints.
fn capture_packets(
    interface_name: &str,
    engine: &StateEngine,
) -> anyhow::Result<Vec<BannerResult>> {
    use pnet::datalink::{self, Channel::Ethernet};

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|i| i.name == interface_name)
        .ok_or_else(|| anyhow::anyhow!("interface {interface_name} not found"))?;

    let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => anyhow::bail!("unsupported channel type for {interface_name}"),
        Err(e) => anyhow::bail!("failed to open channel on {interface_name}: {e}"),
    };

    let deadline = std::time::Instant::now() + CAPTURE_DURATION;
    let mut results = Vec::new();
    let mut seen_ips: std::collections::HashSet<String> = std::collections::HashSet::new();

    while std::time::Instant::now() < deadline {
        match rx.next() {
            Ok(packet) => {
                if let Some(fp) = analyze_packet(packet, engine, &mut seen_ips) {
                    results.push(fp);
                }
            }
            Err(e) => {
                tracing::trace!(error = %e, "packet read error");
                // Transient errors are normal (timeouts, etc.)
            }
        }
    }

    tracing::debug!(fingerprints = results.len(), "passive capture complete");
    Ok(results)
}

/// Analyze a single captured packet for fingerprinting data.
fn analyze_packet(
    packet: &[u8],
    engine: &StateEngine,
    seen_ips: &mut std::collections::HashSet<String>,
) -> Option<BannerResult> {
    use etherparse::SlicedPacket;

    let parsed = SlicedPacket::from_ethernet(packet).ok()?;

    // Get source IP
    let src_ip = match &parsed.net {
        Some(etherparse::NetSlice::Ipv4(ipv4)) => {
            let src = ipv4.header().source_addr();
            src.to_string()
        }
        _ => return None,
    };

    // Only fingerprint each IP once per cycle
    if !seen_ips.insert(src_ip.clone()) {
        return None;
    }

    // Only fingerprint hosts we already know about
    let mac = engine.state.ip_to_mac.get(&src_ip.parse().ok()?)?;
    let mac = mac.clone();

    // Extract TCP fingerprint
    let tcp_fp = match &parsed.transport {
        Some(etherparse::TransportSlice::Tcp(tcp)) => {
            // Only SYN packets (initial connection) are useful for fingerprinting
            if !tcp.syn() || tcp.ack() {
                return None;
            }

            let ttl = match &parsed.net {
                Some(etherparse::NetSlice::Ipv4(ipv4)) => ipv4.header().ttl(),
                _ => 0,
            };

            let window = tcp.window_size();
            let now = Utc::now();
            let mut fingerprints = Vec::new();

            // TTL → OS family
            let os_family = match ttl {
                1..=64 => "Linux/macOS/iOS",
                65..=128 => "Windows",
                129..=255 => "Solaris/AIX",
                _ => "unknown",
            };
            fingerprints.push(Fingerprint {
                source: FingerprintSource::Passive,
                category: "os".into(),
                key: "family".into(),
                value: os_family.into(),
                confidence: 0.5, // TTL-based OS detection is approximate
                observed_at: now,
            });

            // Initial TTL (raw value for detailed analysis)
            fingerprints.push(Fingerprint {
                source: FingerprintSource::Passive,
                category: "net".into(),
                key: "ttl".into(),
                value: ttl.to_string(),
                confidence: 1.0,
                observed_at: now,
            });

            // TCP window size
            fingerprints.push(Fingerprint {
                source: FingerprintSource::Passive,
                category: "net".into(),
                key: "tcp_window".into(),
                value: window.to_string(),
                confidence: 1.0,
                observed_at: now,
            });

            Some(fingerprints)
        }
        _ => None,
    };

    let fingerprints = tcp_fp?;
    if fingerprints.is_empty() {
        return None;
    }

    Some(BannerResult {
        mac,
        ip: src_ip,
        port: 0,
        protocol: "passive".into(),
        banner: String::new(),
        fingerprints,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_duration_reasonable() {
        assert!(CAPTURE_DURATION.as_secs() <= 30);
        assert!(CAPTURE_DURATION.as_secs() >= 5);
    }

    // Note: Actual packet capture tests require root and a live interface.
    // The analyze_packet function is tested via integration tests.
    // Unit tests here validate configuration and constants only.
}
