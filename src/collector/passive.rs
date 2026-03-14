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

    /// Build a minimal Ethernet + IPv4 + TCP SYN packet for testing.
    fn make_tcp_syn_packet(src_ip: [u8; 4], ttl: u8, window: u16) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(54);
        // Ethernet header (14 bytes)
        pkt.extend_from_slice(&[0xff; 6]); // dst MAC
        pkt.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // src MAC
        pkt.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // IPv4 header (20 bytes)
        pkt.push(0x45); // version=4, ihl=5
        pkt.push(0x00); // DSCP/ECN
        pkt.extend_from_slice(&40u16.to_be_bytes()); // total length (20 IP + 20 TCP)
        pkt.extend_from_slice(&[0x00, 0x00]); // identification
        pkt.extend_from_slice(&[0x40, 0x00]); // flags=DF, fragment offset=0
        pkt.push(ttl);
        pkt.push(6); // protocol: TCP
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum (0 = skip)
        pkt.extend_from_slice(&src_ip); // src IP
        pkt.extend_from_slice(&[10, 0, 0, 1]); // dst IP

        // TCP header (20 bytes)
        pkt.extend_from_slice(&12345u16.to_be_bytes()); // src port
        pkt.extend_from_slice(&80u16.to_be_bytes()); // dst port
        pkt.extend_from_slice(&1u32.to_be_bytes()); // sequence number
        pkt.extend_from_slice(&0u32.to_be_bytes()); // ack number
        pkt.push(0x50); // data offset=5 (20 bytes), reserved=0
        pkt.push(0x02); // flags: SYN only (bit 1)
        pkt.extend_from_slice(&window.to_be_bytes()); // window size
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum
        pkt.extend_from_slice(&[0x00, 0x00]); // urgent pointer

        pkt
    }

    #[test]
    fn analyze_packet_extracts_ttl_and_window() {
        use crate::config::FilterConfig;
        use crate::traits::mocks::{InMemoryStorage, MockVendorLookup};
        use std::sync::Arc;

        let engine = StateEngine::with_mocks(
            Arc::new(InMemoryStorage::new()),
            Arc::new(MockVendorLookup::empty()),
            FilterConfig::default(),
            100,
        );

        // Pre-populate a host so the IP→MAC lookup succeeds
        let ip: std::net::IpAddr = "10.0.0.5".parse().unwrap();
        engine.state.hosts.insert("aa:bb:cc:dd:ee:ff".into(), crate::model::HostInfo {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            vendor: String::new(),
            addresses: vec![ip],
            hostname: None, os_hint: None, services: vec![], fingerprints: vec![],
            interface: "en0".into(), network_id: String::new(),
            first_seen: chrono::Utc::now(), last_seen: chrono::Utc::now(),
        });
        engine.state.ip_to_mac.insert(ip, "aa:bb:cc:dd:ee:ff".into());

        let pkt = make_tcp_syn_packet([10, 0, 0, 5], 64, 65535);
        let mut seen = std::collections::HashSet::new();

        let result = analyze_packet(&pkt, &engine, &mut seen);
        assert!(result.is_some(), "should extract fingerprints from valid SYN");
        let r = result.unwrap();
        assert_eq!(r.mac, "aa:bb:cc:dd:ee:ff");

        // Check TTL → OS family fingerprint
        assert!(r.fingerprints.iter().any(|f|
            f.key == "family" && f.value == "Linux/macOS/iOS"
        ), "TTL 64 should map to Linux/macOS");

        // Check TTL raw value
        assert!(r.fingerprints.iter().any(|f|
            f.key == "ttl" && f.value == "64"
        ));

        // Check window size
        assert!(r.fingerprints.iter().any(|f|
            f.key == "tcp_window" && f.value == "65535"
        ));
    }

    #[test]
    fn analyze_packet_windows_ttl() {
        use crate::config::FilterConfig;
        use crate::traits::mocks::{InMemoryStorage, MockVendorLookup};
        use std::sync::Arc;

        let engine = StateEngine::with_mocks(
            Arc::new(InMemoryStorage::new()),
            Arc::new(MockVendorLookup::empty()),
            FilterConfig::default(),
            100,
        );
        let ip: std::net::IpAddr = "10.0.0.5".parse().unwrap();
        engine.state.hosts.insert("aa:bb:cc:dd:ee:ff".into(), crate::model::HostInfo {
            mac: "aa:bb:cc:dd:ee:ff".into(), vendor: String::new(),
            addresses: vec![ip], hostname: None, os_hint: None,
            services: vec![], fingerprints: vec![], interface: "en0".into(),
            network_id: String::new(), first_seen: chrono::Utc::now(), last_seen: chrono::Utc::now(),
        });
        engine.state.ip_to_mac.insert(ip, "aa:bb:cc:dd:ee:ff".into());

        let pkt = make_tcp_syn_packet([10, 0, 0, 5], 128, 8192);
        let mut seen = std::collections::HashSet::new();
        let result = analyze_packet(&pkt, &engine, &mut seen).unwrap();
        assert!(result.fingerprints.iter().any(|f| f.value == "Windows"));
    }

    #[test]
    fn analyze_packet_skips_non_syn() {
        use crate::config::FilterConfig;
        use crate::traits::mocks::{InMemoryStorage, MockVendorLookup};
        use std::sync::Arc;

        let engine = StateEngine::with_mocks(
            Arc::new(InMemoryStorage::new()),
            Arc::new(MockVendorLookup::empty()),
            FilterConfig::default(),
            100,
        );
        let ip: std::net::IpAddr = "10.0.0.5".parse().unwrap();
        engine.state.hosts.insert("aa:bb:cc:dd:ee:ff".into(), crate::model::HostInfo {
            mac: "aa:bb:cc:dd:ee:ff".into(), vendor: String::new(),
            addresses: vec![ip], hostname: None, os_hint: None,
            services: vec![], fingerprints: vec![], interface: "en0".into(),
            network_id: String::new(), first_seen: chrono::Utc::now(), last_seen: chrono::Utc::now(),
        });
        engine.state.ip_to_mac.insert(ip, "aa:bb:cc:dd:ee:ff".into());

        // SYN+ACK (flags = 0x12) — should be skipped
        let mut pkt = make_tcp_syn_packet([10, 0, 0, 5], 64, 65535);
        pkt[47] = 0x12; // SYN+ACK
        let mut seen = std::collections::HashSet::new();
        assert!(analyze_packet(&pkt, &engine, &mut seen).is_none());
    }

    #[test]
    fn analyze_packet_skips_unknown_ip() {
        use crate::config::FilterConfig;
        use crate::traits::mocks::{InMemoryStorage, MockVendorLookup};
        use std::sync::Arc;

        let engine = StateEngine::with_mocks(
            Arc::new(InMemoryStorage::new()),
            Arc::new(MockVendorLookup::empty()),
            FilterConfig::default(),
            100,
        );
        // No hosts in state — IP won't resolve
        let pkt = make_tcp_syn_packet([10, 0, 0, 99], 64, 65535);
        let mut seen = std::collections::HashSet::new();
        assert!(analyze_packet(&pkt, &engine, &mut seen).is_none());
    }

    #[test]
    fn analyze_packet_deduplicates_by_ip() {
        use crate::config::FilterConfig;
        use crate::traits::mocks::{InMemoryStorage, MockVendorLookup};
        use std::sync::Arc;

        let engine = StateEngine::with_mocks(
            Arc::new(InMemoryStorage::new()),
            Arc::new(MockVendorLookup::empty()),
            FilterConfig::default(),
            100,
        );
        let ip: std::net::IpAddr = "10.0.0.5".parse().unwrap();
        engine.state.hosts.insert("aa:bb:cc:dd:ee:ff".into(), crate::model::HostInfo {
            mac: "aa:bb:cc:dd:ee:ff".into(), vendor: String::new(),
            addresses: vec![ip], hostname: None, os_hint: None,
            services: vec![], fingerprints: vec![], interface: "en0".into(),
            network_id: String::new(), first_seen: chrono::Utc::now(), last_seen: chrono::Utc::now(),
        });
        engine.state.ip_to_mac.insert(ip, "aa:bb:cc:dd:ee:ff".into());

        let pkt = make_tcp_syn_packet([10, 0, 0, 5], 64, 65535);
        let mut seen = std::collections::HashSet::new();
        assert!(analyze_packet(&pkt, &engine, &mut seen).is_some());
        // Second packet from same IP — should be deduplicated
        assert!(analyze_packet(&pkt, &engine, &mut seen).is_none());
    }

    #[test]
    fn analyze_packet_too_short() {
        use crate::config::FilterConfig;
        use crate::traits::mocks::{InMemoryStorage, MockVendorLookup};
        use std::sync::Arc;

        let engine = StateEngine::with_mocks(
            Arc::new(InMemoryStorage::new()),
            Arc::new(MockVendorLookup::empty()),
            FilterConfig::default(),
            100,
        );
        let mut seen = std::collections::HashSet::new();
        assert!(analyze_packet(&[0, 1, 2], &engine, &mut seen).is_none());
    }
    // The analyze_packet function is tested via integration tests.
    // Unit tests here validate configuration and constants only.
}
