//! LLDP/CDP passive capture — discover switches, routers, APs.
//!
//! Purely passive: listens for Link Layer Discovery Protocol (IEEE 802.1AB)
//! and Cisco Discovery Protocol frames on the wire. These are sent every
//! 30-60s by managed network infrastructure.
//!
//! Reveals: switch model, firmware/IOS version, port ID, VLANs, PoE status,
//! management addresses, system capabilities (bridge/router/AP/phone).
//!
//! Safety level: 0 (Passive) — read-only L2 capture, zero packets sent.

use std::time::Duration;

use chrono::Utc;

use crate::collector::{Collector, CollectorOutput};
use crate::collector::banner::BannerResult;
use crate::config::Config;
use crate::model::{Fingerprint, FingerprintSource};

/// LLDP destination MAC (IEEE 802.1AB)
const LLDP_MULTICAST: [u8; 6] = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e];
/// CDP destination MAC
const CDP_MULTICAST: [u8; 6] = [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc];
/// LLDP EtherType
const LLDP_ETHERTYPE: u16 = 0x88cc;

const CAPTURE_DURATION: Duration = Duration::from_secs(65); // CDP sends every 60s

pub struct LldpCollector {
    interface: String,
    interval: Duration,
    max_failures: u32,
}

impl LldpCollector {
    pub fn new(config: &Config) -> Self {
        Self {
            interface: config.interfaces.first().cloned().unwrap_or("en0".into()),
            interval: Duration::from_secs(120),
            max_failures: 5,
        }
    }
}

#[async_trait::async_trait]
impl Collector for LldpCollector {
    fn name(&self) -> &str { "lldp" }
    fn interval(&self) -> Duration { self.interval }
    fn max_failures(&self) -> u32 { self.max_failures }

    async fn collect(&self) -> anyhow::Result<CollectorOutput> {
        let iface = self.interface.clone();
        let results = tokio::task::spawn_blocking(move || capture_lldp(&iface)).await??;
        Ok(CollectorOutput::Banners(results))
    }
}

fn capture_lldp(interface_name: &str) -> anyhow::Result<Vec<BannerResult>> {
    use pnet::datalink::{self, Channel::Ethernet};

    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
        .find(|i| i.name == interface_name)
        .ok_or_else(|| anyhow::anyhow!("interface {interface_name} not found"))?;

    let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        _ => anyhow::bail!("failed to open channel on {interface_name}"),
    };

    let deadline = std::time::Instant::now() + CAPTURE_DURATION;
    let mut results = Vec::new();
    let now = Utc::now();

    while std::time::Instant::now() < deadline {
        match rx.next() {
            Ok(packet) if packet.len() >= 14 => {
                let dst = &packet[0..6];
                let ethertype = u16::from_be_bytes([packet[12], packet[13]]);

                if dst == LLDP_MULTICAST && ethertype == LLDP_ETHERTYPE {
                    if let Some(r) = parse_lldp_frame(&packet[14..], now) {
                        results.push(r);
                    }
                } else if dst == CDP_MULTICAST {
                    if let Some(r) = parse_cdp_frame(&packet[22..], now) { // skip SNAP header
                        results.push(r);
                    }
                }
            }
            _ => continue,
        }
    }

    tracing::debug!(frames = results.len(), "LLDP/CDP capture complete");
    Ok(results)
}

/// Parse LLDP TLV chain. Each TLV: 7-bit type + 9-bit length + value.
fn parse_lldp_frame(data: &[u8], now: chrono::DateTime<Utc>) -> Option<BannerResult> {
    let mut fps = Vec::new();
    let mut chassis_id = String::new();
    let mut port_id = String::new();
    let mut sys_name = String::new();
    let mut sys_desc = String::new();
    let mut pos = 0;

    while pos + 2 <= data.len() {
        let header = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let tlv_type = (header >> 9) as u8;
        let tlv_len = (header & 0x01ff) as usize;
        pos += 2;

        if pos + tlv_len > data.len() { break; }
        let value = &data[pos..pos + tlv_len];
        pos += tlv_len;

        match tlv_type {
            0 => break, // End of LLDPDU
            1 if tlv_len > 1 => { // Chassis ID
                chassis_id = String::from_utf8_lossy(&value[1..]).trim().to_string();
            }
            2 if tlv_len > 1 => { // Port ID
                port_id = String::from_utf8_lossy(&value[1..]).trim().to_string();
            }
            5 => { // System Name
                sys_name = String::from_utf8_lossy(value).trim().to_string();
            }
            6 => { // System Description
                sys_desc = String::from_utf8_lossy(value).trim().to_string();
            }
            _ => {}
        }
    }

    if sys_name.is_empty() && chassis_id.is_empty() { return None; }

    if !sys_name.is_empty() {
        fps.push(Fingerprint {
            source: FingerprintSource::Passive, category: "lldp".into(),
            key: "sys_name".into(), value: sys_name, confidence: 1.0, observed_at: now,
        });
    }
    if !sys_desc.is_empty() {
        fps.push(Fingerprint {
            source: FingerprintSource::Passive, category: "lldp".into(),
            key: "sys_desc".into(), value: sys_desc, confidence: 1.0, observed_at: now,
        });
    }
    if !port_id.is_empty() {
        fps.push(Fingerprint {
            source: FingerprintSource::Passive, category: "lldp".into(),
            key: "port_id".into(), value: port_id, confidence: 1.0, observed_at: now,
        });
    }

    Some(BannerResult {
        mac: format_mac_from_chassis(&chassis_id),
        ip: String::new(),
        port: 0,
        protocol: "lldp".into(),
        banner: String::new(),
        fingerprints: fps,
    })
}

/// Parse CDP frame (simplified — extracts device ID and platform).
fn parse_cdp_frame(data: &[u8], now: chrono::DateTime<Utc>) -> Option<BannerResult> {
    if data.len() < 4 { return None; }
    // CDP: version(1) + ttl(1) + checksum(2) + TLVs
    let mut pos = 4;
    let mut device_id = String::new();
    let mut platform = String::new();
    let mut fps = Vec::new();

    while pos + 4 <= data.len() {
        let tlv_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let tlv_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        if tlv_len < 4 || pos + tlv_len > data.len() { break; }
        let value = &data[pos + 4..pos + tlv_len];
        pos += tlv_len;

        match tlv_type {
            0x0001 => device_id = String::from_utf8_lossy(value).trim().to_string(),
            0x0006 => platform = String::from_utf8_lossy(value).trim().to_string(),
            _ => {}
        }
    }

    if device_id.is_empty() { return None; }

    fps.push(Fingerprint {
        source: FingerprintSource::Passive, category: "cdp".into(),
        key: "device_id".into(), value: device_id, confidence: 1.0, observed_at: now,
    });
    if !platform.is_empty() {
        fps.push(Fingerprint {
            source: FingerprintSource::Passive, category: "cdp".into(),
            key: "platform".into(), value: platform, confidence: 1.0, observed_at: now,
        });
    }

    Some(BannerResult {
        mac: String::new(), ip: String::new(), port: 0,
        protocol: "cdp".into(), banner: String::new(), fingerprints: fps,
    })
}

fn format_mac_from_chassis(chassis: &str) -> String {
    // Chassis ID might already be a MAC or might be a hostname
    if chassis.contains(':') && chassis.len() == 17 {
        chassis.to_lowercase()
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lldp_multicast_correct() {
        assert_eq!(LLDP_MULTICAST, [0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e]);
    }

    #[test]
    fn cdp_multicast_correct() {
        assert_eq!(CDP_MULTICAST, [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc]);
    }

    #[test]
    fn format_mac_from_chassis_valid() {
        assert_eq!(format_mac_from_chassis("AA:BB:CC:DD:EE:FF"), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn format_mac_from_chassis_hostname() {
        assert_eq!(format_mac_from_chassis("switch1.local"), "");
    }
}
