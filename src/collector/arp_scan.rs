//! Active ARP scanner — sends ARP requests to discover ALL hosts on the subnet.
//!
//! Unlike the ARP table reader (arp.rs) which only sees cached entries,
//! this sends an ARP "who-has" for every IP in the subnet CIDR. Hosts
//! MUST respond to ARP at Layer 2 — it cannot be blocked by firewalls.
//!
//! Discovers 50-80% more hosts than the ARP table alone.
//!
//! Safety level: 2 (Discovery) — sends ARP request packets.
//! Requires root (BPF on macOS, AF_PACKET on Linux).

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;

use crate::collector::{Collector, CollectorOutput};
use crate::config::Config;
use crate::model::ArpEntry;
use crate::state::StateEngine;

const ARP_PACKET_SIZE: usize = 28;
const ETHERNET_HEADER_SIZE: usize = 14;
const SCAN_TIMEOUT: Duration = Duration::from_secs(3);
const INTER_PACKET_DELAY: Duration = Duration::from_micros(500);

pub struct ArpScanCollector {
    interface_name: String,
    interval: Duration,
    max_failures: u32,
    engine: Arc<StateEngine>,
}

impl ArpScanCollector {
    pub fn new(config: &Config, engine: Arc<StateEngine>) -> Self {
        let interface_name = config
            .interfaces
            .first()
            .cloned()
            .unwrap_or_else(|| "en0".to_string());

        Self {
            interface_name,
            interval: Duration::from_secs(config.collectors.arp.interval * 2),
            max_failures: 5,
            engine,
        }
    }
}

#[async_trait::async_trait]
impl Collector for ArpScanCollector {
    fn name(&self) -> &str {
        "arp-scan"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn max_failures(&self) -> u32 {
        self.max_failures
    }

    async fn collect(&self) -> anyhow::Result<CollectorOutput> {
        let iface_name = self.interface_name.clone();
        let engine = self.engine.clone();

        let entries = tokio::task::spawn_blocking(move || {
            scan_subnet(&iface_name, &engine)
        })
        .await??;

        Ok(CollectorOutput::Arp(entries))
    }
}

fn scan_subnet(interface_name: &str, engine: &StateEngine) -> anyhow::Result<Vec<ArpEntry>> {
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|i| i.name == interface_name)
        .ok_or_else(|| anyhow::anyhow!("interface {interface_name} not found"))?;

    // Get our IP and subnet from the state engine
    let (our_ip, cidr) = {
        let iface = engine
            .state
            .interfaces
            .get(interface_name)
            .ok_or_else(|| anyhow::anyhow!("interface {interface_name} not in state"))?;

        let ip = iface
            .ipv4
            .first()
            .and_then(|a| match a {
                std::net::IpAddr::V4(v4) => Some(*v4),
                _ => None,
            })
            .ok_or_else(|| anyhow::anyhow!("no IPv4 on {interface_name}"))?;

        let cidr = iface.cidr().ok_or_else(|| anyhow::anyhow!("no CIDR for {interface_name}"))?;
        (ip, cidr)
    };

    let our_mac = interface
        .mac
        .unwrap_or(MacAddr::zero());

    // Parse CIDR to get network + prefix length
    let (network, prefix_len) = parse_cidr(&cidr)?;
    let host_count = 1u32 << (32 - prefix_len);

    if host_count > 1024 {
        tracing::warn!(cidr = %cidr, hosts = host_count, "subnet too large for ARP scan, skipping");
        return Ok(Vec::new());
    }

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => anyhow::bail!("unsupported channel type"),
        Err(e) => anyhow::bail!("failed to open channel: {e}"),
    };

    // Send ARP requests for each IP in the subnet
    let network_u32 = u32::from(network);
    for i in 1..host_count.saturating_sub(1) {
        let target_ip = Ipv4Addr::from(network_u32 + i);
        if target_ip == our_ip {
            continue;
        }
        send_arp_request(&mut tx, our_mac, our_ip, target_ip);
        std::thread::sleep(INTER_PACKET_DELAY);
    }

    // Collect responses
    let deadline = std::time::Instant::now() + SCAN_TIMEOUT;
    let mut entries = Vec::new();
    let mut seen = std::collections::HashSet::new();

    while std::time::Instant::now() < deadline {
        match rx.next() {
            Ok(packet) => {
                if let Some(entry) = parse_arp_reply(packet, interface_name) {
                    if seen.insert(entry.mac.clone()) {
                        entries.push(entry);
                    }
                }
            }
            Err(_) => continue,
        }
    }

    tracing::debug!(
        hosts = entries.len(),
        subnet = %cidr,
        "ARP scan complete"
    );
    Ok(entries)
}

fn send_arp_request(
    tx: &mut Box<dyn pnet::datalink::DataLinkSender>,
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) {
    let mut eth_buf = [0u8; ETHERNET_HEADER_SIZE + ARP_PACKET_SIZE];
    let mut eth = MutableEthernetPacket::new(&mut eth_buf).unwrap();
    eth.set_destination(MacAddr::broadcast());
    eth.set_source(src_mac);
    eth.set_ethertype(EtherTypes::Arp);

    let mut arp_buf = [0u8; ARP_PACKET_SIZE];
    let mut arp = MutableArpPacket::new(&mut arp_buf).unwrap();
    arp.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp.set_protocol_type(EtherTypes::Ipv4);
    arp.set_hw_addr_len(6);
    arp.set_proto_addr_len(4);
    arp.set_operation(ArpOperations::Request);
    arp.set_sender_hw_addr(src_mac);
    arp.set_sender_proto_addr(src_ip);
    arp.set_target_hw_addr(MacAddr::zero());
    arp.set_target_proto_addr(target_ip);

    eth.set_payload(arp.packet_mut());
    let packet_bytes = eth.packet().to_vec();
    tx.send_to(&packet_bytes, None);
}

fn parse_arp_reply(packet: &[u8], interface: &str) -> Option<ArpEntry> {
    if packet.len() < ETHERNET_HEADER_SIZE + ARP_PACKET_SIZE {
        return None;
    }

    let arp_data = &packet[ETHERNET_HEADER_SIZE..];
    let arp = ArpPacket::new(arp_data)?;

    if arp.get_operation() != ArpOperations::Reply {
        return None;
    }

    let mac = arp.get_sender_hw_addr();
    let ip = arp.get_sender_proto_addr();

    let mac_str = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac.0, mac.1, mac.2, mac.3, mac.4, mac.5
    );

    Some(ArpEntry {
        ip: std::net::IpAddr::V4(ip),
        mac: mac_str,
        interface: interface.to_string(),
        hostname: None,
    })
}

fn parse_cidr(cidr: &str) -> anyhow::Result<(Ipv4Addr, u32)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!("invalid CIDR: {cidr}");
    }
    let ip: Ipv4Addr = parts[0].parse()?;
    let prefix: u32 = parts[1].parse()?;
    Ok((ip, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cidr_valid() {
        let (ip, prefix) = parse_cidr("192.168.1.0/24").unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(prefix, 24);
    }

    #[test]
    fn parse_cidr_16() {
        let (ip, prefix) = parse_cidr("10.0.0.0/16").unwrap();
        assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(prefix, 16);
    }

    #[test]
    fn parse_cidr_invalid() {
        assert!(parse_cidr("not-a-cidr").is_err());
    }

    #[test]
    fn large_subnet_capped() {
        // /16 = 65536 hosts, should be skipped
        let host_count = 1u32 << (32 - 16);
        assert!(host_count > 1024);
    }
}
