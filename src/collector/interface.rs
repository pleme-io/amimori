use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};

use crate::collector::{Collector, CollectorOutput};
use crate::config::Config;
use crate::model::{InterfaceInfo, InterfaceKind};

/// Collects network interface state. Augments with gateway and DNS info.
pub struct InterfaceCollector {
    monitored: Vec<String>,
    interval: Duration,
    max_failures: u32,
}

impl InterfaceCollector {
    pub fn new(config: &Config) -> Self {
        Self {
            monitored: config.interfaces.clone(),
            interval: Duration::from_secs(config.collectors.interface.interval),
            max_failures: config.collectors.interface.max_failures,
        }
    }
}

#[async_trait::async_trait]
impl Collector for InterfaceCollector {
    fn name(&self) -> &str {
        "interface"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn max_failures(&self) -> u32 {
        self.max_failures
    }

    async fn collect(&self) -> anyhow::Result<CollectorOutput> {
        let net_interfaces = NetworkInterface::show()?;
        let gateways = parse_gateways().await;
        let dns_servers = parse_dns_servers().await;

        let interfaces: Vec<InterfaceInfo> = net_interfaces
            .iter()
            .filter(|ni| {
                if !self.monitored.is_empty() {
                    self.monitored.iter().any(|m| m == &ni.name)
                } else {
                    // Auto-detect: skip loopback
                    ni.name != "lo0" && ni.name != "lo"
                }
            })
            .map(|ni| build_interface_info(ni, &gateways, &dns_servers))
            .collect();

        tracing::debug!(count = interfaces.len(), "interface scan complete");
        Ok(CollectorOutput::Interfaces(interfaces))
    }
}

fn build_interface_info(
    ni: &NetworkInterface,
    gateways: &HashMap<String, String>,
    dns_servers: &HashMap<String, Vec<String>>,
) -> InterfaceInfo {
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    let mut subnet = String::new();

    for addr in &ni.addr {
        match addr {
            Addr::V4(v4) => {
                ipv4.push(IpAddr::V4(v4.ip));
                if let Some(mask) = v4.netmask {
                    if subnet.is_empty() {
                        subnet = mask.to_string();
                    }
                }
            }
            Addr::V6(v6) => {
                ipv6.push(IpAddr::V6(v6.ip));
            }
        }
    }

    let mac = ni.mac_addr.as_deref().unwrap_or("").to_lowercase();
    let kind = InterfaceKind::from_name(&ni.name);
    let gateway = gateways.get(&ni.name).cloned().unwrap_or_default();
    let dns = dns_servers.get(&ni.name).cloned().unwrap_or_default();
    let is_up = !ipv4.is_empty() || !ipv6.is_empty();

    InterfaceInfo {
        name: ni.name.clone(),
        mac,
        ipv4,
        ipv6,
        gateway,
        subnet,
        is_up,
        kind,
        dns,
    }
}

/// Run `netstat -rn` and parse gateways.
async fn parse_gateways() -> HashMap<String, String> {
    let Ok(output) = tokio::process::Command::new("netstat")
        .args(["-rn"])
        .output()
        .await
    else {
        tracing::debug!("netstat -rn failed, gateway detection unavailable");
        return HashMap::new();
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_netstat_gateways(&stdout)
}

/// Run `scutil --dns` and parse DNS servers.
async fn parse_dns_servers() -> HashMap<String, Vec<String>> {
    let Ok(output) = tokio::process::Command::new("scutil")
        .args(["--dns"])
        .output()
        .await
    else {
        tracing::debug!("scutil --dns failed, DNS detection unavailable");
        return HashMap::new();
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_scutil_dns(&stdout)
}

// ── Pure parsing functions (testable) ──────────────────────────────────────

/// Parse `netstat -rn` output to extract default gateways per interface. Pure function.
pub fn parse_netstat_gateways(output: &str) -> HashMap<String, String> {
    let mut gateways = HashMap::new();

    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 && (parts[0] == "default" || parts[0] == "0.0.0.0") {
            let gateway = parts[1];
            if let Some(iface) = parts.last() {
                if iface.starts_with("en") || iface.starts_with("utun") {
                    gateways
                        .entry((*iface).to_string())
                        .or_insert_with(|| gateway.to_string());
                }
            }
        }
    }

    gateways
}

/// Parse `scutil --dns` output to extract DNS servers per interface. Pure function.
pub fn parse_scutil_dns(output: &str) -> HashMap<String, Vec<String>> {
    let mut dns_map: HashMap<String, Vec<String>> = HashMap::new();
    let mut current_iface = String::new();
    let mut current_servers = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("resolver") {
            if !current_iface.is_empty() && !current_servers.is_empty() {
                dns_map
                    .entry(std::mem::take(&mut current_iface))
                    .or_default()
                    .extend(current_servers.drain(..));
            }
            current_iface.clear();
        } else if let Some(iface) = trimmed.strip_prefix("if_index : ") {
            if let (Some(start), Some(end)) = (iface.find('('), iface.find(')')) {
                current_iface = iface[start + 1..end].to_string();
            }
        } else if let Some(ns) = trimmed.strip_prefix("nameserver[") {
            if let Some(addr) = ns.split(" : ").nth(1) {
                current_servers.push(addr.trim().to_string());
            }
        }
    }

    if !current_iface.is_empty() && !current_servers.is_empty() {
        dns_map
            .entry(current_iface)
            .or_default()
            .extend(current_servers);
    }

    dns_map
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Gateway parsing tests ──────────────────────────────────────────

    #[test]
    fn parse_gateways_standard_macos() {
        let output = "\
Routing tables

Internet:
Destination        Gateway            Flags           Netif Expire
default            10.0.0.1           UGScg             en0
10.0.0/24          link#6             UCS               en0
10.0.0.1           aa:bb:cc:dd:ee:ff  UHLWIir           en0";

        let gw = parse_netstat_gateways(output);
        assert_eq!(gw.get("en0"), Some(&"10.0.0.1".to_string()));
    }

    #[test]
    fn parse_gateways_multiple_interfaces() {
        let output = "\
default            10.0.0.1           UGScg             en0
default            192.168.1.1        UGScg             en4";

        let gw = parse_netstat_gateways(output);
        assert_eq!(gw.get("en0"), Some(&"10.0.0.1".to_string()));
        assert_eq!(gw.get("en4"), Some(&"192.168.1.1".to_string()));
    }

    #[test]
    fn parse_gateways_first_default_wins() {
        let output = "\
default            10.0.0.1           UGScg             en0
default            10.0.0.2           UGScg             en0";

        let gw = parse_netstat_gateways(output);
        assert_eq!(gw.get("en0"), Some(&"10.0.0.1".to_string()));
    }

    #[test]
    fn parse_gateways_ignores_non_en_utun() {
        let output = "default            10.0.0.1           UGScg             lo0";
        let gw = parse_netstat_gateways(output);
        assert!(gw.is_empty());
    }

    #[test]
    fn parse_gateways_empty_output() {
        let gw = parse_netstat_gateways("");
        assert!(gw.is_empty());
    }

    #[test]
    fn parse_gateways_utun_interface() {
        let output = "default            10.64.0.1          UGScg            utun3";
        let gw = parse_netstat_gateways(output);
        assert_eq!(gw.get("utun3"), Some(&"10.64.0.1".to_string()));
    }

    #[test]
    fn parse_gateways_linux_0000_format() {
        let output = "0.0.0.0         192.168.1.1     0.0.0.0         UG    100    0        0 en0";
        let gw = parse_netstat_gateways(output);
        assert_eq!(gw.get("en0"), Some(&"192.168.1.1".to_string()));
    }

    // ── DNS parsing tests ──────────────────────────────────────────────

    #[test]
    fn parse_dns_standard_scutil() {
        let output = "\
resolver #1
  nameserver[0] : 10.0.0.1
  nameserver[1] : 8.8.8.8
  if_index : 6 (en0)
  flags    : Request A records
resolver #2
  nameserver[0] : 192.168.1.1
  if_index : 10 (en4)";

        let dns = parse_scutil_dns(output);
        assert_eq!(
            dns.get("en0"),
            Some(&vec!["10.0.0.1".to_string(), "8.8.8.8".to_string()])
        );
        assert_eq!(
            dns.get("en4"),
            Some(&vec!["192.168.1.1".to_string()])
        );
    }

    #[test]
    fn parse_dns_empty_output() {
        let dns = parse_scutil_dns("");
        assert!(dns.is_empty());
    }

    #[test]
    fn parse_dns_resolver_without_interface() {
        let output = "\
resolver #1
  nameserver[0] : 8.8.8.8
  flags    : Request A records";

        let dns = parse_scutil_dns(output);
        // No if_index means no interface to key on
        assert!(dns.is_empty());
    }

    #[test]
    fn parse_dns_resolver_without_nameservers() {
        let output = "\
resolver #1
  if_index : 6 (en0)
  flags    : Request A records";

        let dns = parse_scutil_dns(output);
        // Interface but no nameservers
        assert!(dns.is_empty());
    }

    #[test]
    fn parse_dns_last_resolver_captured() {
        // The final resolver (no trailing resolver line) should still be captured
        let output = "\
resolver #1
  nameserver[0] : 10.0.0.1
  if_index : 6 (en0)";

        let dns = parse_scutil_dns(output);
        assert_eq!(dns.get("en0"), Some(&vec!["10.0.0.1".to_string()]));
    }

    #[test]
    fn parse_dns_multiple_resolvers_same_interface() {
        let output = "\
resolver #1
  nameserver[0] : 10.0.0.1
  if_index : 6 (en0)
resolver #2
  nameserver[0] : 8.8.8.8
  if_index : 6 (en0)";

        let dns = parse_scutil_dns(output);
        let servers = dns.get("en0").unwrap();
        assert_eq!(servers.len(), 2);
        assert!(servers.contains(&"10.0.0.1".to_string()));
        assert!(servers.contains(&"8.8.8.8".to_string()));
    }
}
