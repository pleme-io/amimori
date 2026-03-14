use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};

use crate::collector::{Collector, CollectorOutput};
use crate::config::Config;
use crate::model::{InterfaceInfo, InterfaceKind};

/// Collects network interface state using the `network-interface` crate.
/// Augments with gateway info from `netstat -rn` and DNS from `scutil --dns`.
pub struct InterfaceCollector {
    monitored: Vec<String>,
    interval: Duration,
}

impl InterfaceCollector {
    pub fn new(config: &Config) -> Self {
        Self {
            monitored: config.interfaces.clone(),
            interval: Duration::from_secs(config.interface_interval),
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

    async fn collect(&self) -> anyhow::Result<CollectorOutput> {
        let net_interfaces = NetworkInterface::show()?;
        let gateways = get_gateways().await;
        let dns_servers = get_dns_servers().await;

        let mut interfaces = Vec::new();

        for ni in &net_interfaces {
            // Filter to monitored interfaces if specified
            if !self.monitored.is_empty() && !self.monitored.iter().any(|m| m == &ni.name) {
                continue;
            }

            // Skip loopback unless explicitly monitored
            if ni.name == "lo0" && !self.monitored.iter().any(|m| m == "lo0") {
                continue;
            }

            let mut ipv4 = Vec::new();
            let mut ipv6 = Vec::new();
            let mut subnet = String::new();

            for addr in &ni.addr {
                match addr {
                    Addr::V4(v4_addr) => {
                        ipv4.push(IpAddr::V4(v4_addr.ip));
                        if let Some(mask) = v4_addr.netmask {
                            if subnet.is_empty() {
                                subnet = mask.to_string();
                            }
                        }
                    }
                    Addr::V6(v6_addr) => {
                        ipv6.push(IpAddr::V6(v6_addr.ip));
                    }
                }
            }

            let mac = ni
                .mac_addr
                .as_deref()
                .unwrap_or("")
                .to_lowercase();

            let kind = classify_interface(&ni.name, &mac);
            let gateway = gateways.get(&ni.name).cloned().unwrap_or_default();
            let dns = dns_servers.get(&ni.name).cloned().unwrap_or_default();

            // Determine if interface is up by checking if it has addresses
            let is_up = !ipv4.is_empty() || !ipv6.is_empty();

            interfaces.push(InterfaceInfo {
                name: ni.name.clone(),
                mac,
                ipv4,
                ipv6,
                gateway,
                subnet,
                is_up,
                kind,
                dns,
            });
        }

        tracing::debug!("interface: found {} interfaces", interfaces.len());
        Ok(CollectorOutput::Interfaces(interfaces))
    }
}

fn classify_interface(name: &str, _mac: &str) -> InterfaceKind {
    if name == "lo0" || name == "lo" {
        InterfaceKind::Loopback
    } else if name.starts_with("en0") {
        // en0 is typically WiFi on macOS
        InterfaceKind::Wifi
    } else if name.starts_with("en") {
        InterfaceKind::Ethernet
    } else if name.starts_with("utun") || name.starts_with("tun") || name.starts_with("ipsec") {
        InterfaceKind::Tunnel
    } else {
        InterfaceKind::Other
    }
}

/// Parse `netstat -rn` to extract default gateways per interface.
async fn get_gateways() -> HashMap<String, String> {
    let mut gateways = HashMap::new();

    let Ok(output) = tokio::process::Command::new("netstat")
        .args(["-rn"])
        .output()
        .await
    else {
        return gateways;
    };

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        // Look for default route entries
        if parts.len() >= 4 && (parts[0] == "default" || parts[0] == "0.0.0.0") {
            let gateway = parts[1];
            // On macOS, interface is typically the last column
            if let Some(iface) = parts.last() {
                if iface.starts_with("en") || iface.starts_with("utun") {
                    gateways.entry((*iface).to_string()).or_insert_with(|| gateway.to_string());
                }
            }
        }
    }

    gateways
}

/// Parse `scutil --dns` to extract DNS servers per interface.
async fn get_dns_servers() -> HashMap<String, Vec<String>> {
    let mut dns_map: HashMap<String, Vec<String>> = HashMap::new();

    let Ok(output) = tokio::process::Command::new("scutil")
        .args(["--dns"])
        .output()
        .await
    else {
        return dns_map;
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut current_iface = String::new();
    let mut current_servers = Vec::new();

    for line in stdout.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("resolver") {
            // Save previous resolver's data
            if !current_iface.is_empty() && !current_servers.is_empty() {
                dns_map
                    .entry(current_iface.clone())
                    .or_default()
                    .extend(current_servers.drain(..));
            }
            current_iface.clear();
            current_servers.clear();
        } else if let Some(iface) = trimmed.strip_prefix("if_index : ") {
            // Extract interface name from "if_index : 6 (en0)"
            if let Some(start) = iface.find('(') {
                if let Some(end) = iface.find(')') {
                    current_iface = iface[start + 1..end].to_string();
                }
            }
        } else if let Some(ns) = trimmed.strip_prefix("nameserver[") {
            // Extract DNS server from "nameserver[0] : 10.0.0.1"
            if let Some(addr) = ns.split(" : ").nth(1) {
                current_servers.push(addr.trim().to_string());
            }
        }
    }

    // Don't forget the last resolver
    if !current_iface.is_empty() && !current_servers.is_empty() {
        dns_map
            .entry(current_iface)
            .or_default()
            .extend(current_servers);
    }

    dns_map
}
