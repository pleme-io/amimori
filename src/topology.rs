//! Network topology — subnet inference and gateway relationship mapping.
//!
//! Derives network structure from collected data:
//! - Which subnets exist (from discovered host IPs)
//! - Which gateways connect subnets
//! - Host-to-subnet membership
//! - Gateway hierarchy
//!
//! This is a pure computation layer — no network probing.
//! Uses data already collected by other collectors.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::model::{HostInfo, InterfaceInfo};

/// A discovered subnet with its hosts and gateway.
#[derive(Debug, Clone)]
pub struct Subnet {
    pub cidr: String,
    pub gateway: String,
    pub interface: String,
    pub host_count: usize,
    pub host_macs: Vec<String>,
}

/// Network topology derived from current state.
#[derive(Debug, Clone)]
pub struct Topology {
    pub subnets: Vec<Subnet>,
    pub gateway_to_subnets: HashMap<String, Vec<String>>,
    pub total_hosts: usize,
}

/// Build topology from current state.
pub fn build_topology(
    hosts: &[HostInfo],
    interfaces: &[InterfaceInfo],
) -> Topology {
    let mut subnets_map: HashMap<String, Subnet> = HashMap::new();

    // Build subnets from interfaces
    for iface in interfaces {
        if !iface.is_up { continue; }
        if let Some(cidr) = iface.cidr() {
            subnets_map.entry(cidr.clone()).or_insert_with(|| Subnet {
                cidr,
                gateway: iface.gateway.clone(),
                interface: iface.name.clone(),
                host_count: 0,
                host_macs: Vec::new(),
            });
        }
    }

    // Assign hosts to subnets
    for host in hosts {
        for addr in &host.addresses {
            if let IpAddr::V4(ip) = addr {
                for subnet in subnets_map.values_mut() {
                    if ip_in_cidr(*ip, &subnet.cidr) {
                        subnet.host_count += 1;
                        subnet.host_macs.push(host.mac.clone());
                        break;
                    }
                }
            }
        }
    }

    // Build gateway→subnet mapping
    let mut gateway_to_subnets: HashMap<String, Vec<String>> = HashMap::new();
    for subnet in subnets_map.values() {
        if !subnet.gateway.is_empty() {
            gateway_to_subnets
                .entry(subnet.gateway.clone())
                .or_default()
                .push(subnet.cidr.clone());
        }
    }

    let total_hosts = hosts.len();
    let subnets: Vec<Subnet> = subnets_map.into_values().collect();

    Topology {
        subnets,
        gateway_to_subnets,
        total_hosts,
    }
}

/// Format topology as human-readable text.
pub fn format_topology(topo: &Topology) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(1024);
    let _ = writeln!(out, "Network Topology ({} hosts, {} subnets)\n", topo.total_hosts, topo.subnets.len());

    for subnet in &topo.subnets {
        let _ = writeln!(
            out, "  {} ({} hosts) via {} on {}",
            subnet.cidr, subnet.host_count, subnet.gateway, subnet.interface
        );
    }

    if !topo.gateway_to_subnets.is_empty() {
        let _ = writeln!(out, "\nGateways:");
        for (gw, subnets) in &topo.gateway_to_subnets {
            let _ = writeln!(out, "  {} → {}", gw, subnets.join(", "));
        }
    }

    out
}

/// Check if an IPv4 address falls within a CIDR range.
fn ip_in_cidr(ip: std::net::Ipv4Addr, cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 { return false; }
    let Ok(network) = parts[0].parse::<std::net::Ipv4Addr>() else { return false };
    let Ok(prefix) = parts[1].parse::<u32>() else { return false };
    if prefix > 32 { return false; }

    let mask = if prefix == 0 { 0u32 } else { !0u32 << (32 - prefix) };
    let net = u32::from(network) & mask;
    let host = u32::from(ip) & mask;
    net == host
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_in_cidr_24() {
        assert!(ip_in_cidr("192.168.1.100".parse().unwrap(), "192.168.1.0/24"));
        assert!(!ip_in_cidr("192.168.2.100".parse().unwrap(), "192.168.1.0/24"));
    }

    #[test]
    fn ip_in_cidr_16() {
        assert!(ip_in_cidr("10.0.5.42".parse().unwrap(), "10.0.0.0/16"));
        assert!(!ip_in_cidr("10.1.0.1".parse().unwrap(), "10.0.0.0/16"));
    }

    #[test]
    fn ip_in_cidr_32() {
        assert!(ip_in_cidr("10.0.0.1".parse().unwrap(), "10.0.0.1/32"));
        assert!(!ip_in_cidr("10.0.0.2".parse().unwrap(), "10.0.0.1/32"));
    }

    #[test]
    fn format_topology_empty() {
        let topo = Topology { subnets: vec![], gateway_to_subnets: HashMap::new(), total_hosts: 0 };
        let out = format_topology(&topo);
        assert!(out.contains("0 hosts"));
        assert!(out.contains("0 subnets"));
    }

    #[test]
    fn ip_in_cidr_0() {
        // /0 matches everything
        assert!(ip_in_cidr("192.168.1.1".parse().unwrap(), "0.0.0.0/0"));
        assert!(ip_in_cidr("10.0.0.1".parse().unwrap(), "0.0.0.0/0"));
    }

    #[test]
    fn ip_in_cidr_31() {
        // /31 point-to-point: only 2 IPs
        assert!(ip_in_cidr("10.0.0.0".parse().unwrap(), "10.0.0.0/31"));
        assert!(ip_in_cidr("10.0.0.1".parse().unwrap(), "10.0.0.0/31"));
        assert!(!ip_in_cidr("10.0.0.2".parse().unwrap(), "10.0.0.0/31"));
    }

    #[test]
    fn ip_in_cidr_invalid() {
        assert!(!ip_in_cidr("10.0.0.1".parse().unwrap(), "not-a-cidr"));
        assert!(!ip_in_cidr("10.0.0.1".parse().unwrap(), "10.0.0.0/33"));
    }

    #[test]
    fn format_topology_with_subnet() {
        let topo = Topology {
            subnets: vec![Subnet {
                cidr: "10.0.0.0/24".into(),
                gateway: "10.0.0.1".into(),
                interface: "en0".into(),
                host_count: 5,
                host_macs: vec![],
            }],
            gateway_to_subnets: {
                let mut m = HashMap::new();
                m.insert("10.0.0.1".into(), vec!["10.0.0.0/24".into()]);
                m
            },
            total_hosts: 5,
        };
        let out = format_topology(&topo);
        assert!(out.contains("10.0.0.0/24"));
        assert!(out.contains("5 hosts"));
        assert!(out.contains("10.0.0.1"));
    }
}
