use std::net::IpAddr;
use std::time::Duration;

use crate::collector::{Collector, CollectorOutput};
use crate::config::Config;
use crate::model::{NmapHost, ServiceInfo};

/// Shells out to nmap for ping sweep and optional service detection.
pub struct NmapCollector {
    nmap_bin: String,
    service_detection: bool,
    interval: Duration,
    /// Subnets to scan, derived from interface state at creation time.
    /// Updated dynamically when interfaces change.
    interfaces: Vec<String>,
}

impl NmapCollector {
    pub fn new(config: &Config) -> Self {
        Self {
            nmap_bin: config.nmap.bin.clone(),
            service_detection: config.nmap.service_detection,
            interval: Duration::from_secs(config.scan_interval),
            interfaces: config.interfaces.clone(),
        }
    }

    async fn scan_subnet(&self, subnet: &str) -> anyhow::Result<Vec<NmapHost>> {
        let mut args = vec!["-sn", "-oX", "-", subnet];
        if self.service_detection {
            // Replace -sn with -sV for service detection
            args = vec!["-sV", "--top-ports", "100", "-oX", "-", subnet];
        }

        let output = tokio::process::Command::new(&self.nmap_bin)
            .args(&args)
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("nmap failed: {stderr}");
        }

        let xml = String::from_utf8_lossy(&output.stdout);
        Ok(parse_nmap_xml(&xml))
    }
}

#[async_trait::async_trait]
impl Collector for NmapCollector {
    fn name(&self) -> &str {
        "nmap"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    async fn collect(&self) -> anyhow::Result<CollectorOutput> {
        // For now, scan the default local subnet
        // In practice this would derive from interface state
        let mut all_hosts = Vec::new();
        let iface = self.interfaces.first().cloned().unwrap_or_default();

        // Try common local subnets based on interface
        // A real implementation would get the subnet from the interface collector
        for subnet in &["192.168.1.0/24", "10.0.0.0/24", "192.168.0.0/24"] {
            match self.scan_subnet(subnet).await {
                Ok(hosts) if !hosts.is_empty() => {
                    all_hosts.extend(hosts);
                    break; // Found hosts, use this subnet
                }
                Ok(_) => continue,
                Err(e) => {
                    tracing::debug!("nmap scan of {subnet} failed: {e}");
                    continue;
                }
            }
        }

        tracing::debug!("nmap: found {} hosts", all_hosts.len());
        Ok(CollectorOutput::Nmap {
            interface: iface,
            hosts: all_hosts,
        })
    }
}

/// Parse nmap XML output into host records.
///
/// This is a simple parser that handles the core nmap XML format.
/// For a production implementation, consider using a proper XML parser.
fn parse_nmap_xml(xml: &str) -> Vec<NmapHost> {
    let mut hosts = Vec::new();
    let mut in_host = false;
    let mut current_ip: Option<IpAddr> = None;
    let mut current_mac: Option<String> = None;
    let mut current_hostname: Option<String> = None;
    let mut current_os: Option<String> = None;
    let mut current_services: Vec<ServiceInfo> = Vec::new();

    for line in xml.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("<host ") || trimmed == "<host>" {
            in_host = true;
            current_ip = None;
            current_mac = None;
            current_hostname = None;
            current_os = None;
            current_services.clear();
        } else if trimmed.starts_with("</host>") {
            if in_host {
                if let Some(ip) = current_ip.take() {
                    hosts.push(NmapHost {
                        ip,
                        mac: current_mac.take(),
                        hostname: current_hostname.take(),
                        os_hint: current_os.take(),
                        services: std::mem::take(&mut current_services),
                    });
                }
            }
            in_host = false;
        } else if in_host {
            // Parse address elements
            if trimmed.starts_with("<address ") {
                if let (Some(addr), Some(addr_type)) =
                    (extract_attr(trimmed, "addr"), extract_attr(trimmed, "addrtype"))
                {
                    match addr_type.as_str() {
                        "ipv4" | "ipv6" => {
                            if let Ok(ip) = addr.parse() {
                                current_ip = Some(ip);
                            }
                        }
                        "mac" => {
                            current_mac = Some(addr.to_lowercase().replace('-', ":"));
                        }
                        _ => {}
                    }
                }
            }
            // Parse hostname
            else if trimmed.starts_with("<hostname ") {
                if let Some(name) = extract_attr(trimmed, "name") {
                    current_hostname = Some(name);
                }
            }
            // Parse OS match
            else if trimmed.starts_with("<osmatch ") {
                if let Some(name) = extract_attr(trimmed, "name") {
                    current_os = Some(name);
                }
            }
            // Parse port/service
            else if trimmed.starts_with("<port ") {
                if let (Some(port_str), Some(protocol)) =
                    (extract_attr(trimmed, "portid"), extract_attr(trimmed, "protocol"))
                {
                    if let Ok(port) = port_str.parse::<u16>() {
                        current_services.push(ServiceInfo {
                            port,
                            protocol,
                            name: String::new(),
                            version: String::new(),
                            state: String::new(),
                        });
                    }
                }
            } else if trimmed.starts_with("<state ") {
                if let (Some(state), Some(last_svc)) =
                    (extract_attr(trimmed, "state"), current_services.last_mut())
                {
                    last_svc.state = state;
                }
            } else if trimmed.starts_with("<service ") {
                if let Some(last_svc) = current_services.last_mut() {
                    if let Some(name) = extract_attr(trimmed, "name") {
                        last_svc.name = name;
                    }
                    if let Some(version) = extract_attr(trimmed, "version") {
                        last_svc.version = version;
                    }
                }
            }
        }
    }

    hosts
}

/// Extract an XML attribute value from a tag string.
fn extract_attr(tag: &str, attr: &str) -> Option<String> {
    let pattern = format!("{attr}=\"");
    let start = tag.find(&pattern)? + pattern.len();
    let end = tag[start..].find('"')? + start;
    Some(tag[start..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nmap_ping_sweep() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun>
<host>
<status state="up"/>
<address addr="10.0.0.1" addrtype="ipv4"/>
<address addr="aa:bb:cc:dd:ee:ff" addrtype="mac"/>
<hostnames>
<hostname name="router.local" type="PTR"/>
</hostnames>
</host>
<host>
<status state="up"/>
<address addr="10.0.0.5" addrtype="ipv4"/>
<hostnames/>
</host>
</nmaprun>"#;

        let hosts = parse_nmap_xml(xml);
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].ip.to_string(), "10.0.0.1");
        assert_eq!(hosts[0].mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(hosts[0].hostname.as_deref(), Some("router.local"));
        assert_eq!(hosts[1].ip.to_string(), "10.0.0.5");
        assert!(hosts[1].mac.is_none());
    }

    #[test]
    fn parse_nmap_service_detection() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun>
<host>
<address addr="10.0.0.1" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22">
<state state="open"/>
<service name="ssh" version="OpenSSH 8.9"/>
</port>
<port protocol="tcp" portid="80">
<state state="open"/>
<service name="http" version="nginx 1.18"/>
</port>
</ports>
</host>
</nmaprun>"#;

        let hosts = parse_nmap_xml(xml);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].services.len(), 2);
        assert_eq!(hosts[0].services[0].port, 22);
        assert_eq!(hosts[0].services[0].name, "ssh");
        assert_eq!(hosts[0].services[1].port, 80);
    }
}
