use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use quick_xml::Reader;
use quick_xml::events::Event;

use crate::collector::{Collector, CollectorOutput};
use crate::config::Config;
use crate::model::{NmapHost, ServiceInfo};
use crate::state::StateEngine;

/// Shells out to nmap for host discovery and optional service detection.
///
/// Subnets can be configured explicitly or auto-derived from active interfaces.
pub struct NmapCollector {
    nmap_bin: String,
    service_detection: bool,
    os_detection: bool,
    top_ports: u16,
    version_intensity: u8,
    interval: Duration,
    timeout: Duration,
    max_failures: u32,
    configured_subnets: Vec<String>,
    engine: Arc<StateEngine>,
}

impl NmapCollector {
    pub fn new(config: &Config, engine: Arc<StateEngine>) -> Self {
        Self {
            nmap_bin: config.collectors.nmap.bin.clone(),
            service_detection: config.collectors.nmap.service_detection,
            os_detection: config.collectors.nmap.os_detection,
            top_ports: config.collectors.nmap.top_ports,
            version_intensity: config.collectors.nmap.version_intensity,
            interval: Duration::from_secs(config.collectors.nmap.interval),
            timeout: Duration::from_secs(config.collectors.nmap.timeout),
            max_failures: config.collectors.nmap.max_failures,
            configured_subnets: config.collectors.nmap.subnets.clone(),
            engine,
        }
    }

    /// Determine which subnets to scan, paired with their owning interface.
    /// Re-derived every tick so network changes are picked up immediately.
    fn resolve_targets(&self) -> Vec<(String, String)> {
        if !self.configured_subnets.is_empty() {
            // Configured subnets: pair with first active interface
            let iface = self
                .engine
                .state
                .interfaces
                .iter()
                .find(|e| e.value().is_up)
                .map(|e| e.key().clone())
                .unwrap_or_default();
            return self
                .configured_subnets
                .iter()
                .map(|s| (iface.clone(), s.clone()))
                .collect();
        }

        // Auto-derive: each active interface's CIDR paired with its name
        self.engine
            .state
            .interfaces
            .iter()
            .filter(|e| e.value().is_up)
            .filter_map(|e| {
                e.value()
                    .cidr()
                    .map(|cidr| (e.key().clone(), cidr))
            })
            .collect()
    }

    async fn scan_subnet(&self, subnet: &str) -> anyhow::Result<Vec<NmapHost>> {
        let mut args: Vec<String> = Vec::new();

        if self.service_detection {
            args.push("-sV".into());
            args.push(format!("--version-intensity={}", self.version_intensity));
            args.push("--top-ports".into());
            args.push(self.top_ports.to_string());
        } else {
            args.push("-sn".into());
        }
        if self.os_detection {
            args.push("-O".into());
            args.push("--osscan-guess".into());
        }
        args.extend(["-oX".into(), "-".into(), subnet.into()]);

        let result = tokio::time::timeout(
            self.timeout,
            tokio::process::Command::new(&self.nmap_bin)
                .args(&args)
                .output(),
        )
        .await;

        let output = match result {
            Ok(Ok(out)) => out,
            Ok(Err(e)) => anyhow::bail!("nmap exec failed: {e}"),
            Err(_) => anyhow::bail!("nmap timed out after {}s", self.timeout.as_secs()),
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("nmap exited {}: {stderr}", output.status);
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

    fn max_failures(&self) -> u32 {
        self.max_failures
    }

    async fn collect(&self) -> anyhow::Result<CollectorOutput> {
        let targets = self.resolve_targets();
        if targets.is_empty() {
            tracing::debug!("no subnets to scan (no active interfaces with addresses)");
            return Ok(CollectorOutput::Nmap {
                interface: String::new(),
                hosts: Vec::new(),
            });
        }

        let primary_iface = targets
            .first()
            .map(|(iface, _)| iface.clone())
            .unwrap_or_default();

        // Scan all subnets in parallel — each nmap runs as an independent process.
        let scan_futures: Vec<_> = targets
            .iter()
            .map(|(iface, subnet)| {
                let iface = iface.clone();
                let subnet = subnet.clone();
                async move {
                    match self.scan_subnet(&subnet).await {
                        Ok(hosts) => {
                            tracing::debug!(
                                interface = %iface,
                                subnet = %subnet,
                                count = hosts.len(),
                                "nmap scan complete"
                            );
                            Ok(hosts)
                        }
                        Err(e) => {
                            tracing::warn!(
                                interface = %iface,
                                subnet = %subnet,
                                error = %e,
                                "nmap scan failed"
                            );
                            Err(())
                        }
                    }
                }
            })
            .collect();

        let results = futures::future::join_all(scan_futures).await;
        let total = results.len();
        let failed = results.iter().filter(|r| r.is_err()).count();
        if failed > 0 {
            tracing::warn!(failed, total, "partial nmap scan results");
        }
        let all_hosts: Vec<NmapHost> = results.into_iter().filter_map(Result::ok).flatten().collect();

        Ok(CollectorOutput::Nmap {
            interface: primary_iface,
            hosts: all_hosts,
        })
    }
}

// ── XML parsing via quick-xml ──────────────────────────────────────────────

fn parse_nmap_xml(xml: &str) -> Vec<NmapHost> {
    let mut reader = Reader::from_str(xml);
    let mut hosts = Vec::new();

    let mut in_host = false;
    let mut current_ip: Option<IpAddr> = None;
    let mut current_mac: Option<String> = None;
    let mut current_hostname: Option<String> = None;
    let mut current_os: Option<String> = None;
    let mut current_services: Vec<ServiceInfo> = Vec::new();
    let mut current_service: Option<ServiceInfo> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e) | Event::Empty(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let attrs = collect_attrs(&e);

                match name.as_str() {
                    "host" => {
                        in_host = true;
                        current_ip = None;
                        current_mac = None;
                        current_hostname = None;
                        current_os = None;
                        current_services.clear();
                    }
                    "ports" => {},
                    "address" if in_host => {
                        if let (Some(addr), Some(addrtype)) =
                            (attrs.get("addr"), attrs.get("addrtype"))
                        {
                            match addrtype.as_str() {
                                "ipv4" | "ipv6" => {
                                    current_ip = addr.parse().ok();
                                }
                                "mac" => {
                                    current_mac =
                                        Some(addr.to_lowercase().replace('-', ":"));
                                }
                                _ => {}
                            }
                        }
                    }
                    "hostname" if in_host => {
                        if let Some(name) = attrs.get("name") {
                            current_hostname = Some(name.clone());
                        }
                    }
                    "osmatch" if in_host => {
                        if current_os.is_none() {
                            current_os = attrs.get("name").cloned();
                        }
                    }
                    "port" if in_host => {
                        if let (Some(portid), Some(protocol)) =
                            (attrs.get("portid"), attrs.get("protocol"))
                        {
                            if let Ok(port) = portid.parse::<u16>() {
                                current_service = Some(ServiceInfo {
                                    port,
                                    protocol: protocol.clone(),
                                    name: String::new(),
                                    version: String::new(),
                                    state: String::new(),
                                    banner: String::new(),
                                });
                            }
                        }
                    }
                    "state" if current_service.is_some() => {
                        if let Some(state) = attrs.get("state") {
                            if let Some(svc) = current_service.as_mut() {
                                svc.state = state.clone();
                            }
                        }
                    }
                    "service" if current_service.is_some() => {
                        if let Some(svc) = current_service.as_mut() {
                            if let Some(n) = attrs.get("name") {
                                svc.name = n.clone();
                            }
                            if let Some(v) = attrs.get("version") {
                                svc.version = v.clone();
                            }
                        }
                    }
                    _ => {}
                }

            }
            Ok(Event::End(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                match name.as_str() {
                    "host" => {
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
                    }
                    "ports" => {},
                    "port" => {
                        if let Some(svc) = current_service.take() {
                            current_services.push(svc);
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                tracing::warn!(error = %e, "nmap XML parse error");
                break;
            }
            _ => {}
        }
    }

    hosts
}

fn collect_attrs(e: &quick_xml::events::BytesStart<'_>) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for attr in e.attributes().flatten() {
        let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
        let val = String::from_utf8_lossy(&attr.value).to_string();
        map.insert(key, val);
    }
    map
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

    #[test]
    fn parse_nmap_empty_xml() {
        let xml = r#"<?xml version="1.0"?><nmaprun></nmaprun>"#;
        let hosts = parse_nmap_xml(xml);
        assert!(hosts.is_empty());
    }

    #[test]
    fn parse_nmap_host_without_ip_skipped() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun>
<host>
<status state="up"/>
<address addr="aa:bb:cc:dd:ee:ff" addrtype="mac"/>
</host>
</nmaprun>"#;
        let hosts = parse_nmap_xml(xml);
        assert!(hosts.is_empty(), "hosts without IP should be skipped");
    }

    #[test]
    fn parse_nmap_ipv6_address() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun>
<host>
<address addr="fe80::1" addrtype="ipv6"/>
</host>
</nmaprun>"#;
        let hosts = parse_nmap_xml(xml);
        assert_eq!(hosts.len(), 1);
        assert!(hosts[0].ip.is_ipv6());
    }

    #[test]
    fn parse_nmap_os_detection() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun>
<host>
<address addr="10.0.0.1" addrtype="ipv4"/>
<os>
<osmatch name="Linux 5.4" accuracy="95"/>
<osmatch name="Linux 4.15" accuracy="85"/>
</os>
</host>
</nmaprun>"#;
        let hosts = parse_nmap_xml(xml);
        assert_eq!(hosts[0].os_hint.as_deref(), Some("Linux 5.4"), "should take first osmatch");
    }

    #[test]
    fn parse_nmap_port_state_and_version() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun>
<host>
<address addr="10.0.0.1" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="443">
<state state="open"/>
<service name="https" version="Apache 2.4.41"/>
</port>
</ports>
</host>
</nmaprun>"#;
        let hosts = parse_nmap_xml(xml);
        assert_eq!(hosts[0].services[0].state, "open");
        assert_eq!(hosts[0].services[0].version, "Apache 2.4.41");
    }

    #[test]
    fn parse_nmap_port_without_service_info() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun>
<host>
<address addr="10.0.0.1" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="8080">
<state state="open"/>
</port>
</ports>
</host>
</nmaprun>"#;
        let hosts = parse_nmap_xml(xml);
        assert_eq!(hosts[0].services[0].port, 8080);
        assert_eq!(hosts[0].services[0].name, "");
    }

    #[test]
    fn parse_nmap_mac_normalization() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun>
<host>
<address addr="10.0.0.1" addrtype="ipv4"/>
<address addr="AA-BB-CC-DD-EE-FF" addrtype="mac"/>
</host>
</nmaprun>"#;
        let hosts = parse_nmap_xml(xml);
        assert_eq!(hosts[0].mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn parse_nmap_multiple_hosts() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun>
<host><address addr="10.0.0.1" addrtype="ipv4"/></host>
<host><address addr="10.0.0.2" addrtype="ipv4"/></host>
<host><address addr="10.0.0.3" addrtype="ipv4"/></host>
</nmaprun>"#;
        let hosts = parse_nmap_xml(xml);
        assert_eq!(hosts.len(), 3);
    }

    #[test]
    fn parse_nmap_malformed_port_id_skipped() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun>
<host>
<address addr="10.0.0.1" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="not_a_number">
<state state="open"/>
</port>
<port protocol="tcp" portid="22">
<state state="open"/>
</port>
</ports>
</host>
</nmaprun>"#;
        let hosts = parse_nmap_xml(xml);
        assert_eq!(hosts[0].services.len(), 1, "invalid port ID should be skipped");
        assert_eq!(hosts[0].services[0].port, 22);
    }
}
