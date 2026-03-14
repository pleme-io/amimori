//! Reverse DNS collector — PTR lookups for all discovered IPs.
//!
//! For every IP in the host table without a hostname, queries the
//! PTR record. Often reveals descriptive names like
//! `printer-3rd-floor.company.com` or `ap-lobby.company.com`.
//!
//! Safety level: 2 (Discovery) — sends DNS queries to the configured resolver.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;

use crate::collector::{Collector, CollectorOutput};
use crate::collector::banner::BannerResult;
use crate::config::Config;
use crate::model::{Fingerprint, FingerprintSource};
use crate::state::StateEngine;

pub struct DnsCollector {
    interval: Duration,
    max_failures: u32,
    engine: Arc<StateEngine>,
}

impl DnsCollector {
    pub fn new(_config: &Config, engine: Arc<StateEngine>) -> Self {
        Self {
            interval: Duration::from_secs(120),
            max_failures: 5,
            engine,
        }
    }
}

#[async_trait::async_trait]
impl Collector for DnsCollector {
    fn name(&self) -> &str {
        "dns"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn max_failures(&self) -> u32 {
        self.max_failures
    }

    async fn collect(&self) -> anyhow::Result<CollectorOutput> {
        let now = Utc::now();
        let mut results = Vec::new();

        // Collect IPs that need reverse DNS
        let targets: Vec<(String, std::net::IpAddr)> = self
            .engine
            .state
            .hosts
            .iter()
            .filter(|e| {
                e.value().fingerprint("net", "dns_hostname").is_none()
            })
            .flat_map(|e| {
                let mac = e.key().clone();
                e.value()
                    .addresses
                    .iter()
                    .map(move |ip| (mac.clone(), *ip))
                    .collect::<Vec<_>>()
            })
            .collect();

        for (mac, ip) in targets {
            // Use system DNS via dig/host command for reverse lookup
            let ip_str = ip.to_string();
            let output = tokio::process::Command::new(crate::platform::system_bin("host"))
                .arg(&ip_str)
                .output()
                .await;

            if let Ok(out) = output {
                if out.status.success() {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    // Parse "X.X.X.X.in-addr.arpa domain name pointer hostname."
                    if let Some(hostname) = parse_host_output(&stdout) {
                        results.push(BannerResult {
                            mac,
                            ip: ip_str,
                            port: 53,
                            protocol: "dns".into(),
                            banner: String::new(),
                            fingerprints: vec![Fingerprint {
                                source: FingerprintSource::Nmap,
                                category: "net".into(),
                                key: "dns_hostname".into(),
                                value: hostname,
                                confidence: 0.85,
                                observed_at: now,
                            }],
                        });
                    }
                }
            }
        }

        tracing::debug!(resolved = results.len(), "reverse DNS complete");
        Ok(CollectorOutput::Banners(results))
    }
}

/// Parse `host` command output to extract PTR hostname.
/// Input: "1.0.168.192.in-addr.arpa domain name pointer myhost.local."
fn parse_host_output(output: &str) -> Option<String> {
    for line in output.lines() {
        if let Some(idx) = line.find("domain name pointer ") {
            let hostname = line[idx + 20..].trim().trim_end_matches('.');
            if !hostname.is_empty() {
                return Some(hostname.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_host_output_standard() {
        let output = "101.223.20.10.in-addr.arpa domain name pointer myprinter.local.\n";
        assert_eq!(parse_host_output(output).as_deref(), Some("myprinter.local"));
    }

    #[test]
    fn parse_host_output_no_ptr() {
        let output = "Host 10.0.0.1 not found: 3(NXDOMAIN)\n";
        assert!(parse_host_output(output).is_none());
    }

    #[test]
    fn parse_host_output_multiple_lines() {
        let output = "Using domain server:\nName: 127.0.0.1\n\n1.0.0.10.in-addr.arpa domain name pointer router.lan.\n";
        assert_eq!(parse_host_output(output).as_deref(), Some("router.lan"));
    }
}
