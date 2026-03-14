use std::net::IpAddr;
use std::time::Duration;

use crate::collector::{Collector, CollectorOutput};
use crate::config::Config;
use crate::model::ArpEntry;

/// Parses `arp -a` output for each monitored interface. No root required.
pub struct ArpCollector {
    interfaces: Vec<String>,
    interval: Duration,
}

impl ArpCollector {
    pub fn new(config: &Config) -> Self {
        Self {
            interfaces: config.interfaces.clone(),
            interval: Duration::from_secs(config.arp_interval),
        }
    }
}

#[async_trait::async_trait]
impl Collector for ArpCollector {
    fn name(&self) -> &str {
        "arp"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    async fn collect(&self) -> anyhow::Result<CollectorOutput> {
        let output = tokio::process::Command::new("arp")
            .arg("-a")
            .output()
            .await?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let entries = parse_arp_output(&stdout, &self.interfaces);

        tracing::debug!("arp: found {} entries", entries.len());
        Ok(CollectorOutput::Arp(entries))
    }
}

/// Parse macOS/Linux `arp -a` output.
///
/// Format: `? (10.0.0.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]`
/// Or:     `hostname (10.0.0.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]`
fn parse_arp_output(output: &str, monitored: &[String]) -> Vec<ArpEntry> {
    let mut entries = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Extract IP from parentheses
        let Some(ip_start) = line.find('(') else {
            continue;
        };
        let Some(ip_end) = line.find(')') else {
            continue;
        };
        let ip_str = &line[ip_start + 1..ip_end];
        let Ok(ip) = ip_str.parse::<IpAddr>() else {
            continue;
        };

        // Extract MAC after " at "
        let after_paren = &line[ip_end + 1..];
        let Some(at_pos) = after_paren.find(" at ") else {
            continue;
        };
        let after_at = &after_paren[at_pos + 4..];

        // MAC is the next token
        let mac = after_at.split_whitespace().next().unwrap_or("");
        if mac == "(incomplete)" || mac.len() < 8 {
            continue;
        }

        // Extract interface after " on "
        let interface = after_at
            .find(" on ")
            .map(|pos| {
                after_at[pos + 4..]
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
            })
            .unwrap_or("");

        // Filter to monitored interfaces
        if !monitored.is_empty() && !monitored.iter().any(|m| m == interface) {
            continue;
        }

        // Extract hostname (the part before the IP in parens)
        let hostname_part = line[..ip_start].trim();
        let hostname = if hostname_part == "?" || hostname_part.is_empty() {
            None
        } else {
            Some(hostname_part.to_string())
        };

        entries.push(ArpEntry {
            ip,
            mac: normalize_mac(mac),
            interface: interface.to_string(),
            hostname,
        });
    }

    entries
}

/// Normalize MAC to lowercase colon-separated format.
fn normalize_mac(mac: &str) -> String {
    let parts: Vec<&str> = mac.split(':').collect();
    parts
        .iter()
        .map(|p| {
            if p.len() == 1 {
                format!("0{}", p.to_lowercase())
            } else {
                p.to_lowercase()
            }
        })
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_standard_arp_output() {
        let output = r"? (10.0.0.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
router.local (10.0.0.254) at 11:22:33:44:55:66 on en0 ifscope [ethernet]
? (10.0.0.5) at (incomplete) on en0 ifscope [ethernet]
? (192.168.1.1) at a1:b2:c3:d4:e5:f6 on en4 ifscope [ethernet]";

        let entries = parse_arp_output(output, &["en0".to_string()]);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].ip.to_string(), "10.0.0.1");
        assert_eq!(entries[0].mac, "aa:bb:cc:dd:ee:ff");
        assert!(entries[0].hostname.is_none());
        assert_eq!(entries[1].hostname.as_deref(), Some("router.local"));
    }

    #[test]
    fn parse_with_all_interfaces() {
        let output = "? (10.0.0.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n\
                       ? (192.168.1.1) at 11:22:33:44:55:66 on en4 ifscope [ethernet]";

        let entries = parse_arp_output(output, &[]);
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn normalize_mac_single_digit() {
        assert_eq!(normalize_mac("a:b:c:d:e:f"), "0a:0b:0c:0d:0e:0f");
    }
}
