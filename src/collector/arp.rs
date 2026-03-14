use std::net::IpAddr;
use std::time::Duration;

use crate::collector::{Collector, CollectorOutput};
use crate::config::Config;
use crate::model::{ArpEntry, normalize_mac};

/// Parses `arp -a` output for each monitored interface. No root required.
pub struct ArpCollector {
    interfaces: Vec<String>,
    interval: Duration,
    max_failures: u32,
}

impl ArpCollector {
    pub fn new(config: &Config) -> Self {
        Self {
            interfaces: config.interfaces.clone(),
            interval: Duration::from_secs(config.collectors.arp.interval),
            max_failures: config.collectors.arp.max_failures,
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

    fn max_failures(&self) -> u32 {
        self.max_failures
    }

    async fn collect(&self) -> anyhow::Result<CollectorOutput> {
        let output = tokio::process::Command::new("arp")
            .arg("-a")
            .output()
            .await?;

        if !output.status.success() {
            anyhow::bail!(
                "arp -a exited with {}",
                output.status.code().unwrap_or(-1)
            );
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let entries = parse_arp_output(&stdout, &self.interfaces);
        tracing::debug!(count = entries.len(), "arp scan complete");
        Ok(CollectorOutput::Arp(entries))
    }
}

/// Parse macOS/Linux `arp -a` output. Pure function — no IO.
///
/// Format: `? (10.0.0.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]`
pub fn parse_arp_output(output: &str, monitored: &[String]) -> Vec<ArpEntry> {
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
        let Ok(ip) = line[ip_start + 1..ip_end].parse::<IpAddr>() else {
            continue;
        };

        // Extract MAC after " at "
        let after_paren = &line[ip_end + 1..];
        let Some(at_pos) = after_paren.find(" at ") else {
            continue;
        };
        let after_at = &after_paren[at_pos + 4..];
        let raw_mac = after_at.split_whitespace().next().unwrap_or("");

        let Some(mac) = normalize_mac(raw_mac) else {
            continue;
        };

        // Extract interface after " on "
        let interface = after_at
            .find(" on ")
            .and_then(|pos| after_at[pos + 4..].split_whitespace().next())
            .unwrap_or("");

        // Filter to monitored interfaces (empty = accept all)
        if !monitored.is_empty() && !monitored.iter().any(|m| m == interface) {
            continue;
        }

        // Extract hostname (part before the IP parens)
        let hostname_part = line[..ip_start].trim();
        let hostname = if hostname_part == "?" || hostname_part.is_empty() {
            None
        } else {
            Some(hostname_part.to_string())
        };

        entries.push(ArpEntry {
            ip,
            mac,
            interface: interface.to_string(),
            hostname,
        });
    }

    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_standard_arp_output() {
        let output = "? (10.0.0.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n\
                       router.local (10.0.0.254) at 11:22:33:44:55:66 on en0 ifscope [ethernet]\n\
                       ? (10.0.0.5) at (incomplete) on en0 ifscope [ethernet]\n\
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
    fn skips_incomplete_entries() {
        let output = "? (10.0.0.5) at (incomplete) on en0 ifscope [ethernet]";
        let entries = parse_arp_output(output, &[]);
        assert!(entries.is_empty());
    }

    #[test]
    fn skips_lines_without_parens() {
        let output = "garbage line\nanother bad line";
        let entries = parse_arp_output(output, &[]);
        assert!(entries.is_empty());
    }

    #[test]
    fn skips_lines_without_at() {
        let output = "? (10.0.0.1) missing_at aa:bb:cc:dd:ee:ff on en0";
        let entries = parse_arp_output(output, &[]);
        assert!(entries.is_empty());
    }

    #[test]
    fn skips_invalid_ip() {
        let output = "? (not.an.ip) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]";
        let entries = parse_arp_output(output, &[]);
        assert!(entries.is_empty());
    }

    #[test]
    fn normalizes_single_digit_mac_octets() {
        let output = "? (10.0.0.1) at a:b:c:d:e:f on en0 ifscope [ethernet]";
        let entries = parse_arp_output(output, &[]);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].mac, "0a:0b:0c:0d:0e:0f");
    }

    #[test]
    fn handles_empty_output() {
        let entries = parse_arp_output("", &[]);
        assert!(entries.is_empty());
    }

    #[test]
    fn handles_whitespace_only_output() {
        let entries = parse_arp_output("   \n\n  \n", &[]);
        assert!(entries.is_empty());
    }

    #[test]
    fn interface_filter_excludes_unmonitored() {
        let output = "? (10.0.0.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n\
                       ? (10.0.0.2) at 11:22:33:44:55:66 on en4 ifscope [ethernet]";
        let entries = parse_arp_output(output, &["en4".to_string()]);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].interface, "en4");
    }

    #[test]
    fn extracts_hostname_when_present() {
        let output = "mydevice.local (10.0.0.42) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]";
        let entries = parse_arp_output(output, &[]);
        assert_eq!(entries[0].hostname.as_deref(), Some("mydevice.local"));
    }

    #[test]
    fn question_mark_hostname_is_none() {
        let output = "? (10.0.0.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]";
        let entries = parse_arp_output(output, &[]);
        assert!(entries[0].hostname.is_none());
    }

    #[test]
    fn handles_multicast_addresses() {
        let output = "? (224.0.0.251) at 01:00:5e:00:00:fb on en0 ifscope permanent [ethernet]";
        let entries = parse_arp_output(output, &[]);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ip.to_string(), "224.0.0.251");
    }
}
