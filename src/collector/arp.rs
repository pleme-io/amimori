use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::collector::{Collector, CollectorOutput};
use crate::config::Config;
use crate::model::{ArpEntry, normalize_mac};
use crate::traits::CommandRunner;

/// Parses `arp -a` output for each monitored interface. No root required.
pub struct ArpCollector {
    interfaces: Vec<String>,
    interval: Duration,
    max_failures: u32,
    cmd: Arc<dyn CommandRunner>,
}

impl ArpCollector {
    pub fn new(config: &Config, cmd: Arc<dyn CommandRunner>) -> Self {
        Self {
            interfaces: config.interfaces.clone(),
            interval: Duration::from_secs(config.collectors.arp.interval),
            max_failures: config.collectors.arp.max_failures,
            cmd,
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
        let output = self
            .cmd
            .run(crate::platform::system_bin("arp"), &["-a"])
            .await?;

        if !output.success {
            anyhow::bail!("arp -a failed: {}", output.stderr);
        }

        let entries = parse_arp_output(&output.stdout, &self.interfaces);
        tracing::debug!(count = entries.len(), "arp scan complete");
        Ok(CollectorOutput::Arp(entries))
    }
}

// ── Pure parsing (testable without system commands) ──────────────────────

pub fn parse_arp_output(output: &str, monitored: &[String]) -> Vec<ArpEntry> {
    let mut entries = Vec::new();

    for line in output.lines() {
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
                       router.local (10.0.0.254) at 10:22:33:44:55:66 on en0 ifscope [ethernet]\n\
                       ? (10.0.0.5) at (incomplete) on en0 ifscope [ethernet]\n\
                       ? (192.168.1.1) at a0:b2:c3:d4:e5:f6 on en4 ifscope [ethernet]";

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
                       ? (192.168.1.1) at 10:22:33:44:55:66 on en4 ifscope [ethernet]";
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
                       ? (10.0.0.2) at 10:22:33:44:55:66 on en4 ifscope [ethernet]";
        let entries = parse_arp_output(output, &["en4".to_string()]);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ip.to_string(), "10.0.0.2");
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
    fn rejects_multicast_addresses() {
        let output = "? (224.0.0.251) at 01:00:5e:00:00:fb on en0 ifscope permanent [ethernet]";
        let entries = parse_arp_output(output, &[]);
        assert!(entries.is_empty());
    }

    #[test]
    fn rejects_broadcast_mac() {
        let output = "? (10.20.223.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]";
        let entries = parse_arp_output(output, &[]);
        assert!(entries.is_empty());
    }

    // ── CommandRunner-based integration test ────────────────────────────

    #[tokio::test]
    async fn arp_collector_with_mock_runner() {
        use crate::traits::mocks::MockCommandRunner;

        let arp_output = "? (10.0.0.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n\
                          myhost.local (10.0.0.2) at 10:22:33:44:55:66 on en0 ifscope [ethernet]";

        let runner = Arc::new(MockCommandRunner::new());
        runner.set_response(
            crate::platform::system_bin("arp"),
            crate::traits::CommandOutput {
                success: true,
                stdout: arp_output.to_string(),
                stderr: String::new(),
            },
        );

        let mut config = crate::config::Config::default();
        config.interfaces = vec!["en0".to_string()];

        let collector = ArpCollector::new(&config, runner);
        let result = collector.collect().await.unwrap();

        match result {
            CollectorOutput::Arp(entries) => {
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0].mac, "aa:bb:cc:dd:ee:ff");
                assert_eq!(entries[1].hostname.as_deref(), Some("myhost.local"));
            }
            _ => panic!("expected Arp output"),
        }
    }

    #[tokio::test]
    async fn arp_collector_handles_command_failure() {
        use crate::traits::mocks::MockCommandRunner;

        let runner = Arc::new(MockCommandRunner::new());
        runner.set_response(
            crate::platform::system_bin("arp"),
            crate::traits::CommandOutput {
                success: false,
                stdout: String::new(),
                stderr: "arp: command not found".to_string(),
            },
        );

        let collector = ArpCollector::new(&crate::config::Config::default(), runner);
        let result = collector.collect().await;
        assert!(result.is_err());
    }
}
