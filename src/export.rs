//! Asset inventory export — structured output in standard formats.
//!
//! Exports the current network state as CSV, JSON, or Nmap-compatible XML.
//! Used by the MCP `network_export` tool and CLI `export` subcommand.

use crate::model::HostInfo;

/// Export hosts as CSV.
pub fn to_csv(hosts: &[HostInfo]) -> String {
    let mut out = String::with_capacity(hosts.len() * 200);
    out.push_str("mac,vendor,hostname,ipv4,ipv6,os,interface,services,outlier_score,first_seen,last_seen\n");

    for h in hosts {
        let ipv4: Vec<String> = h.addresses.iter().filter(|a| a.is_ipv4()).map(|a| a.to_string()).collect();
        let ipv6: Vec<String> = h.addresses.iter().filter(|a| a.is_ipv6()).map(|a| a.to_string()).collect();
        let services: Vec<String> = h.services.iter().map(|s| format!("{}/{}", s.port, s.protocol)).collect();

        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{:.1},{},{}\n",
            escape_csv(&h.mac),
            escape_csv(&h.vendor),
            escape_csv(h.hostname.as_deref().unwrap_or("")),
            escape_csv(&ipv4.join(";")),
            escape_csv(&ipv6.join(";")),
            escape_csv(h.os_hint.as_deref().unwrap_or("")),
            escape_csv(&h.interface),
            escape_csv(&services.join(";")),
            h.outlier_score(),
            h.first_seen.to_rfc3339(),
            h.last_seen.to_rfc3339(),
        ));
    }
    out
}

/// Export hosts as JSON array.
pub fn to_json(hosts: &[HostInfo]) -> String {
    serde_json::to_string_pretty(hosts).unwrap_or_else(|_| "[]".into())
}

fn escape_csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_host() -> HostInfo {
        HostInfo {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            vendor: "Apple Inc".into(),
            addresses: vec!["10.0.0.1".parse().unwrap()],
            hostname: Some("macbook.local".into()),
            os_hint: Some("macOS".into()),
            services: vec![],
            fingerprints: vec![],
            interface: "en0".into(),
            network_id: String::new(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        }
    }

    #[test]
    fn csv_has_header() {
        let csv = to_csv(&[]);
        assert!(csv.starts_with("mac,vendor,hostname"));
    }

    #[test]
    fn csv_contains_host() {
        let csv = to_csv(&[make_host()]);
        assert!(csv.contains("aa:bb:cc:dd:ee:ff"));
        assert!(csv.contains("Apple Inc"));
        assert!(csv.contains("macbook.local"));
    }

    #[test]
    fn json_valid() {
        let json = to_json(&[make_host()]);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_array());
        assert_eq!(parsed.as_array().unwrap().len(), 1);
    }

    #[test]
    fn escape_csv_commas() {
        assert_eq!(escape_csv("a,b"), "\"a,b\"");
    }

    #[test]
    fn escape_csv_clean() {
        assert_eq!(escape_csv("hello"), "hello");
    }
}
