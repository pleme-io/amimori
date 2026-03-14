//! Enrichment pipeline — post-collection intelligence layer.
//!
//! Pure functions that derive higher-order insights from collected data:
//!   - CPE identification from service version strings
//!   - Multi-attribute host correlation (survive MAC randomization)
//!
//! These run in the state engine after collector output is applied,
//! not as separate collectors (they don't generate new data, they
//! refine existing data).

use crate::model::{Fingerprint, FingerprintSource, HostInfo};
use chrono::Utc;

// ── CPE Mapping (roadmap item 9) ──────────────────────────────────────────

/// Known service → CPE mappings. This is a small static table for common
/// services. A full CPE dictionary (NVD) integration would use a database.
///
/// Format: (service_name_prefix, version_prefix, cpe23_template)
/// The template uses {version} as a placeholder.
const CPE_MAPPINGS: &[(&str, &str, &str)] = &[
    ("openssh", "", "cpe:2.3:a:openbsd:openssh:{version}:*:*:*:*:*:*:*"),
    ("apache", "", "cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*"),
    ("nginx", "", "cpe:2.3:a:f5:nginx:{version}:*:*:*:*:*:*:*"),
    ("mysql", "", "cpe:2.3:a:oracle:mysql:{version}:*:*:*:*:*:*:*"),
    ("mariadb", "", "cpe:2.3:a:mariadb:mariadb:{version}:*:*:*:*:*:*:*"),
    ("postgresql", "", "cpe:2.3:a:postgresql:postgresql:{version}:*:*:*:*:*:*:*"),
    ("redis", "", "cpe:2.3:a:redis:redis:{version}:*:*:*:*:*:*:*"),
    ("postfix", "", "cpe:2.3:a:postfix:postfix:{version}:*:*:*:*:*:*:*"),
    ("exim", "", "cpe:2.3:a:exim:exim:{version}:*:*:*:*:*:*:*"),
    ("dovecot", "", "cpe:2.3:a:dovecot:dovecot:{version}:*:*:*:*:*:*:*"),
    ("proftpd", "", "cpe:2.3:a:proftpd:proftpd:{version}:*:*:*:*:*:*:*"),
    ("vsftpd", "", "cpe:2.3:a:vsftpd_project:vsftpd:{version}:*:*:*:*:*:*:*"),
    ("lighttpd", "", "cpe:2.3:a:lighttpd:lighttpd:{version}:*:*:*:*:*:*:*"),
    ("samba", "", "cpe:2.3:a:samba:samba:{version}:*:*:*:*:*:*:*"),
];

/// OS name → CPE mappings for common OS fingerprints.
const OS_CPE_MAPPINGS: &[(&str, &str)] = &[
    ("linux", "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"),
    ("macos", "cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*"),
    ("mac os x", "cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*"),
    ("windows", "cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"),
    ("freebsd", "cpe:2.3:o:freebsd:freebsd:*:*:*:*:*:*:*:*"),
    ("openbsd", "cpe:2.3:o:openbsd:openbsd:*:*:*:*:*:*:*:*"),
];

/// Derive CPE identifiers from a host's services and OS fingerprint.
/// Returns fingerprints to merge into the host.
pub fn derive_cpe(host: &HostInfo) -> Vec<Fingerprint> {
    let now = Utc::now();
    let mut fps = Vec::new();

    // Service CPEs
    for svc in &host.services {
        let name_lower = svc.name.to_lowercase();
        let version = extract_version(&svc.version);

        let version_lower = svc.version.to_lowercase();
        for &(prefix, _ver_prefix, template) in CPE_MAPPINGS {
            if (name_lower.starts_with(prefix) || version_lower.contains(prefix)) && !version.is_empty() {
                let cpe = template.replace("{version}", &version);
                fps.push(Fingerprint {
                    source: FingerprintSource::Nmap, // derived from nmap data
                    category: "svc".into(),
                    key: format!("cpe.{}.{}", svc.port, svc.protocol),
                    value: cpe,
                    confidence: 0.6, // heuristic mapping, not definitive
                    observed_at: now,
                });
                break;
            }
        }
    }

    // OS CPE
    if let Some(ref os) = host.os_hint {
        let os_lower = os.to_lowercase();
        for &(pattern, cpe) in OS_CPE_MAPPINGS {
            if os_lower.contains(pattern) {
                fps.push(Fingerprint {
                    source: FingerprintSource::Nmap,
                    category: "os".into(),
                    key: "cpe".into(),
                    value: cpe.to_string(),
                    confidence: 0.5,
                    observed_at: now,
                });
                break;
            }
        }
    }

    fps
}

/// Extract a version number from a version string.
/// "OpenSSH 9.6p1" → "9.6p1", "2.4.58 (Unix)" → "2.4.58"
fn extract_version(version_str: &str) -> String {
    // Find the first token that starts with a digit
    version_str
        .split_whitespace()
        .find(|t| t.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .map(|v| {
            // Strip trailing parens: "2.4.58" from "2.4.58 (Unix)"
            v.trim_end_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.')
                .to_string()
        })
        .unwrap_or_default()
}

// ── Multi-Attribute Correlation (roadmap item 10) ──────────────────────────

/// Compute a correlation score between two hosts (0.0-1.0).
/// Used to detect when the same physical device appears with a different MAC
/// (WiFi randomization, network transition, etc.).
///
/// Factors:
///   - Shared IPs → strong signal (0.4)
///   - Same hostname → strong signal (0.3)
///   - Same OS fingerprint → moderate signal (0.15)
///   - Same vendor → weak signal (0.05)
///   - Same open ports → moderate signal (0.1)
pub fn correlation_score(a: &HostInfo, b: &HostInfo) -> f32 {
    if a.mac == b.mac {
        return 1.0; // same host by definition
    }

    let mut score = 0.0f32;

    // Shared IP addresses
    let shared_ips = a.addresses.iter().any(|ip| b.addresses.contains(ip));
    if shared_ips {
        score += 0.4;
    }

    // Same hostname
    if let (Some(ha), Some(hb)) = (&a.hostname, &b.hostname) {
        if ha == hb {
            score += 0.3;
        }
    }

    // Same OS
    if let (Some(oa), Some(ob)) = (&a.os_hint, &b.os_hint) {
        if oa == ob {
            score += 0.15;
        }
    }

    // Same vendor
    if !a.vendor.is_empty() && a.vendor == b.vendor {
        score += 0.05;
    }

    // Shared open ports (Jaccard similarity of port sets)
    if !a.services.is_empty() && !b.services.is_empty() {
        let ports_a: std::collections::HashSet<u16> = a.services.iter().map(|s| s.port).collect();
        let ports_b: std::collections::HashSet<u16> = b.services.iter().map(|s| s.port).collect();
        let intersection = ports_a.intersection(&ports_b).count();
        let union = ports_a.union(&ports_b).count();
        if union > 0 {
            let jaccard = intersection as f32 / union as f32;
            score += 0.1 * jaccard;
        }
    }

    score.min(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ServiceInfo;

    fn make_host(mac: &str, ip: &str, hostname: Option<&str>) -> HostInfo {
        HostInfo {
            mac: mac.into(),
            vendor: "TestVendor".into(),
            addresses: vec![ip.parse().unwrap()],
            hostname: hostname.map(String::from),
            os_hint: Some("Linux".into()),
            services: vec![],
            fingerprints: vec![],
            interface: "en0".into(),
            network_id: String::new(),
            first_seen: Utc::now() - chrono::Duration::hours(24),
            last_seen: Utc::now(),
        }
    }

    // ── CPE mapping tests ─────────────────────────────────────────────

    #[test]
    fn extract_version_openssh() {
        assert_eq!(extract_version("OpenSSH 9.6p1"), "9.6p1");
    }

    #[test]
    fn extract_version_apache() {
        assert_eq!(extract_version("2.4.58 (Unix)"), "2.4.58");
    }

    #[test]
    fn extract_version_empty() {
        assert_eq!(extract_version(""), "");
    }

    #[test]
    fn extract_version_no_digits() {
        assert_eq!(extract_version("unknown"), "");
    }

    #[test]
    fn derive_cpe_openssh() {
        let mut host = make_host("aa:bb:cc:dd:ee:ff", "10.0.0.1", None);
        host.services.push(ServiceInfo {
            port: 22,
            protocol: "tcp".into(),
            name: "ssh".into(),
            version: "OpenSSH 9.6p1".into(),
            state: "open".into(),
            banner: String::new(),
        });
        let cpes = derive_cpe(&host);
        assert!(!cpes.is_empty());
        assert!(cpes[0].value.contains("openssh"));
        assert!(cpes[0].value.contains("9.6p1"));
    }

    #[test]
    fn derive_cpe_nginx() {
        let mut host = make_host("aa:bb:cc:dd:ee:ff", "10.0.0.1", None);
        host.services.push(ServiceInfo {
            port: 80,
            protocol: "tcp".into(),
            name: "nginx".into(),
            version: "1.25.3".into(),
            state: "open".into(),
            banner: String::new(),
        });
        let cpes = derive_cpe(&host);
        assert!(cpes.iter().any(|c| c.value.contains("nginx") && c.value.contains("1.25.3")));
    }

    #[test]
    fn derive_cpe_os_linux() {
        let host = make_host("aa:bb:cc:dd:ee:ff", "10.0.0.1", None);
        let cpes = derive_cpe(&host);
        assert!(cpes.iter().any(|c| c.key == "cpe" && c.value.contains("linux")));
    }

    #[test]
    fn derive_cpe_no_version_no_cpe() {
        let mut host = make_host("aa:bb:cc:dd:ee:ff", "10.0.0.1", None);
        host.services.push(ServiceInfo {
            port: 22,
            protocol: "tcp".into(),
            name: "ssh".into(),
            version: String::new(), // no version
            state: "open".into(),
            banner: String::new(),
        });
        host.os_hint = None;
        let cpes = derive_cpe(&host);
        assert!(cpes.is_empty()); // no CPE without version
    }

    // ── Correlation tests ─────────────────────────────────────────────

    #[test]
    fn correlation_same_mac_is_1() {
        let a = make_host("aa:bb:cc:dd:ee:ff", "10.0.0.1", Some("host1"));
        let b = make_host("aa:bb:cc:dd:ee:ff", "10.0.0.2", Some("host2"));
        assert_eq!(correlation_score(&a, &b), 1.0);
    }

    #[test]
    fn correlation_shared_ip_strong() {
        let a = make_host("aa:bb:cc:dd:ee:ff", "10.0.0.1", None);
        let b = make_host("00:11:22:33:44:55", "10.0.0.1", None);
        let score = correlation_score(&a, &b);
        assert!(score >= 0.4, "shared IP should give >= 0.4, got {score}");
    }

    #[test]
    fn correlation_same_hostname_strong() {
        let a = make_host("aa:bb:cc:dd:ee:ff", "10.0.0.1", Some("mydevice"));
        let b = make_host("00:11:22:33:44:55", "10.0.0.2", Some("mydevice"));
        let score = correlation_score(&a, &b);
        assert!(score >= 0.3, "same hostname should give >= 0.3, got {score}");
    }

    #[test]
    fn correlation_no_overlap_low() {
        let a = make_host("aa:bb:cc:dd:ee:ff", "10.0.0.1", Some("host1"));
        let mut b = make_host("00:11:22:33:44:55", "10.0.0.2", Some("host2"));
        b.os_hint = Some("Windows".into());
        b.vendor = "OtherVendor".into();
        let score = correlation_score(&a, &b);
        assert!(score < 0.2, "no overlap should be low, got {score}");
    }

    #[test]
    fn correlation_capped_at_1() {
        let a = make_host("aa:bb:cc:dd:ee:ff", "10.0.0.1", Some("same"));
        let b = make_host("00:11:22:33:44:55", "10.0.0.1", Some("same"));
        let score = correlation_score(&a, &b);
        assert!(score <= 1.0);
    }
}
