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

// ── Host Classification (roadmap items 3.2, 3.3) ──────────────────────────

/// Classify a host as physical, VM, container, or cloud based on MAC prefix,
/// open ports, and reverse DNS patterns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostClass {
    Physical,
    Vm(VmPlatform),
    Container(ContainerPlatform),
    Cloud(CloudProvider),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmPlatform {
    VMware,
    HyperV,
    VirtualBox,
    KvmQemu,
    Xen,
    Parallels,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerPlatform {
    Docker,
    Kubernetes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudProvider {
    Aws,
    Gcp,
    Azure,
    DigitalOcean,
}

/// VM MAC prefix → platform mapping.
const VM_MAC_PREFIXES: &[(&str, VmPlatform)] = &[
    ("00:0c:29", VmPlatform::VMware),
    ("00:50:56", VmPlatform::VMware),
    ("00:15:5d", VmPlatform::HyperV),
    ("08:00:27", VmPlatform::VirtualBox),
    ("52:54:00", VmPlatform::KvmQemu),
    ("00:16:3e", VmPlatform::Xen),
    ("00:1c:42", VmPlatform::Parallels),
];

/// Container MAC prefix.
const CONTAINER_MAC_PREFIXES: &[(&str, ContainerPlatform)] = &[
    ("02:42", ContainerPlatform::Docker),
];

/// Cloud provider MAC prefixes.
const CLOUD_MAC_PREFIXES: &[(&str, CloudProvider)] = &[
    ("00:0d:3a", CloudProvider::Azure),
    ("00:17:fa", CloudProvider::Azure),
];

/// Classify a host based on its attributes.
pub fn classify_host(host: &HostInfo) -> HostClass {
    let mac_lower = host.mac.to_lowercase();

    // Check VM MAC prefixes
    for (prefix, platform) in VM_MAC_PREFIXES {
        if mac_lower.starts_with(prefix) {
            return HostClass::Vm(platform.clone());
        }
    }

    // Check container MAC prefixes
    for (prefix, platform) in CONTAINER_MAC_PREFIXES {
        if mac_lower.starts_with(prefix) {
            return HostClass::Container(platform.clone());
        }
    }

    // Check cloud MAC prefixes
    for (prefix, provider) in CLOUD_MAC_PREFIXES {
        if mac_lower.starts_with(prefix) {
            return HostClass::Cloud(provider.clone());
        }
    }

    // Check port-based classification
    let ports: Vec<u16> = host.services.iter().map(|s| s.port).collect();
    if ports.contains(&2375) || ports.contains(&2376) {
        return HostClass::Container(ContainerPlatform::Docker);
    }
    if ports.contains(&6443) || ports.contains(&10250) {
        return HostClass::Container(ContainerPlatform::Kubernetes);
    }

    // Check reverse DNS patterns for cloud
    if let Some(ref hostname) = host.hostname {
        let h = hostname.to_lowercase();
        if h.contains("amazonaws.com") || h.contains("ec2") {
            return HostClass::Cloud(CloudProvider::Aws);
        }
        if h.contains("googleusercontent.com") || h.contains("gcp") {
            return HostClass::Cloud(CloudProvider::Gcp);
        }
        if h.contains("azure") || h.contains("cloudapp") {
            return HostClass::Cloud(CloudProvider::Azure);
        }
    }

    // Check fingerprints for cloud/DNS patterns
    for fp in &host.fingerprints {
        if fp.key == "dns_hostname" {
            let v = fp.value.to_lowercase();
            if v.contains("amazonaws.com") {
                return HostClass::Cloud(CloudProvider::Aws);
            }
            if v.contains("googleusercontent.com") {
                return HostClass::Cloud(CloudProvider::Gcp);
            }
        }
    }

    HostClass::Physical
}

/// Derive classification fingerprints for a host.
pub fn derive_classification(host: &HostInfo) -> Vec<Fingerprint> {
    let class = classify_host(host);
    let now = Utc::now();

    let (category, value) = match &class {
        HostClass::Physical => return Vec::new(), // no fingerprint for physical
        HostClass::Vm(p) => ("hw", format!("vm:{p:?}").to_lowercase()),
        HostClass::Container(p) => ("sw", format!("container:{p:?}").to_lowercase()),
        HostClass::Cloud(p) => ("net", format!("cloud:{p:?}").to_lowercase()),
    };

    vec![Fingerprint {
        source: FingerprintSource::Arp, // derived from MAC/port data
        category: category.into(),
        key: "classification".into(),
        value,
        confidence: 0.8,
        observed_at: now,
    }]
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

    #[test]
    fn correlation_same_os_adds_score() {
        let a = make_host("aa:bb:cc:dd:ee:ff", "10.0.0.1", None);
        let b = make_host("00:11:22:33:44:55", "10.0.0.2", None);
        // Both have os_hint = "Linux" from make_host
        let score = correlation_score(&a, &b);
        assert!(score >= 0.15, "same OS should add 0.15, got {score}");
    }

    #[test]
    fn correlation_shared_ports() {
        let mut a = make_host("aa:bb:cc:dd:ee:ff", "10.0.0.1", None);
        let mut b = make_host("00:11:22:33:44:55", "10.0.0.2", None);
        b.os_hint = Some("Windows".into());
        b.vendor = "Other".into();

        // Give both hosts port 22 and 80
        for host in [&mut a, &mut b] {
            host.services = vec![
                ServiceInfo { port: 22, protocol: "tcp".into(), name: "ssh".into(),
                    version: String::new(), state: "open".into(), banner: String::new() },
                ServiceInfo { port: 80, protocol: "tcp".into(), name: "http".into(),
                    version: String::new(), state: "open".into(), banner: String::new() },
            ];
        }
        let score = correlation_score(&a, &b);
        // Full port overlap (Jaccard=1.0) → +0.1, different OS/hostname/IP = no other factors
        assert!(score >= 0.1, "shared ports should contribute, got {score}");
    }

    #[test]
    fn correlation_empty_services_no_port_score() {
        let a = make_host("aa:bb:cc:dd:ee:ff", "10.0.0.1", None);
        let mut b = make_host("00:11:22:33:44:55", "10.0.0.2", None);
        b.os_hint = Some("Windows".into());
        b.vendor = "Other".into();
        // a has no services, b has no services → no port contribution
        let score = correlation_score(&a, &b);
        assert!(score < 0.1, "empty services should contribute nothing, got {score}");
    }

    #[test]
    fn correlation_partial_port_overlap() {
        let mut a = make_host("aa:bb:cc:dd:ee:ff", "10.0.0.1", None);
        let mut b = make_host("00:11:22:33:44:55", "10.0.0.2", None);
        b.os_hint = Some("Windows".into());
        b.vendor = "Other".into();

        a.services = vec![
            ServiceInfo { port: 22, protocol: "tcp".into(), name: "ssh".into(),
                version: String::new(), state: "open".into(), banner: String::new() },
            ServiceInfo { port: 80, protocol: "tcp".into(), name: "http".into(),
                version: String::new(), state: "open".into(), banner: String::new() },
        ];
        b.services = vec![
            ServiceInfo { port: 22, protocol: "tcp".into(), name: "ssh".into(),
                version: String::new(), state: "open".into(), banner: String::new() },
            ServiceInfo { port: 443, protocol: "tcp".into(), name: "https".into(),
                version: String::new(), state: "open".into(), banner: String::new() },
        ];
        // Jaccard = 1 intersection / 3 union = 0.33 → 0.1 * 0.33 = 0.033
        let score = correlation_score(&a, &b);
        assert!(score > 0.0 && score < 0.15, "partial overlap score should be small, got {score}");
    }

    // ── Classification tests ──────────────────────────────────────────

    #[test]
    fn classify_vmware() {
        let host = make_host("00:0c:29:aa:bb:cc", "10.0.0.1", None);
        assert_eq!(classify_host(&host), HostClass::Vm(VmPlatform::VMware));
    }

    #[test]
    fn classify_docker() {
        let host = make_host("02:42:ac:11:00:02", "172.17.0.2", None);
        assert_eq!(classify_host(&host), HostClass::Container(ContainerPlatform::Docker));
    }

    #[test]
    fn classify_hyperv() {
        let host = make_host("00:15:5d:aa:bb:cc", "10.0.0.1", None);
        assert_eq!(classify_host(&host), HostClass::Vm(VmPlatform::HyperV));
    }

    #[test]
    fn classify_azure_mac() {
        let host = make_host("00:0d:3a:aa:bb:cc", "10.0.0.1", None);
        assert_eq!(classify_host(&host), HostClass::Cloud(CloudProvider::Azure));
    }

    #[test]
    fn classify_aws_hostname() {
        let host = make_host("aa:bb:cc:dd:ee:ff", "10.0.0.1", Some("ec2-1-2-3-4.compute-1.amazonaws.com"));
        assert_eq!(classify_host(&host), HostClass::Cloud(CloudProvider::Aws));
    }

    #[test]
    fn classify_kubernetes_ports() {
        let mut host = make_host("aa:bb:cc:dd:ee:ff", "10.0.0.1", None);
        host.services.push(ServiceInfo {
            port: 6443,
            protocol: "tcp".into(),
            name: "kube-api".into(),
            version: String::new(),
            state: "open".into(),
            banner: String::new(),
        });
        assert_eq!(classify_host(&host), HostClass::Container(ContainerPlatform::Kubernetes));
    }

    #[test]
    fn classify_physical() {
        let host = make_host("aa:bb:cc:dd:ee:ff", "10.0.0.1", None);
        assert_eq!(classify_host(&host), HostClass::Physical);
    }

    #[test]
    fn derive_classification_vm() {
        let host = make_host("00:50:56:aa:bb:cc", "10.0.0.1", None);
        let fps = derive_classification(&host);
        assert!(!fps.is_empty());
        assert!(fps[0].value.contains("vmware"));
    }

    #[test]
    fn derive_classification_physical_empty() {
        let host = make_host("aa:bb:cc:dd:ee:ff", "10.0.0.1", None);
        assert!(derive_classification(&host).is_empty());
    }
}
