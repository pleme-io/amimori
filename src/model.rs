use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::AtomicU64;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

// ── In-memory state ────────────────────────────────────────────────────────

/// Top-level concurrent network state shared across collectors and servers.
///
/// All host insertions go through `insert_host()` which enforces MAC
/// validity (rejects broadcast, multicast, zero, and self MACs).
/// This is the single enforcement point — callers don't need to
/// pre-validate.
pub struct NetworkState {
    pub interfaces: DashMap<String, InterfaceInfo>,
    pub hosts: DashMap<String, HostInfo>,
    /// Reverse index: IP → MAC for O(1) host lookup by IP address.
    /// Maintained automatically by `insert_host()`.
    pub ip_to_mac: DashMap<IpAddr, String>,
    pub wifi_networks: DashMap<String, WifiInfo>,
    pub sequence: AtomicU64,
}

impl NetworkState {
    pub fn new() -> Self {
        Self {
            interfaces: DashMap::new(),
            hosts: DashMap::new(),
            ip_to_mac: DashMap::new(),
            wifi_networks: DashMap::new(),
            sequence: AtomicU64::new(0),
        }
    }

    /// Insert a host, enforcing MAC validity and self-MAC filtering.
    /// Maintains the IP→MAC reverse index automatically.
    /// Returns false if the host was rejected (non-host MAC or self MAC).
    pub fn insert_host(&self, mac: String, host: HostInfo) -> bool {
        if is_non_host_mac(&mac) || self.is_self_mac(&mac) {
            return false;
        }
        for addr in &host.addresses {
            self.ip_to_mac.insert(*addr, mac.clone());
        }
        self.hosts.insert(mac, host);
        true
    }

    /// Look up a host by MAC or IP address. IP lookup is O(1) via reverse index.
    pub fn get_host(&self, addr: &str) -> Option<HostInfo> {
        // Direct MAC lookup
        if let Some(host) = self.hosts.get(addr) {
            return Some(host.clone());
        }
        // IP reverse index lookup
        if let Ok(ip) = addr.parse::<IpAddr>() {
            if let Some(mac) = self.ip_to_mac.get(&ip) {
                return self.hosts.get(mac.value()).map(|h| h.clone());
            }
        }
        None
    }

    /// Check if a MAC belongs to one of our monitored interfaces.
    pub fn is_self_mac(&self, mac: &str) -> bool {
        self.interfaces.iter().any(|e| e.value().mac == mac)
    }
}

// ── Core domain types ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InterfaceInfo {
    pub name: String,
    pub mac: String,
    pub ipv4: Vec<IpAddr>,
    pub ipv6: Vec<IpAddr>,
    pub gateway: String,
    pub subnet: String,
    pub is_up: bool,
    pub kind: InterfaceKind,
    pub dns: Vec<String>,
}

impl InterfaceInfo {
    /// A fingerprint that identifies the logical network this interface is connected to.
    /// Changes when you switch WiFi networks, plug into a different Ethernet, etc.
    /// Format: `{gateway}|{subnet}` — two networks with the same gateway+subnet are the same network.
    pub fn network_id(&self) -> String {
        if !self.is_up || (self.gateway.is_empty() && self.subnet.is_empty()) {
            return String::new();
        }
        format!("{}|{}", self.gateway, self.subnet)
    }
}

impl InterfaceInfo {
    /// Derive CIDR subnet string from first IPv4 + netmask (e.g. "192.168.1.0/24").
    pub fn cidr(&self) -> Option<String> {
        let ip = self.ipv4.first()?;
        if self.subnet.is_empty() {
            return None;
        }
        let mask: IpAddr = self.subnet.parse().ok()?;
        let prefix_len = match mask {
            IpAddr::V4(v4) => u32::from(v4).count_ones(),
            IpAddr::V6(v6) => u128::from(v6).count_ones(),
        };
        // Apply mask to get network address
        if let (IpAddr::V4(ip4), IpAddr::V4(mask4)) = (ip, mask) {
            let net = u32::from(*ip4) & u32::from(mask4);
            let net_ip = std::net::Ipv4Addr::from(net);
            Some(format!("{net_ip}/{prefix_len}"))
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceKind {
    Wifi,
    Ethernet,
    Tunnel,
    Loopback,
    Other,
}

impl fmt::Display for InterfaceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wifi => f.write_str("wifi"),
            Self::Ethernet => f.write_str("ethernet"),
            Self::Tunnel => f.write_str("tunnel"),
            Self::Loopback => f.write_str("loopback"),
            Self::Other => f.write_str("other"),
        }
    }
}

impl InterfaceKind {
    pub fn from_name(name: &str) -> Self {
        match name {
            "lo0" | "lo" => Self::Loopback,
            n if n == "en0" => Self::Wifi,
            n if n.starts_with("en") => Self::Ethernet,
            n if n.starts_with("utun") || n.starts_with("tun") || n.starts_with("ipsec") => {
                Self::Tunnel
            }
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HostInfo {
    pub mac: String,
    pub vendor: String,
    pub addresses: Vec<IpAddr>,
    pub hostname: Option<String>,
    pub os_hint: Option<String>,
    pub services: Vec<ServiceInfo>,
    pub interface: String,
    /// Identifies which logical network this host was seen on (gateway|subnet).
    /// Empty for hosts discovered before network tracking was added.
    pub network_id: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

impl HostInfo {
    /// Check whether this host was last seen before `cutoff`.
    pub fn is_stale(&self, cutoff: DateTime<Utc>) -> bool {
        self.last_seen < cutoff
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServiceInfo {
    pub port: u16,
    pub protocol: String,
    pub name: String,
    pub version: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WifiInfo {
    pub ssid: String,
    pub bssid: String,
    pub rssi: i32,
    pub noise: i32,
    pub channel: u32,
    pub band: String,
    pub security: String,
    pub interface: String,
}

// ── Delta types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaEvent {
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub change: Change,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Change {
    HostAdded(HostInfo),
    HostRemoved { mac: String },
    HostUpdated(HostInfo),
    ServiceChanged {
        mac: String,
        service: ServiceInfo,
        change_type: ChangeType,
    },
    WifiAdded(WifiInfo),
    WifiRemoved { bssid: String },
    WifiUpdated(WifiInfo),
    InterfaceChanged(InterfaceInfo),
    /// Emitted when an interface transitions to a different network
    /// (different gateway/subnet). All hosts on the old network are cleared.
    NetworkChanged {
        interface: String,
        old_network_id: String,
        new_network_id: String,
        hosts_cleared: usize,
    },
}

impl fmt::Display for Change {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostAdded(h) => write!(f, "host_added({})", h.mac),
            Self::HostRemoved { mac } => write!(f, "host_removed({mac})"),
            Self::HostUpdated(h) => write!(f, "host_updated({})", h.mac),
            Self::ServiceChanged { mac, service, .. } => {
                write!(f, "service_changed({mac}:{})", service.port)
            }
            Self::WifiAdded(w) => write!(f, "wifi_added({})", w.ssid),
            Self::WifiRemoved { bssid } => write!(f, "wifi_removed({bssid})"),
            Self::WifiUpdated(w) => write!(f, "wifi_updated({})", w.ssid),
            Self::InterfaceChanged(i) => write!(f, "interface_changed({})", i.name),
            Self::NetworkChanged {
                interface,
                hosts_cleared,
                ..
            } => write!(f, "network_changed({interface}, cleared={hosts_cleared})"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ChangeType {
    Added,
    Removed,
    Updated,
}

impl fmt::Display for ChangeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Added => f.write_str("added"),
            Self::Removed => f.write_str("removed"),
            Self::Updated => f.write_str("updated"),
        }
    }
}

// ── Collector output types ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpEntry {
    pub ip: IpAddr,
    pub mac: String,
    pub interface: String,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmapHost {
    pub ip: IpAddr,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub os_hint: Option<String>,
    pub services: Vec<ServiceInfo>,
}

// ── MAC address utilities ──────────────────────────────────────────────────

/// Returns true if this MAC is broadcast, multicast, or otherwise
/// not a real unicast host that should appear in the host table.
///
/// Filters: broadcast (ff:ff:ff:ff:ff:ff), IPv4 multicast (01:00:5e:*),
/// IPv6 multicast (33:33:*), zero MAC, and locally-administered group addresses.
pub fn is_non_host_mac(mac: &str) -> bool {
    if mac == "ff:ff:ff:ff:ff:ff" || mac == "00:00:00:00:00:00" {
        return true;
    }
    // Multicast: first octet has the group bit (bit 0) set
    if let Some(first_octet) = mac.split(':').next() {
        if let Ok(byte) = u8::from_str_radix(first_octet, 16) {
            if byte & 0x01 != 0 {
                return true; // multicast/group address
            }
        }
    }
    false
}

/// Normalize a MAC/BSSID to lowercase colon-separated format with zero-padded octets.
///
/// Returns `None` if the input isn't a valid unicast MAC. Rejects:
/// - Wrong octet count, non-hex chars, empty octets
/// - Broadcast, multicast, and zero MACs
///
/// Examples: `"a:B:c:D:e:F"` → `Some("0a:0b:0c:0d:0e:0f")`
pub fn normalize_mac(mac: &str) -> Option<String> {
    let octets: Vec<&str> = mac.split(':').collect();
    if octets.len() != 6 {
        return None;
    }

    let mut out = String::with_capacity(17);
    for (i, octet) in octets.iter().enumerate() {
        if octet.is_empty() || octet.len() > 2 || !octet.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        if i > 0 {
            out.push(':');
        }
        if octet.len() == 1 {
            out.push('0');
        }
        for c in octet.chars() {
            out.push(c.to_ascii_lowercase());
        }
    }
    if is_non_host_mac(&out) {
        return None;
    }
    Some(out)
}

/// Validate that a string looks like a MAC address.
#[cfg(test)]
pub fn is_valid_mac(mac: &str) -> bool {
    normalize_mac(mac).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_mac_single_digit() {
        assert_eq!(
            normalize_mac("a:b:c:d:e:f").as_deref(),
            Some("0a:0b:0c:0d:0e:0f")
        );
    }

    #[test]
    fn normalize_mac_full() {
        assert_eq!(
            normalize_mac("AA:BB:CC:DD:EE:FF").as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
    }

    #[test]
    fn validate_mac_valid() {
        assert!(is_valid_mac("aa:bb:cc:dd:ee:ff"));
        assert!(is_valid_mac("a:b:c:d:e:f"));
    }

    #[test]
    fn validate_mac_incomplete() {
        assert!(!is_valid_mac("(incomplete)"));
    }

    #[test]
    fn validate_mac_too_short() {
        assert!(!is_valid_mac("short"));
    }

    #[test]
    fn validate_mac_wrong_octet_count() {
        assert!(!is_valid_mac("aa:bb:cc:dd:ee")); // 5 octets
        assert!(!is_valid_mac("aa:bb:cc:dd:ee:ff:00")); // 7 octets
    }

    #[test]
    fn validate_mac_empty_octet() {
        assert!(!is_valid_mac("aa::cc:dd:ee:ff"));
    }

    #[test]
    fn validate_mac_triple_digit_octet() {
        assert!(!is_valid_mac("aaa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn normalize_mac_rejects_non_hex() {
        assert!(normalize_mac("zz:yy:xx:ww:vv:uu").is_none());
    }

    #[test]
    fn normalize_mac_rejects_too_few_octets() {
        assert!(normalize_mac("aa:bb:cc:dd:ee").is_none());
    }

    #[test]
    fn normalize_mac_rejects_too_many_octets() {
        assert!(normalize_mac("aa:bb:cc:dd:ee:ff:00").is_none());
    }

    #[test]
    fn normalize_mac_rejects_empty_octet() {
        assert!(normalize_mac("aa::cc:dd:ee:ff").is_none());
    }

    #[test]
    fn normalize_mac_rejects_triple_digit_octet() {
        assert!(normalize_mac("aaa:bb:cc:dd:ee:ff").is_none());
    }

    #[test]
    fn normalize_mac_mixed_case() {
        assert_eq!(
            normalize_mac("aA:Bb:cC:Dd:eE:fF").as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
    }

    // ── Non-host MAC filtering (broadcast, multicast, zero) ───────────

    #[test]
    fn normalize_mac_rejects_broadcast() {
        assert!(normalize_mac("ff:ff:ff:ff:ff:ff").is_none());
    }

    #[test]
    fn normalize_mac_rejects_zero() {
        assert!(normalize_mac("00:00:00:00:00:00").is_none());
    }

    #[test]
    fn normalize_mac_rejects_ipv4_multicast() {
        // 01:00:5e:* — IPv4 multicast
        assert!(normalize_mac("01:00:5e:00:00:fb").is_none());
    }

    #[test]
    fn normalize_mac_rejects_ipv6_multicast() {
        // 33:33:* — IPv6 multicast (first octet 0x33 has group bit set)
        assert!(normalize_mac("33:33:00:00:00:01").is_none());
    }

    #[test]
    fn normalize_mac_accepts_unicast() {
        // Normal unicast MAC (first octet even = unicast)
        assert!(normalize_mac("84:69:93:7e:33:fe").is_some());
    }

    #[test]
    fn is_non_host_mac_broadcast() {
        assert!(is_non_host_mac("ff:ff:ff:ff:ff:ff"));
    }

    #[test]
    fn is_non_host_mac_multicast_group_bit() {
        // First octet 0x01 has bit 0 set = group/multicast
        assert!(is_non_host_mac("01:00:5e:00:00:fb"));
        // First octet 0x33 has bit 0 set
        assert!(is_non_host_mac("33:33:ff:00:00:01"));
    }

    #[test]
    fn is_non_host_mac_unicast() {
        // Even first octet = unicast
        assert!(!is_non_host_mac("84:69:93:7e:33:fe"));
        assert!(!is_non_host_mac("aa:bb:cc:dd:ee:ff")); // 0xaa = 1010_1010, bit 0 = 0
    }

    // ── InterfaceInfo::cidr() ──────────────────────────────────────────

    fn make_iface(ipv4: Vec<&str>, subnet: &str) -> InterfaceInfo {
        InterfaceInfo {
            name: "en0".into(),
            mac: String::new(),
            ipv4: ipv4.iter().filter_map(|s| s.parse().ok()).collect(),
            ipv6: vec![],
            gateway: String::new(),
            subnet: subnet.into(),
            is_up: true,
            kind: InterfaceKind::Wifi,
            dns: vec![],
        }
    }

    #[test]
    fn interface_cidr_class_c() {
        assert_eq!(
            make_iface(vec!["192.168.1.42"], "255.255.255.0")
                .cidr()
                .as_deref(),
            Some("192.168.1.0/24")
        );
    }

    #[test]
    fn interface_cidr_class_b() {
        assert_eq!(
            make_iface(vec!["172.16.5.42"], "255.255.0.0")
                .cidr()
                .as_deref(),
            Some("172.16.0.0/16")
        );
    }

    #[test]
    fn interface_cidr_no_ipv4() {
        assert!(make_iface(vec![], "255.255.255.0").cidr().is_none());
    }

    #[test]
    fn interface_cidr_empty_subnet() {
        assert!(make_iface(vec!["10.0.0.1"], "").cidr().is_none());
    }

    #[test]
    fn interface_cidr_malformed_subnet() {
        assert!(make_iface(vec!["10.0.0.1"], "not_a_mask").cidr().is_none());
    }

    #[test]
    fn interface_cidr_uses_first_ipv4() {
        let cidr = make_iface(vec!["10.0.0.5", "10.0.0.6"], "255.255.255.0")
            .cidr()
            .unwrap();
        assert_eq!(cidr, "10.0.0.0/24");
    }

    // ── InterfaceKind ──────────────────────────────────────────────────

    #[test]
    fn interface_kind_from_name() {
        assert_eq!(InterfaceKind::from_name("lo0"), InterfaceKind::Loopback);
        assert_eq!(InterfaceKind::from_name("lo"), InterfaceKind::Loopback);
        assert_eq!(InterfaceKind::from_name("en0"), InterfaceKind::Wifi);
        assert_eq!(InterfaceKind::from_name("en1"), InterfaceKind::Ethernet);
        assert_eq!(InterfaceKind::from_name("en4"), InterfaceKind::Ethernet);
        assert_eq!(InterfaceKind::from_name("utun3"), InterfaceKind::Tunnel);
        assert_eq!(InterfaceKind::from_name("tun0"), InterfaceKind::Tunnel);
        assert_eq!(InterfaceKind::from_name("ipsec0"), InterfaceKind::Tunnel);
        assert_eq!(InterfaceKind::from_name("bridge0"), InterfaceKind::Other);
    }

    // ── HostInfo::is_stale() ───────────────────────────────────────────

    #[test]
    fn host_is_stale_before_cutoff() {
        let host = HostInfo {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            vendor: String::new(),
            addresses: vec![],
            hostname: None,
            os_hint: None,
            services: vec![],
            interface: "en0".into(),
            network_id: String::new(),
            first_seen: Utc::now() - chrono::Duration::hours(48),
            last_seen: Utc::now() - chrono::Duration::hours(25),
        };
        let cutoff = Utc::now() - chrono::Duration::hours(24);
        assert!(host.is_stale(cutoff));
    }

    #[test]
    fn host_is_not_stale_after_cutoff() {
        let host = HostInfo {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            vendor: String::new(),
            addresses: vec![],
            hostname: None,
            os_hint: None,
            services: vec![],
            interface: "en0".into(),
            network_id: String::new(),
            first_seen: Utc::now() - chrono::Duration::hours(1),
            last_seen: Utc::now(),
        };
        let cutoff = Utc::now() - chrono::Duration::hours(24);
        assert!(!host.is_stale(cutoff));
    }

    // ── Change Display ─────────────────────────────────────────────────

    #[test]
    fn change_display_variants() {
        let host = HostInfo {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            vendor: String::new(),
            addresses: vec![],
            hostname: None,
            os_hint: None,
            services: vec![],
            interface: "en0".into(),
            network_id: String::new(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        };
        assert_eq!(
            Change::HostAdded(host.clone()).to_string(),
            "host_added(aa:bb:cc:dd:ee:ff)"
        );
        assert_eq!(
            Change::HostRemoved {
                mac: "aa:bb:cc:dd:ee:ff".into()
            }
            .to_string(),
            "host_removed(aa:bb:cc:dd:ee:ff)"
        );

        let svc = ServiceInfo {
            port: 22,
            protocol: "tcp".into(),
            name: "ssh".into(),
            version: String::new(),
            state: "open".into(),
        };
        assert_eq!(
            Change::ServiceChanged {
                mac: "aa:bb:cc:dd:ee:ff".into(),
                service: svc,
                change_type: ChangeType::Added,
            }
            .to_string(),
            "service_changed(aa:bb:cc:dd:ee:ff:22)"
        );
    }

    // ── Serde round-trips ──────────────────────────────────────────────

    #[test]
    fn arp_entry_serde_round_trip() {
        let entry = ArpEntry {
            ip: "10.0.0.1".parse().unwrap(),
            mac: "aa:bb:cc:dd:ee:ff".into(),
            interface: "en0".into(),
            hostname: Some("router".into()),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: ArpEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.mac, entry.mac);
        assert_eq!(back.hostname, entry.hostname);
    }

    #[test]
    fn delta_event_serde_round_trip() {
        let event = DeltaEvent {
            sequence: 42,
            timestamp: Utc::now(),
            change: Change::HostRemoved {
                mac: "aa:bb:cc:dd:ee:ff".into(),
            },
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: DeltaEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.sequence, 42);
    }

    #[test]
    fn change_type_display() {
        assert_eq!(ChangeType::Added.to_string(), "added");
        assert_eq!(ChangeType::Removed.to_string(), "removed");
        assert_eq!(ChangeType::Updated.to_string(), "updated");
    }
}
