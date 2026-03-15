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
    /// Per-interface active network tracking.
    pub active_networks: DashMap<String, NetworkInfo>,
    pub sequence: AtomicU64,
}

impl NetworkState {
    pub fn new() -> Self {
        Self {
            interfaces: DashMap::new(),
            hosts: DashMap::new(),
            ip_to_mac: DashMap::new(),
            wifi_networks: DashMap::new(),
            active_networks: DashMap::new(),
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

// ── Structured fingerprints (ADR-012) ──────────────────────────────────────

/// Source of a fingerprint observation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum FingerprintSource {
    Arp,
    Nmap,
    Mdns,
    Tls,
    Banner,
    Dhcp,
    Passive,
    Manual,
}

/// Probe safety classification (ADR-013).
///
/// Every enrichment technique has a safety level. The daemon only runs
/// probes at or below `collectors.max_probe_level` (default: 2 = discovery).
/// This protects fragile IoT/OT devices from intrusive probing.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ProbeLevel {
    /// Level 0: No packets sent. ARP table read, mDNS listen, DHCP observe.
    Passive = 0,
    /// Level 1: TCP connect + read. Banner grab, TLS handshake.
    Safe = 1,
    /// Level 2: Active probing. nmap -sV, HTTP GET, SMB negotiate.
    Discovery = 2,
    /// Level 3: Aggressive. nmap -O, SNMP walk, script scanning.
    Intrusive = 3,
}

impl FingerprintSource {
    /// The minimum probe level required to produce this type of fingerprint.
    pub const fn probe_level(self) -> ProbeLevel {
        match self {
            Self::Arp | Self::Passive | Self::Dhcp | Self::Mdns => ProbeLevel::Passive,
            Self::Banner | Self::Tls => ProbeLevel::Safe,
            Self::Nmap => ProbeLevel::Discovery,
            Self::Manual => ProbeLevel::Passive,
        }
    }
}

impl fmt::Display for FingerprintSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Arp => f.write_str("arp"),
            Self::Nmap => f.write_str("nmap"),
            Self::Mdns => f.write_str("mdns"),
            Self::Tls => f.write_str("tls"),
            Self::Banner => f.write_str("banner"),
            Self::Dhcp => f.write_str("dhcp"),
            Self::Passive => f.write_str("passive"),
            Self::Manual => f.write_str("manual"),
        }
    }
}

/// A single observed attribute about a host, with provenance and confidence.
///
/// Inspired by runZero's `fp.<category>.<key>` schema. Multiple fingerprints
/// can exist for the same (category, key) from different sources — the state
/// engine merges them by highest confidence, ties broken by recency.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Fingerprint {
    pub source: FingerprintSource,
    /// Category: "os", "hw", "sw", "net", "tls", "svc"
    pub category: String,
    /// Dot-separated key within category: "os.name", "hw.vendor", "tls.cn"
    pub key: String,
    /// The observed value
    pub value: String,
    /// Confidence 0.0 (guess) to 1.0 (certain)
    pub confidence: f32,
    /// When this fingerprint was observed
    pub observed_at: DateTime<Utc>,
}

impl Fingerprint {
    /// Composite key for merging: "os.name", "hw.vendor", etc.
    pub fn full_key(&self) -> String {
        format!("{}.{}", self.category, self.key)
    }

    /// Returns true if `other` should replace `self` (higher confidence, or
    /// same confidence but more recent).
    pub fn dominated_by(&self, other: &Self) -> bool {
        other.confidence > self.confidence
            || (other.confidence == self.confidence && other.observed_at > self.observed_at)
    }
}

// ── Host status ────────────────────────────────────────────────────────────

/// Lifecycle status of a host in the network state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum HostStatus {
    /// Recently confirmed by ARP or other active observation.
    #[default]
    Active,
    /// Not seen recently — will be removed on next prune if still unseen.
    Stale,
    /// Restored from database (known from a previous session). Not yet confirmed.
    Historical,
}

impl fmt::Display for HostStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => f.write_str("active"),
            Self::Stale => f.write_str("stale"),
            Self::Historical => f.write_str("historical"),
        }
    }
}

// ── Host info ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HostInfo {
    pub mac: String,
    pub vendor: String,
    pub addresses: Vec<IpAddr>,
    pub hostname: Option<String>,
    pub os_hint: Option<String>,
    pub services: Vec<ServiceInfo>,
    /// Structured fingerprints — typed observations with provenance and confidence.
    /// Multiple entries per (category, key) from different sources are allowed;
    /// the state engine merges by highest confidence.
    #[serde(default)]
    pub fingerprints: Vec<Fingerprint>,
    pub interface: String,
    /// Identifies which logical network this host was seen on (gateway|subnet).
    pub network_id: String,
    /// Lifecycle status: Active, Stale, or Historical.
    #[serde(default)]
    pub status: HostStatus,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

impl HostInfo {
    /// Check whether this host was last seen before `cutoff`.
    pub fn is_stale(&self, cutoff: DateTime<Utc>) -> bool {
        self.last_seen < cutoff
    }

    /// Merge a fingerprint. Higher confidence replaces lower; ties broken by recency.
    /// Returns true if the fingerprint was new or replaced an existing one.
    pub fn merge_fingerprint(&mut self, fp: Fingerprint) -> bool {
        let full_key = fp.full_key();
        if let Some(existing) = self.fingerprints.iter_mut().find(|f| f.full_key() == full_key) {
            if existing.dominated_by(&fp) {
                *existing = fp;
                return true;
            }
            return false;
        }
        self.fingerprints.push(fp);
        true
    }

    /// Get the best fingerprint for a key, or None.
    pub fn fingerprint(&self, category: &str, key: &str) -> Option<&Fingerprint> {
        let full = format!("{category}.{key}");
        self.fingerprints.iter().find(|f| f.full_key() == full)
    }

    /// Compute an outlier score (0.0-5.0) based on how unusual this host is
    /// relative to network norms. Higher = more unusual = worth investigating.
    ///
    /// Factors:
    /// - Unknown vendor (no OUI match) → +1.0
    /// - High service count (>10 open ports) → +1.0
    /// - Locally-administered MAC (randomized) → +0.5
    /// - No hostname after multiple scans → +0.5
    /// - Has intrusive services (telnet, ftp, rsh) → +1.0
    /// - Recent first_seen (appeared < 1h ago) → +1.0
    pub fn outlier_score(&self) -> f32 {
        let mut score = 0.0f32;

        if self.vendor.is_empty() {
            score += 1.0;
        }

        if self.services.len() > 10 {
            score += 1.0;
        }

        // Locally-administered MAC: bit 1 of first octet set
        if let Some(first) = self.mac.split(':').next() {
            if let Ok(byte) = u8::from_str_radix(first, 16) {
                if byte & 0x02 != 0 {
                    score += 0.5;
                }
            }
        }

        if self.hostname.is_none() && self.last_seen - self.first_seen > chrono::Duration::minutes(10) {
            score += 0.5;
        }

        // Risky services
        const RISKY_SERVICES: &[&str] = &["telnet", "ftp", "rsh", "rlogin", "vnc", "rdp"];
        if self.services.iter().any(|s| RISKY_SERVICES.contains(&s.name.as_str())) {
            score += 1.0;
        }

        // Recently appeared
        if Utc::now() - self.first_seen < chrono::Duration::hours(1) {
            score += 1.0;
        }

        score.min(5.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServiceInfo {
    pub port: u16,
    pub protocol: String,
    pub name: String,
    pub version: String,
    pub state: String,
    /// Raw banner text (first 1024 bytes of service response)
    #[serde(default)]
    pub banner: String,
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

// ── Network identity (ADR-015) ─────────────────────────────────────────────

/// A known network the device has connected to.
///
/// Each network is identified by a composite fingerprint (gateway MAC + subnet
/// CIDR). When the device reconnects to a known network, the existing host tree
/// is restored from the database rather than starting from scratch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkInfo {
    /// Composite identity key: `{gateway_mac}|{subnet_cidr}` or
    /// `{gateway_ip}|{subnet_mask}` as fallback.
    pub id: String,
    pub ssid: String,
    pub gateway_mac: String,
    pub gateway_ip: String,
    pub subnet_cidr: String,
    pub subnet_mask: String,
    pub interface: String,
    pub times_connected: u32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

impl NetworkInfo {
    /// Build a network identity from interface info + gateway MAC.
    ///
    /// Prefers `gateway_mac|subnet_cidr` (hardware-bound, stable) over
    /// `gateway_ip|subnet_mask` (common across networks).
    pub fn from_interface(iface: &InterfaceInfo, gateway_mac: &str) -> Option<Self> {
        if !iface.is_up || (iface.gateway.is_empty() && iface.subnet.is_empty()) {
            return None;
        }

        let subnet_cidr = iface.cidr().unwrap_or_default();
        let id = if !gateway_mac.is_empty() && !subnet_cidr.is_empty() {
            format!("{gateway_mac}|{subnet_cidr}")
        } else {
            iface.network_id() // fallback: gateway_ip|subnet_mask
        };

        if id.is_empty() {
            return None;
        }

        let now = Utc::now();
        Some(Self {
            id,
            ssid: String::new(), // set later from WiFi scan
            gateway_mac: gateway_mac.to_string(),
            gateway_ip: iface.gateway.clone(),
            subnet_cidr,
            subnet_mask: iface.subnet.clone(),
            interface: iface.name.clone(),
            times_connected: 1,
            first_seen: now,
            last_seen: now,
        })
    }
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
            fingerprints: vec![],
            interface: "en0".into(),
            network_id: String::new(),
            status: HostStatus::default(),
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
            fingerprints: vec![],
            interface: "en0".into(),
            network_id: String::new(),
            status: HostStatus::default(),
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
            fingerprints: vec![],
            interface: "en0".into(),
            network_id: String::new(),
            status: HostStatus::default(),
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
            state: "open".into(), banner: String::new(),
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

    // ── Outlier scoring ────────────────────────────────────────────────

    fn make_host_for_outlier(vendor: &str, services: Vec<ServiceInfo>) -> HostInfo {
        HostInfo {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            vendor: vendor.into(),
            addresses: vec!["10.0.0.1".parse().unwrap()],
            hostname: Some("test".into()),
            os_hint: None,
            services,
            fingerprints: vec![],
            interface: "en0".into(),
            network_id: String::new(),
            status: HostStatus::default(),
            first_seen: Utc::now() - chrono::Duration::hours(24),
            last_seen: Utc::now(),
        }
    }

    #[test]
    fn outlier_score_normal_host() {
        let host = make_host_for_outlier("Apple Inc", vec![]);
        assert!(host.outlier_score() < 1.0);
    }

    #[test]
    fn outlier_score_no_vendor() {
        let host = make_host_for_outlier("", vec![]);
        assert!(host.outlier_score() >= 1.0);
    }

    #[test]
    fn outlier_score_risky_services() {
        let host = make_host_for_outlier("SomeVendor", vec![
            ServiceInfo {
                port: 23,
                protocol: "tcp".into(),
                name: "telnet".into(),
                version: String::new(),
                state: "open".into(),
                banner: String::new(),
            },
        ]);
        assert!(host.outlier_score() >= 1.0);
    }

    #[test]
    fn outlier_score_capped_at_5() {
        let mut host = make_host_for_outlier("", (0..15).map(|i| ServiceInfo {
            port: i,
            protocol: "tcp".into(),
            name: "telnet".into(),
            version: String::new(),
            state: "open".into(),
            banner: String::new(),
        }).collect());
        host.hostname = None;
        host.first_seen = Utc::now();
        host.mac = "02:00:00:00:00:01".into(); // locally administered
        assert!(host.outlier_score() <= 5.0);
    }

    // ── Fingerprint merging ──────────────────────────────────────────

    #[test]
    fn merge_fingerprint_new() {
        let mut host = make_host_for_outlier("Apple", vec![]);
        let fp = Fingerprint {
            source: FingerprintSource::Nmap,
            category: "os".into(),
            key: "name".into(),
            value: "macOS".into(),
            confidence: 0.7,
            observed_at: Utc::now(),
        };
        assert!(host.merge_fingerprint(fp));
        assert_eq!(host.fingerprints.len(), 1);
    }

    #[test]
    fn merge_fingerprint_higher_confidence_wins() {
        let mut host = make_host_for_outlier("Apple", vec![]);
        let low = Fingerprint {
            source: FingerprintSource::Arp,
            category: "os".into(),
            key: "name".into(),
            value: "Linux".into(),
            confidence: 0.3,
            observed_at: Utc::now(),
        };
        let high = Fingerprint {
            source: FingerprintSource::Nmap,
            category: "os".into(),
            key: "name".into(),
            value: "macOS".into(),
            confidence: 0.9,
            observed_at: Utc::now(),
        };
        host.merge_fingerprint(low);
        host.merge_fingerprint(high);
        assert_eq!(host.fingerprints.len(), 1);
        assert_eq!(host.fingerprints[0].value, "macOS");
    }

    #[test]
    fn merge_fingerprint_lower_confidence_rejected() {
        let mut host = make_host_for_outlier("Apple", vec![]);
        let high = Fingerprint {
            source: FingerprintSource::Nmap,
            category: "os".into(),
            key: "name".into(),
            value: "macOS".into(),
            confidence: 0.9,
            observed_at: Utc::now(),
        };
        let low = Fingerprint {
            source: FingerprintSource::Arp,
            category: "os".into(),
            key: "name".into(),
            value: "Linux".into(),
            confidence: 0.3,
            observed_at: Utc::now(),
        };
        host.merge_fingerprint(high);
        assert!(!host.merge_fingerprint(low));
        assert_eq!(host.fingerprints[0].value, "macOS");
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
