use std::net::IpAddr;
use std::sync::atomic::AtomicU64;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

/// Top-level in-memory network state.
pub struct NetworkState {
    pub interfaces: DashMap<String, InterfaceInfo>,
    pub hosts: DashMap<String, HostInfo>, // keyed by MAC
    pub wifi_networks: DashMap<String, WifiInfo>, // keyed by BSSID
    pub sequence: AtomicU64,
}

impl NetworkState {
    pub fn new() -> Self {
        Self {
            interfaces: DashMap::new(),
            hosts: DashMap::new(),
            wifi_networks: DashMap::new(),
            sequence: AtomicU64::new(0),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InterfaceKind {
    Wifi,
    Ethernet,
    Tunnel,
    Loopback,
    Other,
}

impl std::fmt::Display for InterfaceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wifi => write!(f, "wifi"),
            Self::Ethernet => write!(f, "ethernet"),
            Self::Tunnel => write!(f, "tunnel"),
            Self::Loopback => write!(f, "loopback"),
            Self::Other => write!(f, "other"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub mac: String,
    pub vendor: String,
    pub addresses: Vec<IpAddr>,
    pub hostname: Option<String>,
    pub os_hint: Option<String>,
    pub services: Vec<ServiceInfo>,
    pub interface: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServiceInfo {
    pub port: u16,
    pub protocol: String,
    pub name: String,
    pub version: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize)]
pub struct DeltaEvent {
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub change: Change,
}

#[derive(Debug, Clone, Serialize)]
pub enum Change {
    HostAdded(HostInfo),
    #[allow(dead_code)]
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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChangeType {
    Added,
    Removed,
    Updated,
}

impl std::fmt::Display for ChangeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Added => write!(f, "added"),
            Self::Removed => write!(f, "removed"),
            Self::Updated => write!(f, "updated"),
        }
    }
}

// ── Collector output types ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ArpEntry {
    pub ip: IpAddr,
    pub mac: String,
    pub interface: String,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NmapHost {
    pub ip: IpAddr,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub os_hint: Option<String>,
    pub services: Vec<ServiceInfo>,
}
