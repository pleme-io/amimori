use serde::{Deserialize, Serialize};
use shikumi::{ConfigDiscovery, ProviderChain};
use std::path::{Path, PathBuf};

// ── Top-level config ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Network interfaces to monitor. Empty = auto-detect all non-loopback.
    #[serde(default)]
    pub interfaces: Vec<String>,

    /// gRPC server settings.
    #[serde(default)]
    pub grpc: GrpcConfig,

    /// Per-collector configuration.
    #[serde(default)]
    pub collectors: CollectorConfig,

    /// Storage and retention settings.
    #[serde(default)]
    pub storage: StorageConfig,

    /// Host/network filtering rules.
    #[serde(default)]
    pub filters: FilterConfig,

    /// Logging configuration.
    #[serde(default)]
    pub logging: LoggingConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interfaces: Vec::new(),
            grpc: GrpcConfig::default(),
            collectors: CollectorConfig::default(),
            storage: StorageConfig::default(),
            filters: FilterConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

// ── gRPC config ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcConfig {
    /// Bind address for the gRPC server.
    #[serde(default = "default_grpc_address")]
    pub address: String,

    /// Listen port for the gRPC server.
    #[serde(default = "default_grpc_port")]
    pub port: u16,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            address: default_grpc_address(),
            port: default_grpc_port(),
        }
    }
}

impl GrpcConfig {
    /// Full gRPC endpoint URL (e.g. `http://127.0.0.1:50051`).
    #[allow(dead_code)]
    pub fn endpoint(&self) -> String {
        format!("http://{}:{}", self.address, self.port)
    }

    pub fn socket_addr(&self) -> String {
        format!("{}:{}", self.address, self.port)
    }
}

// ── Collector config ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorConfig {
    #[serde(default)]
    pub arp: ArpCollectorConfig,

    #[serde(default)]
    pub interface: InterfaceCollectorConfig,

    #[serde(default)]
    pub wifi: WifiCollectorConfig,

    #[serde(default)]
    pub nmap: NmapCollectorConfig,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            arp: ArpCollectorConfig::default(),
            interface: InterfaceCollectorConfig::default(),
            wifi: WifiCollectorConfig::default(),
            nmap: NmapCollectorConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpCollectorConfig {
    #[serde(default = "default_true")]
    pub enable: bool,

    /// Fallback poll interval in seconds (reactive triggers supplement this).
    #[serde(default = "default_30")]
    pub interval: u64,

    /// Max consecutive failures before disabling.
    #[serde(default = "default_10")]
    pub max_failures: u32,

    /// Enable reactive triggering (run immediately on network changes).
    #[serde(default = "default_true")]
    pub reactive: bool,

    /// Cooldown after reactive trigger in seconds (debounce).
    #[serde(default = "default_2")]
    pub reactive_cooldown: u64,
}

impl Default for ArpCollectorConfig {
    fn default() -> Self {
        Self {
            enable: true,
            interval: 30,
            max_failures: 10,
            reactive: true,
            reactive_cooldown: 2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceCollectorConfig {
    #[serde(default = "default_true")]
    pub enable: bool,

    /// Fast poll interval for change detection (the root event source).
    #[serde(default = "default_2")]
    pub interval: u64,

    #[serde(default = "default_10")]
    pub max_failures: u32,
}

impl Default for InterfaceCollectorConfig {
    fn default() -> Self {
        Self {
            enable: true,
            interval: 2,
            max_failures: 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiCollectorConfig {
    #[serde(default = "default_true")]
    pub enable: bool,

    #[serde(default = "default_15")]
    pub interval: u64,

    #[serde(default = "default_10")]
    pub max_failures: u32,

    #[serde(default = "default_true")]
    pub reactive: bool,

    #[serde(default = "default_3")]
    pub reactive_cooldown: u64,
}

impl Default for WifiCollectorConfig {
    fn default() -> Self {
        Self {
            enable: true,
            interval: 15,
            max_failures: 10,
            reactive: true,
            reactive_cooldown: 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmapCollectorConfig {
    #[serde(default = "default_true")]
    pub enable: bool,

    /// Scan interval in seconds.
    #[serde(default = "default_60")]
    pub interval: u64,

    /// Path to nmap binary.
    #[serde(default = "default_nmap_bin")]
    pub bin: String,

    /// Command timeout in seconds (kills nmap after this).
    #[serde(default = "default_120")]
    pub timeout: u64,

    /// Enable service version detection (-sV). Slower but richer data.
    #[serde(default)]
    pub service_detection: bool,

    /// Subnets to scan. Empty = auto-derive from active interfaces.
    #[serde(default)]
    pub subnets: Vec<String>,

    /// Max consecutive failures before disabling.
    #[serde(default = "default_3_u32")]
    pub max_failures: u32,

    /// Enable reactive triggering (run immediately on network changes).
    #[serde(default = "default_true")]
    pub reactive: bool,

    /// Cooldown after reactive trigger in seconds (nmap is expensive).
    #[serde(default = "default_5")]
    pub reactive_cooldown: u64,
}

impl Default for NmapCollectorConfig {
    fn default() -> Self {
        Self {
            enable: true,
            interval: 60,
            bin: default_nmap_bin(),
            timeout: 120,
            service_detection: false,
            subnets: Vec::new(),
            max_failures: 3,
            reactive: true,
            reactive_cooldown: 5,
        }
    }
}

// ── Storage config ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Path to SQLite database. Supports ~ expansion.
    #[serde(default = "default_db_path")]
    pub db_path: String,

    /// In-memory event ring buffer capacity.
    #[serde(default = "default_event_buffer_size")]
    pub event_buffer_size: usize,

    #[serde(default)]
    pub retention: RetentionConfig,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            db_path: default_db_path(),
            event_buffer_size: default_event_buffer_size(),
            retention: RetentionConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionConfig {
    /// Remove hosts not seen for this many seconds. 0 = keep forever.
    #[serde(default = "default_host_ttl")]
    pub host_ttl: u64,

    /// How often to run the pruning sweep, in seconds.
    #[serde(default = "default_prune_interval")]
    pub prune_interval: u64,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            host_ttl: default_host_ttl(),
            prune_interval: default_prune_interval(),
        }
    }
}

// ── Filter config ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FilterConfig {
    /// MAC addresses to exclude from tracking.
    #[serde(default)]
    pub exclude_macs: Vec<String>,

    /// IP addresses/CIDRs to exclude from tracking.
    #[serde(default)]
    pub exclude_ips: Vec<String>,

    /// Interface names to ignore entirely.
    #[serde(default)]
    pub exclude_interfaces: Vec<String>,

    /// If non-empty, only track hosts from these vendors (case-insensitive substring).
    #[serde(default)]
    pub include_vendors: Vec<String>,
}

impl FilterConfig {
    /// Returns true if no filters are active (empty config = accept everything).
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.exclude_macs.is_empty()
            && self.exclude_ips.is_empty()
            && self.exclude_interfaces.is_empty()
            && self.include_vendors.is_empty()
    }

    pub fn should_exclude_mac(&self, mac: &str) -> bool {
        // MACs are already normalized to lowercase by normalize_mac()
        self.exclude_macs.iter().any(|m| m.eq_ignore_ascii_case(mac))
    }

    pub fn should_exclude_ip(&self, ip: &std::net::IpAddr) -> bool {
        if self.exclude_ips.is_empty() {
            return false;
        }
        let ip_str = ip.to_string();
        self.exclude_ips.iter().any(|e| *e == ip_str)
    }

    pub fn should_exclude_interface(&self, name: &str) -> bool {
        self.exclude_interfaces.iter().any(|e| e == name)
    }

    pub fn vendor_matches(&self, vendor: &str) -> bool {
        if self.include_vendors.is_empty() {
            return true;
        }
        self.include_vendors
            .iter()
            .any(|inc| vendor.to_lowercase().contains(&inc.to_lowercase()))
    }
}

// ── Logging config ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level: trace, debug, info, warn, error.
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Log format: "text" or "json".
    #[serde(default = "default_log_format")]
    pub format: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

// ── Default value functions ────────────────────────────────────────────────

fn default_grpc_address() -> String {
    "127.0.0.1".to_string()
}
fn default_grpc_port() -> u16 {
    50051
}
const fn default_true() -> bool {
    true
}
const fn default_2() -> u64 {
    2
}
const fn default_5() -> u64 {
    5
}
const fn default_30() -> u64 {
    30
}
const fn default_10() -> u32 {
    10
}
const fn default_3_u32() -> u32 {
    3
}
const fn default_3() -> u64 {
    3
}
const fn default_15() -> u64 {
    15
}
const fn default_60() -> u64 {
    60
}
const fn default_120() -> u64 {
    120
}
fn default_nmap_bin() -> String {
    "nmap".to_string()
}
fn default_db_path() -> String {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("amimori/state.db")
        .to_string_lossy()
        .to_string()
}
const fn default_event_buffer_size() -> usize {
    10_000
}
const fn default_host_ttl() -> u64 {
    86_400 // 24 hours
}
const fn default_prune_interval() -> u64 {
    300 // 5 minutes
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_log_format() -> String {
    "text".to_string()
}

// ── Config loading ─────────────────────────────────────────────────────────

impl Config {
    /// Load from a specific path (daemon --config).
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let config = ProviderChain::new()
            .with_defaults(&Self::default())
            .with_file(path)
            .with_env("AMIMORI_")
            .extract::<Self>()?;
        config.validate()?;
        Ok(config)
    }

    /// Discover via shikumi XDG paths, fall back to defaults.
    pub fn discover() -> anyhow::Result<Self> {
        match ConfigDiscovery::new("amimori")
            .env_override("AMIMORI_CONFIG")
            .discover()
        {
            Ok(p) => Self::load(&p),
            Err(_) => {
                tracing::info!("no config file found, using defaults");
                Ok(Self::default())
            }
        }
    }

    /// Resolve db_path with tilde expansion.
    pub fn resolved_db_path(&self) -> PathBuf {
        PathBuf::from(shellexpand::tilde(&self.storage.db_path).as_ref())
    }

    /// Validate config values.
    fn validate(&self) -> anyhow::Result<()> {
        if self.grpc.port == 0 {
            anyhow::bail!("grpc.port must be non-zero");
        }
        if self.collectors.arp.interval == 0 {
            anyhow::bail!("collectors.arp.interval must be > 0");
        }
        if self.collectors.interface.interval == 0 {
            anyhow::bail!("collectors.interface.interval must be > 0");
        }
        if self.collectors.wifi.interval == 0 {
            anyhow::bail!("collectors.wifi.interval must be > 0");
        }
        if self.collectors.nmap.interval == 0 {
            anyhow::bail!("collectors.nmap.interval must be > 0");
        }
        if self.storage.event_buffer_size == 0 {
            anyhow::bail!("storage.event_buffer_size must be > 0");
        }
        if self.collectors.nmap.timeout == 0 {
            anyhow::bail!("collectors.nmap.timeout must be > 0");
        }
        // Warn on odd but valid configs
        if self.storage.retention.host_ttl == 0 && self.storage.retention.prune_interval > 0 {
            tracing::debug!(
                "retention.host_ttl=0 means hosts kept forever; prune_interval has no effect"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Default config ─────────────────────────────────────────────────

    #[test]
    fn default_config_is_valid() {
        let cfg = Config::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn default_config_auto_detects_interfaces() {
        let cfg = Config::default();
        assert!(cfg.interfaces.is_empty(), "empty = auto-detect");
    }

    #[test]
    fn default_config_all_collectors_enabled() {
        let cfg = Config::default();
        assert!(cfg.collectors.arp.enable);
        assert!(cfg.collectors.interface.enable);
        assert!(cfg.collectors.wifi.enable);
        assert!(cfg.collectors.nmap.enable);
    }

    #[test]
    fn default_grpc_endpoint() {
        let cfg = Config::default();
        assert_eq!(cfg.grpc.socket_addr(), "127.0.0.1:50051");
    }

    #[test]
    fn default_retention_24h() {
        let cfg = Config::default();
        assert_eq!(cfg.storage.retention.host_ttl, 86_400);
    }

    // ── Validation ─────────────────────────────────────────────────────

    #[test]
    fn validation_rejects_zero_grpc_port() {
        let mut cfg = Config::default();
        cfg.grpc.port = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validation_rejects_zero_arp_interval() {
        let mut cfg = Config::default();
        cfg.collectors.arp.interval = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validation_rejects_zero_nmap_timeout() {
        let mut cfg = Config::default();
        cfg.collectors.nmap.timeout = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validation_rejects_zero_buffer_size() {
        let mut cfg = Config::default();
        cfg.storage.event_buffer_size = 0;
        assert!(cfg.validate().is_err());
    }

    // ── Filter logic ───────────────────────────────────────────────────

    #[test]
    fn empty_filters_accept_everything() {
        let f = FilterConfig::default();
        assert!(!f.should_exclude_mac("aa:bb:cc:dd:ee:ff"));
        assert!(!f.should_exclude_ip(&"10.0.0.1".parse().unwrap()));
        assert!(!f.should_exclude_interface("en0"));
        assert!(f.vendor_matches("Apple"));
        assert!(f.vendor_matches(""));
    }

    #[test]
    fn filter_excludes_mac_case_insensitive() {
        let f = FilterConfig {
            exclude_macs: vec!["AA:BB:CC:DD:EE:FF".to_string()],
            ..Default::default()
        };
        assert!(f.should_exclude_mac("aa:bb:cc:dd:ee:ff"));
        assert!(f.should_exclude_mac("AA:BB:CC:DD:EE:FF"));
        assert!(!f.should_exclude_mac("11:22:33:44:55:66"));
    }

    #[test]
    fn filter_excludes_ip() {
        let f = FilterConfig {
            exclude_ips: vec!["10.0.0.1".to_string()],
            ..Default::default()
        };
        assert!(f.should_exclude_ip(&"10.0.0.1".parse().unwrap()));
        assert!(!f.should_exclude_ip(&"10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn filter_excludes_interface() {
        let f = FilterConfig {
            exclude_interfaces: vec!["lo0".to_string()],
            ..Default::default()
        };
        assert!(f.should_exclude_interface("lo0"));
        assert!(!f.should_exclude_interface("en0"));
    }

    #[test]
    fn filter_vendor_whitelist() {
        let f = FilterConfig {
            include_vendors: vec!["Apple".to_string()],
            ..Default::default()
        };
        assert!(f.vendor_matches("Apple Inc"));
        assert!(f.vendor_matches("apple"));
        assert!(!f.vendor_matches("Samsung"));
        assert!(!f.vendor_matches(""));
    }

    #[test]
    fn filter_vendor_empty_whitelist_accepts_all() {
        let f = FilterConfig::default();
        assert!(f.vendor_matches("anything"));
        assert!(f.vendor_matches(""));
    }

    // ── Serde round-trip ───────────────────────────────────────────────

    #[test]
    fn config_serde_round_trip() {
        let cfg = Config::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let deserialized: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.grpc.port, cfg.grpc.port);
        assert_eq!(
            deserialized.collectors.arp.interval,
            cfg.collectors.arp.interval
        );
    }

    #[test]
    fn config_deserializes_from_minimal_json() {
        // Zero-config: empty JSON object should produce valid defaults
        let cfg: Config = serde_json::from_str("{}").unwrap();
        assert!(cfg.validate().is_ok());
        assert!(cfg.interfaces.is_empty());
        assert_eq!(cfg.grpc.port, 50051);
    }

    #[test]
    fn config_deserializes_partial_override() {
        let json = r#"{"grpc": {"port": 9090}}"#;
        let cfg: Config = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.grpc.port, 9090);
        // Everything else should be default
        assert_eq!(cfg.grpc.address, "127.0.0.1");
        assert!(cfg.collectors.arp.enable);
    }
}
