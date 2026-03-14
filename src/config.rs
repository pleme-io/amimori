use serde::{Deserialize, Serialize};
use shikumi::{ConfigDiscovery, ConfigStore, ProviderChain};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_interfaces")]
    pub interfaces: Vec<String>,

    #[serde(default = "default_grpc_port")]
    pub grpc_port: u16,

    #[serde(default = "default_arp_interval")]
    pub arp_interval: u64,

    #[serde(default = "default_interface_interval")]
    pub interface_interval: u64,

    #[serde(default = "default_wifi_interval")]
    pub wifi_interval: u64,

    #[serde(default = "default_scan_interval")]
    pub scan_interval: u64,

    #[serde(default = "default_db_path")]
    pub db_path: String,

    #[serde(default = "default_event_buffer_size")]
    pub event_buffer_size: usize,

    #[serde(default)]
    pub nmap: NmapConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmapConfig {
    #[serde(default = "default_true")]
    pub enable: bool,

    #[serde(default = "default_nmap_bin")]
    pub bin: String,

    #[serde(default)]
    pub service_detection: bool,
}

impl Default for NmapConfig {
    fn default() -> Self {
        Self {
            enable: true,
            bin: default_nmap_bin(),
            service_detection: false,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interfaces: default_interfaces(),
            grpc_port: default_grpc_port(),
            arp_interval: default_arp_interval(),
            interface_interval: default_interface_interval(),
            wifi_interval: default_wifi_interval(),
            scan_interval: default_scan_interval(),
            db_path: default_db_path(),
            event_buffer_size: default_event_buffer_size(),
            nmap: NmapConfig::default(),
        }
    }
}

fn default_interfaces() -> Vec<String> {
    vec!["en0".to_string()]
}

fn default_grpc_port() -> u16 {
    50051
}

fn default_arp_interval() -> u64 {
    5
}

fn default_interface_interval() -> u64 {
    5
}

fn default_wifi_interval() -> u64 {
    15
}

fn default_scan_interval() -> u64 {
    60
}

fn default_db_path() -> String {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("amimori/state.db")
        .to_string_lossy()
        .to_string()
}

fn default_event_buffer_size() -> usize {
    10000
}

fn default_nmap_bin() -> String {
    "nmap".to_string()
}

const fn default_true() -> bool {
    true
}

impl Config {
    /// Load config from a specific path (used by daemon --config).
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let config = ProviderChain::new()
            .with_defaults(&Config::default())
            .with_file(path)
            .with_env("AMIMORI_")
            .extract::<Self>()?;
        Ok(config)
    }

    /// Discover and load config using shikumi's standard XDG discovery.
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

    /// Load config with optional hot-reload.
    #[allow(dead_code)]
    pub fn load_and_watch(
        path: &Path,
        on_reload: impl Fn(&Self) + Send + Sync + 'static,
    ) -> anyhow::Result<ConfigStore<Self>> {
        Ok(ConfigStore::<Self>::load_and_watch(
            path,
            "AMIMORI_",
            on_reload,
        )?)
    }

    /// Resolve db_path with shell expansion.
    pub fn resolved_db_path(&self) -> PathBuf {
        let expanded = shellexpand::tilde(&self.db_path);
        PathBuf::from(expanded.as_ref())
    }
}
