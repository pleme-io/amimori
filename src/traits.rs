//! Trait boundaries for testability.
//!
//! Every external dependency (system commands, database, vendor lookup)
//! is abstracted behind a trait so business logic can be unit tested
//! with mock implementations.

use std::collections::HashMap;

use crate::model::{HostInfo, InterfaceInfo, WifiInfo};

// ── Command execution ──────────────────────────────────────────────────────

/// Output from a system command.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Abstraction over system command execution.
#[async_trait::async_trait]
pub trait CommandRunner: Send + Sync {
    async fn run(&self, name: &str, args: &[&str]) -> anyhow::Result<CommandOutput>;
}

/// Real implementation using tokio::process.
pub struct SystemCommandRunner;

#[async_trait::async_trait]
impl CommandRunner for SystemCommandRunner {
    async fn run(&self, name: &str, args: &[&str]) -> anyhow::Result<CommandOutput> {
        let output = tokio::process::Command::new(name)
            .args(args)
            .output()
            .await?;

        Ok(CommandOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
}

// ── Vendor lookup ──────────────────────────────────────────────────────────

/// MAC address → vendor name lookup.
pub trait VendorLookup: Send + Sync {
    fn lookup(&self, mac: &str) -> String;
}

/// Real implementation using mac_oui crate.
pub struct OuiVendorLookup {
    db: Option<mac_oui::Oui>,
}

impl OuiVendorLookup {
    pub fn new() -> Self {
        let db = match mac_oui::Oui::default() {
            Ok(db) => Some(db),
            Err(e) => {
                tracing::warn!(error = %e, "OUI database unavailable, vendor lookups disabled");
                None
            }
        };
        Self { db }
    }
}

impl VendorLookup for OuiVendorLookup {
    fn lookup(&self, mac: &str) -> String {
        self.db
            .as_ref()
            .and_then(|db| db.lookup_by_mac(mac).ok().flatten())
            .map(|entry| entry.company_name.clone())
            .unwrap_or_default()
    }
}

// ── Persistent storage ─────────────────────────────────────────────────────

/// Abstraction over the persistence layer.
#[async_trait::async_trait]
pub trait StorageBackend: Send + Sync {
    async fn upsert_host(&self, host: &HostInfo) -> anyhow::Result<()>;
    async fn remove_host(&self, mac: &str) -> anyhow::Result<()>;
    async fn upsert_interface(&self, iface: &InterfaceInfo) -> anyhow::Result<()>;
    async fn upsert_wifi(&self, wifi: &WifiInfo) -> anyhow::Result<()>;
    async fn remove_wifi(&self, bssid: &str) -> anyhow::Result<()>;
    async fn load_all(&self) -> anyhow::Result<(Vec<InterfaceInfo>, Vec<HostInfo>, Vec<WifiInfo>)>;
}

// ── Gateway / DNS providers ────────────────────────────────────────────────

/// Provides default gateway per interface.
#[async_trait::async_trait]
pub trait GatewayProvider: Send + Sync {
    async fn get_gateways(&self) -> HashMap<String, String>;
}

/// Provides DNS servers per interface.
#[async_trait::async_trait]
pub trait DnsProvider: Send + Sync {
    async fn get_dns_servers(&self) -> HashMap<String, Vec<String>>;
}

// ── Test mocks ─────────────────────────────────────────────────────────────

#[cfg(test)]
pub mod mocks {
    use super::*;
    use std::sync::Mutex;

    /// Mock command runner that returns pre-configured outputs.
    pub struct MockCommandRunner {
        responses: Mutex<HashMap<String, CommandOutput>>,
    }

    impl MockCommandRunner {
        pub fn new() -> Self {
            Self {
                responses: Mutex::new(HashMap::new()),
            }
        }

        pub fn set_response(&self, command: &str, output: CommandOutput) {
            self.responses
                .lock()
                .unwrap()
                .insert(command.to_string(), output);
        }
    }

    #[async_trait::async_trait]
    impl CommandRunner for MockCommandRunner {
        async fn run(&self, name: &str, _args: &[&str]) -> anyhow::Result<CommandOutput> {
            let responses = self.responses.lock().unwrap();
            responses
                .get(name)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no mock response for {name}"))
        }
    }

    /// Mock vendor lookup with configurable responses.
    pub struct MockVendorLookup {
        vendors: HashMap<String, String>,
    }

    impl MockVendorLookup {
        pub fn new(vendors: Vec<(&str, &str)>) -> Self {
            Self {
                vendors: vendors
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            }
        }

        pub fn empty() -> Self {
            Self {
                vendors: HashMap::new(),
            }
        }
    }

    impl VendorLookup for MockVendorLookup {
        fn lookup(&self, mac: &str) -> String {
            self.vendors.get(mac).cloned().unwrap_or_default()
        }
    }

    /// In-memory storage backend for testing.
    pub struct InMemoryStorage {
        pub hosts: Mutex<HashMap<String, HostInfo>>,
        pub interfaces: Mutex<HashMap<String, InterfaceInfo>>,
        pub wifi: Mutex<HashMap<String, WifiInfo>>,
    }

    impl InMemoryStorage {
        pub fn new() -> Self {
            Self {
                hosts: Mutex::new(HashMap::new()),
                interfaces: Mutex::new(HashMap::new()),
                wifi: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl StorageBackend for InMemoryStorage {
        async fn upsert_host(&self, host: &HostInfo) -> anyhow::Result<()> {
            self.hosts
                .lock()
                .unwrap()
                .insert(host.mac.clone(), host.clone());
            Ok(())
        }

        async fn remove_host(&self, mac: &str) -> anyhow::Result<()> {
            self.hosts.lock().unwrap().remove(mac);
            Ok(())
        }

        async fn upsert_interface(&self, iface: &InterfaceInfo) -> anyhow::Result<()> {
            self.interfaces
                .lock()
                .unwrap()
                .insert(iface.name.clone(), iface.clone());
            Ok(())
        }

        async fn upsert_wifi(&self, wifi: &WifiInfo) -> anyhow::Result<()> {
            self.wifi
                .lock()
                .unwrap()
                .insert(wifi.bssid.clone(), wifi.clone());
            Ok(())
        }

        async fn remove_wifi(&self, bssid: &str) -> anyhow::Result<()> {
            self.wifi.lock().unwrap().remove(bssid);
            Ok(())
        }

        async fn load_all(
            &self,
        ) -> anyhow::Result<(Vec<InterfaceInfo>, Vec<HostInfo>, Vec<WifiInfo>)> {
            let interfaces = self.interfaces.lock().unwrap().values().cloned().collect();
            let hosts = self.hosts.lock().unwrap().values().cloned().collect();
            let wifi = self.wifi.lock().unwrap().values().cloned().collect();
            Ok((interfaces, hosts, wifi))
        }
    }

    /// Mock gateway provider.
    pub struct MockGatewayProvider(pub HashMap<String, String>);

    #[async_trait::async_trait]
    impl GatewayProvider for MockGatewayProvider {
        async fn get_gateways(&self) -> HashMap<String, String> {
            self.0.clone()
        }
    }

    /// Mock DNS provider.
    pub struct MockDnsProvider(pub HashMap<String, Vec<String>>);

    #[async_trait::async_trait]
    impl DnsProvider for MockDnsProvider {
        async fn get_dns_servers(&self) -> HashMap<String, Vec<String>> {
            self.0.clone()
        }
    }

    // ── Mock self-tests ────────────────────────────────────────────────

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::model::{HostInfo, InterfaceInfo, InterfaceKind, WifiInfo};
        use chrono::Utc;

        fn test_host(mac: &str) -> HostInfo {
            HostInfo {
                mac: mac.into(),
                vendor: String::new(),
                addresses: vec!["10.0.0.1".parse().unwrap()],
                hostname: None,
                os_hint: None,
                services: vec![],
                interface: "en0".into(),
                network_id: String::new(),
                first_seen: Utc::now(),
                last_seen: Utc::now(),
            }
        }

        fn test_iface(name: &str) -> InterfaceInfo {
            InterfaceInfo {
                name: name.into(),
                mac: String::new(),
                ipv4: vec![],
                ipv6: vec![],
                gateway: String::new(),
                subnet: String::new(),
                is_up: true,
                kind: InterfaceKind::Wifi,
                dns: vec![],
            }
        }

        fn test_wifi(bssid: &str) -> WifiInfo {
            WifiInfo {
                ssid: "test".into(),
                bssid: bssid.into(),
                rssi: -60,
                noise: -90,
                channel: 6,
                band: "2.4GHz".into(),
                security: "WPA2".into(),
                interface: "en0".into(),
            }
        }

        #[tokio::test]
        async fn mock_command_runner_returns_configured_response() {
            let runner = MockCommandRunner::new();
            runner.set_response(
                "test",
                CommandOutput {
                    success: true,
                    stdout: "hello".into(),
                    stderr: String::new(),
                },
            );
            let result = runner.run("test", &[]).await.unwrap();
            assert!(result.success);
            assert_eq!(result.stdout, "hello");
        }

        #[tokio::test]
        async fn mock_command_runner_errors_on_unknown() {
            let runner = MockCommandRunner::new();
            assert!(runner.run("unknown", &[]).await.is_err());
        }

        #[test]
        fn mock_vendor_lookup_returns_known() {
            let lookup = MockVendorLookup::new(vec![("aa:bb:cc:dd:ee:ff", "Apple")]);
            assert_eq!(lookup.lookup("aa:bb:cc:dd:ee:ff"), "Apple");
        }

        #[test]
        fn mock_vendor_lookup_returns_empty_for_unknown() {
            let lookup = MockVendorLookup::empty();
            assert_eq!(lookup.lookup("aa:bb:cc:dd:ee:ff"), "");
        }

        #[tokio::test]
        async fn in_memory_storage_host_crud() {
            let storage = InMemoryStorage::new();
            let host = test_host("aa:bb:cc:dd:ee:ff");

            storage.upsert_host(&host).await.unwrap();

            let (_, hosts, _) = storage.load_all().await.unwrap();
            assert_eq!(hosts.len(), 1);
            assert_eq!(hosts[0].mac, "aa:bb:cc:dd:ee:ff");

            storage.remove_host("aa:bb:cc:dd:ee:ff").await.unwrap();
            let (_, hosts, _) = storage.load_all().await.unwrap();
            assert!(hosts.is_empty());
        }

        #[tokio::test]
        async fn in_memory_storage_host_upsert_replaces() {
            let storage = InMemoryStorage::new();
            let mut host = test_host("aa:bb:cc:dd:ee:ff");
            storage.upsert_host(&host).await.unwrap();

            host.vendor = "Apple".into();
            storage.upsert_host(&host).await.unwrap();

            let (_, hosts, _) = storage.load_all().await.unwrap();
            assert_eq!(hosts.len(), 1);
            assert_eq!(hosts[0].vendor, "Apple");
        }

        #[tokio::test]
        async fn in_memory_storage_interface_crud() {
            let storage = InMemoryStorage::new();
            storage.upsert_interface(&test_iface("en0")).await.unwrap();

            let (ifaces, _, _) = storage.load_all().await.unwrap();
            assert_eq!(ifaces.len(), 1);
        }

        #[tokio::test]
        async fn in_memory_storage_wifi_crud() {
            let storage = InMemoryStorage::new();
            let w = test_wifi("aa:bb:cc:dd:ee:ff");

            storage.upsert_wifi(&w).await.unwrap();
            let (_, _, wifi) = storage.load_all().await.unwrap();
            assert_eq!(wifi.len(), 1);

            storage.remove_wifi("aa:bb:cc:dd:ee:ff").await.unwrap();
            let (_, _, wifi) = storage.load_all().await.unwrap();
            assert!(wifi.is_empty());
        }

        #[tokio::test]
        async fn in_memory_storage_load_all_empty() {
            let storage = InMemoryStorage::new();
            let (i, h, w) = storage.load_all().await.unwrap();
            assert!(i.is_empty());
            assert!(h.is_empty());
            assert!(w.is_empty());
        }
    }
}
