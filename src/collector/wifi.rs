//! WiFi network scanner using CoreWLAN (macOS only).
//!
//! All CoreWLAN FFI calls are isolated in the `platform` module at the
//! bottom of this file. Each unsafe call is wrapped in a safe function
//! with a SAFETY comment explaining why it's sound.
//!
//! The `WifiScanner` trait enables testing without CoreWLAN hardware.

use std::sync::Arc;
use std::time::Duration;

use crate::collector::{Collector, CollectorOutput};
use crate::config::Config;
use crate::model::WifiInfo;

// ── Trait for testability ────────────────────────────────────────────────

/// Abstraction over WiFi scanning. Real impl uses CoreWLAN, mock returns
/// pre-configured results.
pub trait WifiScanner: Send + Sync {
    fn scan(&self) -> anyhow::Result<Vec<WifiInfo>>;
}

// ── Collector ────────────────────────────────────────────────────────────

pub struct WifiCollector {
    interval: Duration,
    max_failures: u32,
    scanner: Arc<dyn WifiScanner>,
}

impl WifiCollector {
    pub fn new(config: &Config) -> Self {
        Self {
            interval: Duration::from_secs(config.collectors.wifi.interval),
            max_failures: config.collectors.wifi.max_failures,
            scanner: Arc::new(platform::CoreWlanScanner),
        }
    }

    #[cfg(test)]
    pub fn with_mock(scanner: Arc<dyn WifiScanner>) -> Self {
        Self {
            interval: Duration::from_secs(15),
            max_failures: 10,
            scanner,
        }
    }
}

#[async_trait::async_trait]
impl Collector for WifiCollector {
    fn name(&self) -> &str {
        "wifi"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn max_failures(&self) -> u32 {
        self.max_failures
    }

    async fn collect(&self) -> anyhow::Result<CollectorOutput> {
        let scanner = self.scanner.clone();
        let networks = tokio::task::spawn_blocking(move || scanner.scan()).await??;
        tracing::debug!(count = networks.len(), "wifi scan complete");
        Ok(CollectorOutput::Wifi(networks))
    }
}

// ── Security detection (pure, no unsafe) ────────────────────────────────

fn format_iface_security(sec: objc2_core_wlan::CWSecurity) -> String {
    use objc2_core_wlan::CWSecurity;
    match sec {
        CWSecurity::None => "Open",
        CWSecurity::WEP => "WEP",
        CWSecurity::WPAPersonal => "WPA Personal",
        CWSecurity::WPA2Personal => "WPA2 Personal",
        CWSecurity::WPA3Personal => "WPA3 Personal",
        CWSecurity::WPAEnterprise => "WPA Enterprise",
        CWSecurity::WPA2Enterprise => "WPA2 Enterprise",
        CWSecurity::WPA3Enterprise => "WPA3 Enterprise",
        _ => "Unknown",
    }
    .to_string()
}

// ── Platform layer: safe wrappers around CoreWLAN unsafe FFI ────────────

mod platform {
    use super::*;
    use objc2_core_wlan::{CWChannelBand, CWInterface, CWNetwork, CWSecurity, CWWiFiClient};

    pub struct CoreWlanScanner;

    impl WifiScanner for CoreWlanScanner {
        fn scan(&self) -> anyhow::Result<Vec<WifiInfo>> {
            let client = shared_wifi_client();
            let iface = default_interface(&client)?;
            let iface_name = interface_name(&iface);

            let mut results = Vec::new();

            // Scan for visible networks
            if let Ok(networks) = scan_networks(&iface) {
                for network in networks.iter() {
                    results.push(extract_network_info(&network, &iface_name));
                }
            }

            // Enrich with connected network's live RSSI/noise
            if let Some(connected) = connected_network_info(&iface, &iface_name) {
                if let Some(existing) = results.iter_mut().find(|w| w.bssid == connected.bssid) {
                    existing.rssi = connected.rssi;
                    existing.noise = connected.noise;
                } else {
                    results.push(connected);
                }
            }

            Ok(results)
        }
    }

    // Each function wraps exactly one unsafe call with a SAFETY comment.

    fn shared_wifi_client() -> objc2::rc::Retained<CWWiFiClient> {
        // SAFETY: CWWiFiClient::sharedWiFiClient() returns a valid singleton
        // that lives for the process lifetime. The Retained wrapper manages
        // the reference count. This never returns nil.
        unsafe { CWWiFiClient::sharedWiFiClient() }
    }

    fn default_interface(client: &CWWiFiClient) -> anyhow::Result<objc2::rc::Retained<CWInterface>> {
        // SAFETY: client.interface() returns the default WiFi interface or nil.
        // We convert nil to an error via the Option return.
        unsafe { client.interface() }
            .ok_or_else(|| anyhow::anyhow!("no WiFi interface found"))
    }

    fn interface_name(iface: &CWInterface) -> String {
        // SAFETY: interfaceName() returns an NSString or nil. We handle nil
        // by defaulting to "en0".
        unsafe { iface.interfaceName() }
            .map(|s| s.to_string())
            .unwrap_or_else(|| "en0".to_string())
    }

    fn scan_networks(iface: &CWInterface) -> anyhow::Result<objc2::rc::Retained<objc2_foundation::NSSet<CWNetwork>>> {
        // SAFETY: scanForNetworksWithName_error(None) performs a WiFi scan.
        // It's a read-only operation that returns an NSSet or an error.
        // The NSSet is autoreleased but Retained handles the retain.
        unsafe { iface.scanForNetworksWithName_error(None) }
            .map_err(|e| anyhow::anyhow!("CoreWLAN scan failed: {e}"))
    }

    fn extract_network_info(network: &CWNetwork, iface_name: &str) -> WifiInfo {
        // SAFETY: All CWNetwork accessors return Objective-C objects or
        // primitive values. NSString returns are handled via Option.
        // Numeric values (rssi, noise, channel) are always valid.
        let ssid = unsafe { network.ssid() }
            .map(|s| s.to_string())
            .unwrap_or_default();
        let bssid = unsafe { network.bssid() }
            .map(|s| s.to_string())
            .unwrap_or_default();
        let rssi = unsafe { network.rssiValue() } as i32;
        let noise = unsafe { network.noiseMeasurement() } as i32;

        let (channel, band) = unsafe { network.wlanChannel() }
            .map(|ch| {
                let num = unsafe { ch.channelNumber() } as u32;
                let band = match unsafe { ch.channelBand() } {
                    CWChannelBand::Band2GHz => "2.4GHz",
                    CWChannelBand::Band5GHz => "5GHz",
                    CWChannelBand::Band6GHz => "6GHz",
                    _ => "unknown",
                };
                (num, band.to_string())
            })
            .unwrap_or((0, String::new()));

        let security = detect_security(network);

        WifiInfo {
            ssid,
            bssid,
            rssi,
            noise,
            channel,
            band,
            security,
            interface: iface_name.to_string(),
        }
    }

    fn detect_security(network: &CWNetwork) -> String {
        // SAFETY: supportsSecurity() is a read-only query that returns bool.
        const CHECKS: &[(CWSecurity, &str)] = &[
            (CWSecurity::WPA3Enterprise, "WPA3 Enterprise"),
            (CWSecurity::WPA3Personal, "WPA3 Personal"),
            (CWSecurity::WPA3Transition, "WPA3 Transition"),
            (CWSecurity::Enterprise, "WPA2 Enterprise"),
            (CWSecurity::WPA2Enterprise, "WPA2 Enterprise"),
            (CWSecurity::WPA2Personal, "WPA2 Personal"),
            (CWSecurity::Personal, "WPA2 Personal"),
            (CWSecurity::WPAEnterpriseMixed, "WPA Enterprise Mixed"),
            (CWSecurity::WPAPersonalMixed, "WPA Personal Mixed"),
            (CWSecurity::WPAEnterprise, "WPA Enterprise"),
            (CWSecurity::WPAPersonal, "WPA Personal"),
            (CWSecurity::DynamicWEP, "Dynamic WEP"),
            (CWSecurity::WEP, "WEP"),
        ];

        for &(sec, name) in CHECKS {
            if unsafe { network.supportsSecurity(sec) } {
                return name.to_string();
            }
        }
        "Open".to_string()
    }

    fn connected_network_info(iface: &CWInterface, iface_name: &str) -> Option<WifiInfo> {
        // SAFETY: All CWInterface accessors are read-only queries.
        let ssid = unsafe { iface.ssid() }?.to_string();
        let bssid = unsafe { iface.bssid() }?.to_string();
        let rssi = unsafe { iface.rssiValue() } as i32;
        let noise = unsafe { iface.noiseMeasurement() } as i32;

        let (channel, band) = unsafe { iface.wlanChannel() }
            .map(|ch| {
                let num = unsafe { ch.channelNumber() } as u32;
                let band = match unsafe { ch.channelBand() } {
                    CWChannelBand::Band2GHz => "2.4GHz",
                    CWChannelBand::Band5GHz => "5GHz",
                    CWChannelBand::Band6GHz => "6GHz",
                    _ => "unknown",
                };
                (num, band.to_string())
            })
            .unwrap_or((0, String::new()));

        let security = format_iface_security(unsafe { iface.security() });

        Some(WifiInfo {
            ssid,
            bssid,
            rssi,
            noise,
            channel,
            band,
            security,
            interface: iface_name.to_string(),
        })
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    struct MockWifiScanner {
        networks: Vec<WifiInfo>,
    }

    impl WifiScanner for MockWifiScanner {
        fn scan(&self) -> anyhow::Result<Vec<WifiInfo>> {
            Ok(self.networks.clone())
        }
    }

    struct FailingWifiScanner;

    impl WifiScanner for FailingWifiScanner {
        fn scan(&self) -> anyhow::Result<Vec<WifiInfo>> {
            anyhow::bail!("no WiFi hardware")
        }
    }

    #[tokio::test]
    async fn wifi_collector_with_mock() {
        let scanner = Arc::new(MockWifiScanner {
            networks: vec![WifiInfo {
                ssid: "TestNet".into(),
                bssid: "10:22:33:44:55:66".into(),
                rssi: -55,
                noise: -90,
                channel: 36,
                band: "5GHz".into(),
                security: "WPA3".into(),
                interface: "en0".into(),
            }],
        });

        let collector = WifiCollector::with_mock(scanner);
        let result = collector.collect().await.unwrap();

        match result {
            CollectorOutput::Wifi(networks) => {
                assert_eq!(networks.len(), 1);
                assert_eq!(networks[0].ssid, "TestNet");
                assert_eq!(networks[0].rssi, -55);
            }
            _ => panic!("expected Wifi output"),
        }
    }

    #[tokio::test]
    async fn wifi_collector_empty_scan() {
        let scanner = Arc::new(MockWifiScanner { networks: vec![] });
        let collector = WifiCollector::with_mock(scanner);
        let result = collector.collect().await.unwrap();

        match result {
            CollectorOutput::Wifi(networks) => assert!(networks.is_empty()),
            _ => panic!("expected Wifi output"),
        }
    }

    #[tokio::test]
    async fn wifi_collector_handles_error() {
        let scanner = Arc::new(FailingWifiScanner);
        let collector = WifiCollector::with_mock(scanner);
        assert!(collector.collect().await.is_err());
    }

    #[test]
    fn wifi_collector_name() {
        let scanner = Arc::new(MockWifiScanner { networks: vec![] });
        let collector = WifiCollector::with_mock(scanner);
        assert_eq!(collector.name(), "wifi");
    }
}
