//! WiFi network scanner using CoreWLAN (macOS only).

use std::time::Duration;

use objc2_core_wlan::{CWChannelBand, CWInterface, CWNetwork, CWSecurity, CWWiFiClient};

use crate::collector::{Collector, CollectorOutput};
use crate::config::Config;
use crate::model::WifiInfo;

pub struct WifiCollector {
    interval: Duration,
    max_failures: u32,
}

impl WifiCollector {
    pub fn new(config: &Config) -> Self {
        Self {
            interval: Duration::from_secs(config.collectors.wifi.interval),
            max_failures: config.collectors.wifi.max_failures,
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
        let networks = tokio::task::spawn_blocking(scan_wifi).await??;
        tracing::debug!(count = networks.len(), "wifi scan complete");
        Ok(CollectorOutput::Wifi(networks))
    }
}

fn scan_wifi() -> anyhow::Result<Vec<WifiInfo>> {
    let client = unsafe { CWWiFiClient::sharedWiFiClient() };
    let Some(iface) = (unsafe { client.interface() }) else {
        return Ok(Vec::new());
    };

    let iface_name = unsafe { iface.interfaceName() }
        .map(|s| s.to_string())
        .unwrap_or_else(|| "en0".to_string());

    let networks = match unsafe { iface.scanForNetworksWithName_error(None) } {
        Ok(nets) => nets,
        Err(e) => {
            anyhow::bail!("CoreWLAN scan failed: {e}");
        }
    };

    let mut results = Vec::new();
    for network in &*networks {
        results.push(extract_network_info(&network, &iface_name));
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

fn extract_network_info(network: &CWNetwork, iface_name: &str) -> WifiInfo {
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

/// Probe `supportsSecurity()` from most to least secure.
fn detect_security(network: &CWNetwork) -> String {
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

fn format_iface_security(sec: CWSecurity) -> String {
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
