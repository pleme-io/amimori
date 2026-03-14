//! WiFi network scanner using CoreWLAN (macOS only).
//!
//! Uses `objc2-core-wlan` for safe Objective-C interop.

use std::time::Duration;

use objc2_core_wlan::{CWChannelBand, CWInterface, CWNetwork, CWSecurity, CWWiFiClient};

use crate::collector::{Collector, CollectorOutput};
use crate::config::Config;
use crate::model::WifiInfo;

pub struct WifiCollector {
    interval: Duration,
}

impl WifiCollector {
    pub fn new(config: &Config) -> Self {
        Self {
            interval: Duration::from_secs(config.wifi_interval),
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

    async fn collect(&self) -> anyhow::Result<CollectorOutput> {
        // CoreWLAN must be called from a thread with an active run loop.
        let networks = tokio::task::spawn_blocking(scan_wifi).await??;
        tracing::debug!("wifi: found {} networks", networks.len());
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

    // Scan for available networks
    let networks = unsafe { iface.scanForNetworksWithName_error(None) };

    let networks = match networks {
        Ok(nets) => nets,
        Err(e) => {
            tracing::warn!("wifi scan failed: {e}");
            return Ok(Vec::new());
        }
    };

    let mut results = Vec::new();

    for network in &*networks {
        let info = extract_network_info(&network, &iface_name);
        results.push(info);
    }

    // Also capture the currently connected network info
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

    let channel_obj = unsafe { network.wlanChannel() };
    let (channel, band) = channel_obj
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

    // CWNetwork doesn't expose securityType() directly.
    // Use supportsSecurity() to detect the security type.
    let security = detect_network_security(network);

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

/// Detect security type by probing supportsSecurity() for each type.
/// Returns the highest-grade security supported.
fn detect_network_security(network: &CWNetwork) -> String {
    // Check from most secure to least secure
    let checks = [
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

    for (security_type, name) in &checks {
        if unsafe { network.supportsSecurity(*security_type) } {
            return (*name).to_string();
        }
    }

    "Open".to_string()
}

fn connected_network_info(iface: &CWInterface, iface_name: &str) -> Option<WifiInfo> {
    let ssid = unsafe { iface.ssid() }?.to_string();
    let bssid = unsafe { iface.bssid() }?.to_string();
    let rssi = unsafe { iface.rssiValue() } as i32;
    let noise = unsafe { iface.noiseMeasurement() } as i32;

    let channel_obj = unsafe { iface.wlanChannel() };
    let (channel, band) = channel_obj
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

    let security = format_interface_security(unsafe { iface.security() });

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

fn format_interface_security(security: CWSecurity) -> String {
    match security {
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
