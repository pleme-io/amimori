//! mDNS/DNS-SD discovery — passive service enumeration via multicast.
//!
//! Listens on 224.0.0.251:5353 for Bonjour/Avahi announcements. Zero
//! active probing — devices advertise themselves. Discovers:
//!   - Device hostnames (FQDN)
//!   - Service types (_http._tcp, _airplay._tcp, _printer._tcp, etc.)
//!   - IP addresses (from A/AAAA records in mDNS responses)
//!   - TXT record metadata (firmware, model, capabilities)
//!
//! Produces fingerprints:
//!   mdns.hostname     — mDNS hostname (high confidence, device-advertised)
//!   mdns.service.N    — Nth service type discovered
//!   mdns.txt.{key}    — TXT record key-value pairs
//!   mdns.model        — device model (from TXT "md" or "model" key)
//!
//! Safety level: 0 (passive) — only listens, never sends probes.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use mdns_sd::{ServiceDaemon, ServiceEvent};

use crate::collector::{Collector, CollectorOutput};
use crate::collector::banner::BannerResult;
use crate::config::Config;
use crate::model::{Fingerprint, FingerprintSource};
use crate::state::StateEngine;

/// How long to listen for mDNS announcements per collection cycle.
const LISTEN_DURATION: Duration = Duration::from_secs(10);

/// Common service types to browse. The meta-query `_services._dns-sd._udp.local.`
/// discovers all types, but browsing specific types directly is faster for
/// initial population.
const BROWSE_TYPES: &[&str] = &[
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_printer._tcp.local.",
    "_ipp._tcp.local.",
    "_smb._tcp.local.",
    "_ssh._tcp.local.",
    "_googlecast._tcp.local.",
    "_hap._tcp.local.",        // HomeKit
    "_companion-link._tcp.local.", // Apple device pairing
    "_sleep-proxy._udp.local.",
];

pub struct MdnsCollector {
    interval: Duration,
    max_failures: u32,
    engine: Arc<StateEngine>,
}

impl MdnsCollector {
    pub fn new(config: &Config, engine: Arc<StateEngine>) -> Self {
        Self {
            interval: Duration::from_secs(config.collectors.wifi.interval * 2),
            max_failures: 5,
            engine,
        }
    }
}

#[async_trait::async_trait]
impl Collector for MdnsCollector {
    fn name(&self) -> &str {
        "mdns"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn max_failures(&self) -> u32 {
        self.max_failures
    }

    async fn collect(&self) -> anyhow::Result<CollectorOutput> {
        let engine = self.engine.clone();

        // mDNS daemon uses a background thread — run collection in spawn_blocking
        let results = tokio::task::spawn_blocking(move || {
            collect_mdns(&engine)
        })
        .await??;

        Ok(CollectorOutput::Banners(results))
    }
}

/// Run mDNS discovery for LISTEN_DURATION, collecting resolved services.
fn collect_mdns(engine: &StateEngine) -> anyhow::Result<Vec<BannerResult>> {
    let mdns = ServiceDaemon::new()
        .map_err(|e| anyhow::anyhow!("failed to create mDNS daemon: {e}"))?;

    // Browse common service types
    let mut receivers = Vec::new();
    for svc_type in BROWSE_TYPES {
        match mdns.browse(svc_type) {
            Ok(rx) => receivers.push((svc_type, rx)),
            Err(e) => {
                tracing::debug!(service = svc_type, error = %e, "mDNS browse failed");
            }
        }
    }

    if receivers.is_empty() {
        mdns.shutdown().ok();
        return Ok(Vec::new());
    }

    // Collect events for LISTEN_DURATION
    let deadline = std::time::Instant::now() + LISTEN_DURATION;
    let mut discovered: HashMap<String, DiscoveredDevice> = HashMap::new();

    while std::time::Instant::now() < deadline {
        for (_svc_type, rx) in &receivers {
            // Non-blocking poll with short timeout
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(ServiceEvent::ServiceResolved(info)) => {
                    let hostname = info.get_hostname().trim_end_matches('.').to_string();
                    let addresses: Vec<String> = info.get_addresses()
                        .iter()
                        .map(|a| a.to_string())
                        .collect();
                    let service_type = info.get_fullname().split('.').take(2).collect::<Vec<_>>().join(".");

                    // Try to find which host this is by IP
                    let mac = addresses.iter().find_map(|ip| {
                        engine.state.ip_to_mac.get(&ip.parse().ok()?).map(|r| r.clone())
                    });

                    let device = discovered
                        .entry(hostname.clone())
                        .or_insert_with(|| DiscoveredDevice {
                            mac,
                            hostname: hostname.clone(),
                            addresses,
                            services: Vec::new(),
                            txt_records: HashMap::new(),
                        });

                    if !device.services.contains(&service_type) {
                        device.services.push(service_type);
                    }

                    // Extract TXT records
                    for prop in info.get_properties().iter() {
                        let key = prop.key().to_string();
                        let val = prop.val_str().to_string();
                        device.txt_records.insert(key, val);
                    }
                }
                Ok(_) => {} // SearchStarted, ServiceFound (unresolved), etc.
                Err(_) => {} // timeout or channel closed
            }
        }
    }

    mdns.shutdown().ok();

    // Convert discoveries to BannerResults with fingerprints
    let now = Utc::now();
    let results: Vec<BannerResult> = discovered
        .into_values()
        .filter_map(|device| {
            let mac = device.mac?; // only enrich hosts we already know about
            let ip = device.addresses.first()?.clone();

            let mut fingerprints = Vec::new();

            // Hostname (high confidence — device-advertised)
            if !device.hostname.is_empty() {
                fingerprints.push(Fingerprint {
                    source: FingerprintSource::Mdns,
                    category: "net".into(),
                    key: "hostname".into(),
                    value: device.hostname.clone(),
                    confidence: 0.95,
                    observed_at: now,
                });
            }

            // Service types
            for (i, svc) in device.services.iter().enumerate() {
                fingerprints.push(Fingerprint {
                    source: FingerprintSource::Mdns,
                    category: "mdns".into(),
                    key: format!("service.{i}"),
                    value: svc.clone(),
                    confidence: 1.0,
                    observed_at: now,
                });
            }

            // Device model (from TXT md/model key)
            if let Some(model) = device.txt_records.get("md")
                .or_else(|| device.txt_records.get("model"))
            {
                fingerprints.push(Fingerprint {
                    source: FingerprintSource::Mdns,
                    category: "hw".into(),
                    key: "model".into(),
                    value: model.clone(),
                    confidence: 0.95,
                    observed_at: now,
                });
            }

            // Firmware version (from TXT fw/fv key)
            if let Some(fw) = device.txt_records.get("fw")
                .or_else(|| device.txt_records.get("fv"))
            {
                fingerprints.push(Fingerprint {
                    source: FingerprintSource::Mdns,
                    category: "sw".into(),
                    key: "firmware".into(),
                    value: fw.clone(),
                    confidence: 0.9,
                    observed_at: now,
                });
            }

            // Interesting TXT keys as raw fingerprints
            for (key, val) in &device.txt_records {
                if !val.is_empty() && key != "md" && key != "model" && key != "fw" && key != "fv" {
                    fingerprints.push(Fingerprint {
                        source: FingerprintSource::Mdns,
                        category: "mdns".into(),
                        key: format!("txt.{key}"),
                        value: val.clone(),
                        confidence: 0.8,
                        observed_at: now,
                    });
                }
            }

            if fingerprints.is_empty() {
                return None;
            }

            Some(BannerResult {
                mac,
                ip,
                port: 5353,
                protocol: "mdns".into(),
                banner: String::new(),
                fingerprints,
            })
        })
        .collect();

    tracing::debug!(
        devices = results.len(),
        "mDNS discovery complete"
    );

    Ok(results)
}

struct DiscoveredDevice {
    mac: Option<String>,
    hostname: String,
    addresses: Vec<String>,
    services: Vec<String>,
    txt_records: HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browse_types_are_valid_mdns() {
        for svc in BROWSE_TYPES {
            assert!(svc.ends_with(".local."), "{svc} must end with .local.");
            assert!(svc.starts_with('_'), "{svc} must start with _");
        }
    }

    #[test]
    fn browse_types_include_common_services() {
        let types: Vec<&&str> = BROWSE_TYPES.iter().collect();
        assert!(types.iter().any(|t| t.contains("http")));
        assert!(types.iter().any(|t| t.contains("airplay")));
        assert!(types.iter().any(|t| t.contains("ssh")));
        assert!(types.iter().any(|t| t.contains("printer")));
    }
}
