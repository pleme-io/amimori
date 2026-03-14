//! UPnP/SSDP discovery — find smart TVs, IoT devices, gaming consoles.
//!
//! Sends M-SEARCH to 239.255.255.250:1900 and listens for responses.
//! Devices respond with their type, location URL, and USN. The location
//! URL points to an XML device description with manufacturer, model,
//! serial, firmware, and service list.
//!
//! Finds devices invisible to port scanning: Chromecast, Sonos, Hue
//! bridges, smart TVs, gaming consoles, NAS devices.
//!
//! Safety level: 2 (Discovery) — sends M-SEARCH multicast.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;

use crate::collector::{Collector, CollectorOutput};
use crate::collector::banner::BannerResult;
use crate::config::Config;
use crate::model::{Fingerprint, FingerprintSource};
use crate::state::StateEngine;

pub struct SsdpCollector {
    interval: Duration,
    max_failures: u32,
    engine: Arc<StateEngine>,
}

impl SsdpCollector {
    pub fn new(_config: &Config, engine: Arc<StateEngine>) -> Self {
        Self {
            interval: Duration::from_secs(60),
            max_failures: 5,
            engine,
        }
    }
}

#[async_trait::async_trait]
impl Collector for SsdpCollector {
    fn name(&self) -> &str {
        "ssdp"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn max_failures(&self) -> u32 {
        self.max_failures
    }

    async fn collect(&self) -> anyhow::Result<CollectorOutput> {
        let now = Utc::now();
        let mut results = Vec::new();

        // Search for all UPnP devices via SSDP M-SEARCH
        let search_target = ssdp_client::SearchTarget::All;
        let responses = ssdp_client::search(
            &search_target,
            Duration::from_secs(5),
            3,
            None, // bind address
        )
        .await;

        match responses {
            Ok(mut stream) => {
                use futures::StreamExt;
                while let Some(response) = stream.next().await {
                    if let Ok(resp) = response {
                        let location = resp.location().to_string();
                        let usn = resp.usn().to_string();
                        // Extract IP from location URL
                        let ip = url::Url::parse(&location)
                            .ok()
                            .and_then(|u| u.host_str().map(String::from))
                            .unwrap_or_default();

                        // Try to find this host in our state
                        let mac = ip.parse::<std::net::IpAddr>().ok().and_then(|addr| {
                            self.engine.state.ip_to_mac.get(&addr).map(|r| r.clone())
                        });

                        let Some(mac) = mac else { continue };

                        let mut fingerprints = vec![
                            Fingerprint {
                                source: FingerprintSource::Mdns, // UPnP source
                                category: "upnp".into(),
                                key: "usn".into(),
                                value: usn,
                                confidence: 1.0,
                                observed_at: now,
                            },
                            Fingerprint {
                                source: FingerprintSource::Mdns,
                                category: "upnp".into(),
                                key: "location".into(),
                                value: location.clone(),
                                confidence: 1.0,
                                observed_at: now,
                            },
                        ];

                        // Try to fetch device description XML
                        if let Ok(desc) = fetch_device_description(&location).await {
                            fingerprints.extend(desc);
                        }

                        results.push(BannerResult {
                            mac,
                            ip,
                            port: 1900,
                            protocol: "ssdp".into(),
                            banner: String::new(),
                            fingerprints,
                        });
                    }
                }
            }
            Err(e) => {
                tracing::debug!(error = %e, "SSDP search failed");
            }
        }

        tracing::debug!(devices = results.len(), "SSDP discovery complete");
        Ok(CollectorOutput::Banners(results))
    }
}

/// Fetch and parse the UPnP device description XML.
async fn fetch_device_description(location: &str) -> anyhow::Result<Vec<Fingerprint>> {
    let now = Utc::now();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()?;

    let text = client.get(location).send().await?.text().await?;
    let mut fps = Vec::new();

    // Simple XML extraction — avoid heavy XML parser deps
    if let Some(name) = extract_xml_value(&text, "friendlyName") {
        fps.push(Fingerprint {
            source: FingerprintSource::Mdns,
            category: "upnp".into(),
            key: "friendly_name".into(),
            value: name,
            confidence: 0.95,
            observed_at: now,
        });
    }
    if let Some(mfr) = extract_xml_value(&text, "manufacturer") {
        fps.push(Fingerprint {
            source: FingerprintSource::Mdns,
            category: "hw".into(),
            key: "manufacturer".into(),
            value: mfr,
            confidence: 0.95,
            observed_at: now,
        });
    }
    if let Some(model) = extract_xml_value(&text, "modelName") {
        fps.push(Fingerprint {
            source: FingerprintSource::Mdns,
            category: "hw".into(),
            key: "model".into(),
            value: model,
            confidence: 0.95,
            observed_at: now,
        });
    }
    if let Some(serial) = extract_xml_value(&text, "serialNumber") {
        fps.push(Fingerprint {
            source: FingerprintSource::Mdns,
            category: "hw".into(),
            key: "serial".into(),
            value: serial,
            confidence: 1.0,
            observed_at: now,
        });
    }
    if let Some(fw) = extract_xml_value(&text, "modelNumber") {
        fps.push(Fingerprint {
            source: FingerprintSource::Mdns,
            category: "sw".into(),
            key: "firmware".into(),
            value: fw,
            confidence: 0.8,
            observed_at: now,
        });
    }

    Ok(fps)
}

fn extract_xml_value(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    let value = xml[start..end].trim().to_string();
    if value.is_empty() { None } else { Some(value) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_xml_value_basic() {
        let xml = "<root><friendlyName>Living Room TV</friendlyName></root>";
        assert_eq!(
            extract_xml_value(xml, "friendlyName").as_deref(),
            Some("Living Room TV")
        );
    }

    #[test]
    fn extract_xml_value_missing() {
        assert!(extract_xml_value("<root></root>", "friendlyName").is_none());
    }

    #[test]
    fn extract_xml_value_empty() {
        let xml = "<root><friendlyName></friendlyName></root>";
        assert!(extract_xml_value(xml, "friendlyName").is_none());
    }
}
