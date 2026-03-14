//! Banner grabber — connects to open ports and reads service banners.
//!
//! Runs after nmap discovers open ports. For each host with services that
//! have no banner yet, connects via TCP, reads the first 1024 bytes of
//! response (or sends a minimal probe for HTTP), and stores the banner
//! text in ServiceInfo.banner.
//!
//! This is separate from nmap -sV (which probes actively with its own
//! signature database). Banner grabbing is simpler: connect, read, store.
//!
//! Safety level: 1 (safe) — only TCP connect + read, no intrusive probing.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::collector::{Collector, CollectorOutput};
use crate::config::Config;
use crate::model::{Fingerprint, FingerprintSource, ServiceInfo};
use crate::state::StateEngine;

/// Maximum banner size to read (bytes).
const MAX_BANNER_LEN: usize = 1024;

/// Per-port connection timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Read timeout after connection.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Collected banner for a single service on a host.
#[derive(Debug, Clone)]
pub struct BannerResult {
    pub mac: String,
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub banner: String,
    /// Fingerprints extracted from the banner (e.g., TLS CN, HTTP Server header).
    pub fingerprints: Vec<Fingerprint>,
}

pub struct BannerCollector {
    interval: Duration,
    max_failures: u32,
    engine: Arc<StateEngine>,
}

impl BannerCollector {
    pub fn new(config: &Config, engine: Arc<StateEngine>) -> Self {
        Self {
            // Banner grabbing runs less frequently than nmap — only on hosts
            // that already have services but no banners.
            interval: Duration::from_secs(config.collectors.nmap.interval * 2),
            max_failures: 5,
            engine,
        }
    }
}

#[async_trait::async_trait]
impl Collector for BannerCollector {
    fn name(&self) -> &str {
        "banner"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn max_failures(&self) -> u32 {
        self.max_failures
    }

    async fn collect(&self) -> anyhow::Result<CollectorOutput> {
        // Find hosts with services that have no banner yet.
        let targets: Vec<(String, String, ServiceInfo)> = self
            .engine
            .state
            .hosts
            .iter()
            .flat_map(|entry| {
                let host = entry.value();
                let ip = host
                    .addresses
                    .iter()
                    .find(|a| a.is_ipv4())
                    .map(|a| a.to_string())
                    .unwrap_or_default();

                if ip.is_empty() {
                    return Vec::new();
                }

                host.services
                    .iter()
                    .filter(|s| s.banner.is_empty() && s.state == "open")
                    .map(|s| (host.mac.clone(), ip.clone(), s.clone()))
                    .collect::<Vec<_>>()
            })
            .collect();

        if targets.is_empty() {
            return Ok(CollectorOutput::Banners(Vec::new()));
        }

        tracing::debug!(targets = targets.len(), "banner grabbing");

        // Grab banners in parallel with bounded concurrency.
        let semaphore = Arc::new(tokio::sync::Semaphore::new(16));
        let mut handles = Vec::with_capacity(targets.len());

        for (mac, ip, svc) in targets {
            let sem = semaphore.clone();
            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.ok()?;
                grab_banner(&mac, &ip, &svc).await
            }));
        }

        let mut results = Vec::new();
        for handle in handles {
            if let Ok(Some(result)) = handle.await {
                results.push(result);
            }
        }

        tracing::debug!(banners = results.len(), "banner grab complete");
        Ok(CollectorOutput::Banners(results))
    }
}

/// Connect to a service and grab the banner.
async fn grab_banner(mac: &str, ip: &str, svc: &ServiceInfo) -> Option<BannerResult> {
    let addr: SocketAddr = format!("{ip}:{}", svc.port).parse().ok()?;

    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let banner = match svc.port {
        80 | 8080 | 8443 | 3000 | 5000 | 8000 | 8888 => {
            grab_http_banner(stream).await
        }
        _ => {
            grab_raw_banner(stream).await
        }
    };

    let banner = banner?;
    if banner.is_empty() {
        return None;
    }

    let mut fingerprints = Vec::new();

    // Extract HTTP Server header if present
    if let Some(server) = extract_http_server(&banner) {
        fingerprints.push(Fingerprint {
            source: FingerprintSource::Banner,
            category: "sw".into(),
            key: format!("http_server.{}", svc.port),
            value: server,
            confidence: 0.85,
            observed_at: chrono::Utc::now(),
        });
    }

    Some(BannerResult {
        mac: mac.to_string(),
        ip: ip.to_string(),
        port: svc.port,
        protocol: svc.protocol.clone(),
        banner,
        fingerprints,
    })
}

/// Read raw banner — many services (SSH, SMTP, FTP, MySQL) send a banner on connect.
async fn grab_raw_banner(mut stream: TcpStream) -> Option<String> {
    let mut buf = vec![0u8; MAX_BANNER_LEN];
    let n = tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n == 0 {
        return None;
    }

    Some(String::from_utf8_lossy(&buf[..n]).trim().to_string())
}

/// Send HTTP GET and read response headers.
async fn grab_http_banner(mut stream: TcpStream) -> Option<String> {
    let request = b"GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    stream.write_all(request).await.ok()?;

    let mut buf = vec![0u8; MAX_BANNER_LEN];
    let n = tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;

    if n == 0 {
        return None;
    }

    // Return just the headers (up to \r\n\r\n or first 1024 bytes)
    let response = String::from_utf8_lossy(&buf[..n]);
    if let Some(header_end) = response.find("\r\n\r\n") {
        Some(response[..header_end].to_string())
    } else {
        Some(response.trim().to_string())
    }
}

/// Extract the Server header value from HTTP response headers.
fn extract_http_server(banner: &str) -> Option<String> {
    for line in banner.lines() {
        if let Some(value) = line.strip_prefix("Server: ").or_else(|| line.strip_prefix("server: ")) {
            return Some(value.trim().to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_http_server_standard() {
        let banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nContent-Type: text/html";
        assert_eq!(
            extract_http_server(banner).as_deref(),
            Some("nginx/1.25.3")
        );
    }

    #[test]
    fn extract_http_server_lowercase() {
        let banner = "HTTP/1.1 200 OK\r\nserver: Apache/2.4.58";
        assert_eq!(
            extract_http_server(banner).as_deref(),
            Some("Apache/2.4.58")
        );
    }

    #[test]
    fn extract_http_server_missing() {
        let banner = "HTTP/1.1 200 OK\r\nContent-Type: text/html";
        assert!(extract_http_server(banner).is_none());
    }

    #[test]
    fn extract_http_server_empty_banner() {
        assert!(extract_http_server("").is_none());
    }
}
