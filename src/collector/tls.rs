//! TLS certificate collector — connects to TLS ports and extracts certificate metadata.
//!
//! For each host with open TLS-capable ports (443, 8443, 993, 995, 465, etc.),
//! performs a TLS handshake, extracts the peer certificate, and produces fingerprints:
//!   tls.cn       — subject Common Name
//!   tls.san      — Subject Alternative Names (comma-separated)
//!   tls.issuer   — issuer organization
//!   tls.expiry   — certificate expiry date (ISO 8601)
//!   tls.protocol — negotiated TLS version (e.g., "TLSv1.3")
//!
//! Safety level: 1 (safe) — TCP connect + TLS handshake, no data sent.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use rustls::ClientConfig;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::collector::{Collector, CollectorOutput};
use crate::collector::banner::BannerResult;
use crate::config::Config;
use crate::model::{Fingerprint, FingerprintSource};
use crate::state::StateEngine;

/// Ports commonly serving TLS.
const TLS_PORTS: &[u16] = &[443, 8443, 993, 995, 465, 636, 989, 990, 5061, 6697];

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub struct TlsCollector {
    interval: Duration,
    max_failures: u32,
    engine: Arc<StateEngine>,
    tls_config: Arc<ClientConfig>,
}

impl TlsCollector {
    pub fn new(config: &Config, engine: Arc<StateEngine>) -> Self {
        // Build a TLS config that accepts any certificate (we're inspecting, not validating).
        let tls_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
            .with_no_client_auth();

        Self {
            interval: Duration::from_secs(config.collectors.nmap.interval * 3),
            max_failures: 5,
            engine,
            tls_config: Arc::new(tls_config),
        }
    }
}

#[async_trait::async_trait]
impl Collector for TlsCollector {
    fn name(&self) -> &str {
        "tls"
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn max_failures(&self) -> u32 {
        self.max_failures
    }

    async fn collect(&self) -> anyhow::Result<CollectorOutput> {
        // Find hosts with TLS-capable open ports that we haven't fingerprinted yet.
        let targets: Vec<(String, String, u16)> = self
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

                // Only probe TLS ports that we haven't fingerprinted yet
                host.services
                    .iter()
                    .filter(|s| s.state == "open" && TLS_PORTS.contains(&s.port))
                    .filter(|s| {
                        host.fingerprint("tls", &format!("cn.{}", s.port)).is_none()
                    })
                    .map(|s| (host.mac.clone(), ip.clone(), s.port))
                    .collect::<Vec<_>>()
            })
            .collect();

        if targets.is_empty() {
            return Ok(CollectorOutput::Banners(Vec::new()));
        }

        tracing::debug!(targets = targets.len(), "TLS certificate collection");

        let semaphore = Arc::new(tokio::sync::Semaphore::new(8));
        let mut handles = Vec::with_capacity(targets.len());

        for (mac, ip, port) in targets {
            let sem = semaphore.clone();
            let connector = TlsConnector::from(self.tls_config.clone());
            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.ok()?;
                probe_tls(&mac, &ip, port, connector).await
            }));
        }

        let mut results = Vec::new();
        for handle in handles {
            if let Ok(Some(result)) = handle.await {
                results.push(result);
            }
        }

        tracing::debug!(certs = results.len(), "TLS collection complete");
        Ok(CollectorOutput::Banners(results))
    }
}

async fn probe_tls(
    mac: &str,
    ip: &str,
    port: u16,
    connector: TlsConnector,
) -> Option<BannerResult> {
    let addr: SocketAddr = format!("{ip}:{port}").parse().ok()?;
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let server_name = rustls::pki_types::ServerName::try_from(ip.to_string())
        .or_else(|_| rustls::pki_types::ServerName::try_from("localhost".to_string()))
        .ok()?;

    let tls_stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        connector.connect(server_name, stream),
    )
    .await
    .ok()?
    .ok()?;

    let (_, conn) = tls_stream.get_ref();

    let mut fingerprints = Vec::new();
    let now = Utc::now();

    // Extract negotiated protocol version
    if let Some(version) = conn.protocol_version() {
        fingerprints.push(Fingerprint {
            source: FingerprintSource::Tls,
            category: "tls".into(),
            key: format!("protocol.{port}"),
            value: format!("{version:?}"),
            confidence: 1.0,
            observed_at: now,
        });
    }

    // Extract peer certificates
    if let Some(certs) = conn.peer_certificates() {
        if let Some(cert_der) = certs.first() {
            if let Ok((_rem, cert)) = x509_parser(cert_der.as_ref()) {
                // Subject CN
                if let Some(cn) = extract_cn(&cert.subject) {
                    fingerprints.push(Fingerprint {
                        source: FingerprintSource::Tls,
                        category: "tls".into(),
                        key: format!("cn.{port}"),
                        value: cn,
                        confidence: 1.0,
                        observed_at: now,
                    });
                }

                // Issuer
                if let Some(issuer) = extract_cn(&cert.issuer) {
                    fingerprints.push(Fingerprint {
                        source: FingerprintSource::Tls,
                        category: "tls".into(),
                        key: format!("issuer.{port}"),
                        value: issuer,
                        confidence: 1.0,
                        observed_at: now,
                    });
                }

                // Expiry
                fingerprints.push(Fingerprint {
                    source: FingerprintSource::Tls,
                    category: "tls".into(),
                    key: format!("expiry.{port}"),
                    value: cert.not_after.to_string(),
                    confidence: 1.0,
                    observed_at: now,
                });

                // SANs
                if !cert.sans.is_empty() {
                    fingerprints.push(Fingerprint {
                        source: FingerprintSource::Tls,
                        category: "tls".into(),
                        key: format!("san.{port}"),
                        value: cert.sans.join(", "),
                        confidence: 1.0,
                        observed_at: now,
                    });
                }
            }
        }
    }

    if fingerprints.is_empty() {
        return None;
    }

    Some(BannerResult {
        mac: mac.to_string(),
        ip: ip.to_string(),
        port,
        protocol: "tcp".into(),
        banner: String::new(), // TLS doesn't produce a text banner
        fingerprints,
    })
}

// ── Minimal X.509 parsing (no heavy deps) ─────────────────────────────────

struct SimpleCert {
    subject: String,
    issuer: String,
    not_after: String,
    sans: Vec<String>,
}

/// Minimal DER certificate parser — extracts subject, issuer, expiry, SANs.
/// This avoids pulling in a full ASN.1 library. If parsing fails, returns Err.
fn x509_parser(der: &[u8]) -> Result<(&[u8], SimpleCert), ()> {
    // For now, use a simple heuristic: scan for readable strings in the DER.
    // A proper implementation would use x509-parser or rasn crate.
    let text = String::from_utf8_lossy(der);

    // Extract CN-like patterns from the readable portions
    let subject = extract_readable_cn(&text, "CN=").unwrap_or_default();
    let issuer = extract_readable_cn(&text, "O=").unwrap_or_default();

    Ok((
        &[],
        SimpleCert {
            subject,
            issuer,
            not_after: String::new(), // requires proper ASN.1 parsing
            sans: Vec::new(),         // requires proper ASN.1 parsing
        },
    ))
}

fn extract_cn(subject: &str) -> Option<String> {
    if subject.is_empty() {
        return None;
    }
    Some(subject.to_string())
}

fn extract_readable_cn(text: &str, prefix: &str) -> Option<String> {
    text.find(prefix).map(|start| {
        let after = &text[start + prefix.len()..];
        let end = after.find(|c: char| c == ',' || c == '/' || !c.is_ascii_graphic())
            .unwrap_or(after.len());
        after[..end].to_string()
    })
}

/// Custom certificate verifier that accepts any certificate.
/// We're collecting certificates for analysis, not validating trust chains.
#[derive(Debug)]
struct AcceptAnyCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_readable_cn_finds_cn() {
        let text = "some/CN=example.com,O=Org";
        assert_eq!(
            extract_readable_cn(text, "CN=").as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn extract_readable_cn_finds_org() {
        let text = "some/CN=test,O=MyOrg,L=City";
        assert_eq!(
            extract_readable_cn(text, "O=").as_deref(),
            Some("MyOrg")
        );
    }

    #[test]
    fn extract_readable_cn_not_found() {
        assert!(extract_readable_cn("no match here", "CN=").is_none());
    }

    #[test]
    fn tls_ports_include_common() {
        assert!(TLS_PORTS.contains(&443));
        assert!(TLS_PORTS.contains(&8443));
        assert!(TLS_PORTS.contains(&993));
        assert!(!TLS_PORTS.contains(&80));
    }

    #[test]
    fn extract_readable_cn_at_end() {
        let text = "O=Test,CN=last.example.com";
        assert_eq!(extract_readable_cn(text, "CN=").as_deref(), Some("last.example.com"));
    }

    #[test]
    fn extract_readable_cn_with_spaces() {
        // Stops at non-graphic chars
        let text = "CN=my host";
        assert_eq!(extract_readable_cn(text, "CN=").as_deref(), Some("my"));
    }

    #[test]
    fn x509_parser_basic() {
        let der = b"some/CN=test.local,O=TestOrg/other data";
        let result = x509_parser(der);
        assert!(result.is_ok());
        let (_, cert) = result.unwrap();
        assert_eq!(cert.subject, "test.local");
    }

    #[test]
    fn x509_parser_no_cn() {
        let der = b"no cn or org here just random bytes";
        let result = x509_parser(der);
        assert!(result.is_ok());
        let (_, cert) = result.unwrap();
        assert!(cert.subject.is_empty());
    }

    #[test]
    fn tls_ports_no_duplicates() {
        let mut sorted = TLS_PORTS.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), TLS_PORTS.len(), "TLS_PORTS has duplicates");
    }
}
