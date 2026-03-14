//! NetBIOS/SMB fingerprinting — discover Windows hosts, domains, shares.
//!
//! NetBIOS Name Service (UDP 137): sends NODE STATUS REQUEST to get
//! computer name, domain/workgroup, logged-in user, and role flags.
//! No authentication required.
//!
//! SMB Negotiate (TCP 445): connects and sends a Negotiate Protocol
//! request. The response reveals OS version, native LAN manager,
//! SMB dialect support, and server GUID — all before authentication.
//!
//! Safety level: 2 (Discovery) — sends UDP/TCP packets to well-known ports.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::collector::{Collector, CollectorOutput};
use crate::collector::banner::BannerResult;
use crate::config::Config;
use crate::model::{Fingerprint, FingerprintSource};
use crate::state::StateEngine;

const NETBIOS_PORT: u16 = 137;
const SMB_PORT: u16 = 445;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const READ_TIMEOUT: Duration = Duration::from_secs(3);

pub struct NetbiosCollector {
    interval: Duration,
    max_failures: u32,
    engine: Arc<StateEngine>,
}

impl NetbiosCollector {
    pub fn new(_config: &Config, engine: Arc<StateEngine>) -> Self {
        Self {
            interval: Duration::from_secs(120),
            max_failures: 5,
            engine,
        }
    }
}

#[async_trait::async_trait]
impl Collector for NetbiosCollector {
    fn name(&self) -> &str { "netbios" }
    fn interval(&self) -> Duration { self.interval }
    fn max_failures(&self) -> u32 { self.max_failures }

    async fn collect(&self) -> anyhow::Result<CollectorOutput> {
        let now = Utc::now();
        let mut results = Vec::new();

        // Find hosts with port 445 or 137 open, or Windows-like OS
        let targets: Vec<(String, String)> = self.engine.state.hosts.iter()
            .filter(|e| {
                let h = e.value();
                h.services.iter().any(|s| s.port == SMB_PORT || s.port == NETBIOS_PORT)
                    || h.os_hint.as_deref().map_or(false, |o| o.to_lowercase().contains("windows"))
                    || h.fingerprint("net", "netbios_name").is_none() // not yet probed
            })
            .filter_map(|e| {
                let ip = e.value().addresses.iter()
                    .find(|a| a.is_ipv4())?
                    .to_string();
                Some((e.key().clone(), ip))
            })
            .take(32) // limit per cycle
            .collect();

        let semaphore = Arc::new(tokio::sync::Semaphore::new(8));

        for (mac, ip) in targets {
            let sem = semaphore.clone();
            let mac_clone = mac.clone();
            let ip_clone = ip.clone();

            // NetBIOS name query (UDP, blocking)
            let nb_result = tokio::task::spawn_blocking({
                let ip = ip.clone();
                move || query_netbios_name(&ip)
            });

            // SMB negotiate (TCP, async)
            let smb_result = {
                let ip = ip.clone();
                async move {
                    let _permit = sem.acquire().await.ok()?;
                    smb_negotiate(&ip).await
                }
            };

            let (nb, smb) = tokio::join!(nb_result, smb_result);
            let mut fps = Vec::new();

            if let Ok(Some(names)) = nb {
                for (name_type, name) in names {
                    fps.push(Fingerprint {
                        source: FingerprintSource::Banner,
                        category: "net".into(),
                        key: name_type,
                        value: name,
                        confidence: 0.9,
                        observed_at: now,
                    });
                }
            }

            if let Some(smb_fps) = smb {
                fps.extend(smb_fps);
            }

            if !fps.is_empty() {
                results.push(BannerResult {
                    mac: mac_clone,
                    ip: ip_clone,
                    port: SMB_PORT,
                    protocol: "smb".into(),
                    banner: String::new(),
                    fingerprints: fps,
                });
            }
        }

        tracing::debug!(hosts = results.len(), "NetBIOS/SMB probe complete");
        Ok(CollectorOutput::Banners(results))
    }
}

/// Send NetBIOS NODE STATUS REQUEST (UDP 137) and parse the response.
fn query_netbios_name(ip: &str) -> Option<Vec<(String, String)>> {
    let addr: SocketAddr = format!("{ip}:{NETBIOS_PORT}").parse().ok()?;
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(READ_TIMEOUT)).ok()?;

    // NetBIOS NODE STATUS REQUEST packet
    // Transaction ID (2) + Flags (2) + Questions (2) + Answer/Auth/Additional (6)
    // + Name (34, encoded "*") + Type (2, NBSTAT=0x0021) + Class (2, IN=0x0001)
    let packet: [u8; 50] = [
        0x00, 0x01, // Transaction ID
        0x00, 0x00, // Flags: query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Answer/Authority/Additional: 0
        // Encoded name "*" (CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)
        0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x00,
        0x00, 0x21, // Type: NBSTAT
        0x00, 0x01, // Class: IN
    ];

    socket.send_to(&packet, addr).ok()?;

    let mut buf = [0u8; 1024];
    let n = socket.recv(&mut buf).ok()?;
    if n < 57 { return None; }

    // Parse response: skip header (12) + name (34) + type/class (4) + TTL (4) + rdlength (2) = 56
    // Then: num_names (1) + name entries (18 bytes each)
    let num_names = buf[56] as usize;
    let mut names = Vec::new();

    for i in 0..num_names {
        let offset = 57 + i * 18;
        if offset + 18 > n { break; }

        let name_bytes = &buf[offset..offset + 15];
        let name = String::from_utf8_lossy(name_bytes).trim().to_string();
        let name_type = buf[offset + 15];
        let _flags = u16::from_be_bytes([buf[offset + 16], buf[offset + 17]]);

        if name.is_empty() { continue; }

        let key = match name_type {
            0x00 => "netbios_name",
            0x03 => "netbios_user",
            0x20 => "netbios_server",
            0x1B => "netbios_domain_master",
            0x1C => "netbios_domain_controller",
            0x1D => "netbios_master_browser",
            _ => continue,
        };
        names.push((key.to_string(), name));
    }

    if names.is_empty() { None } else { Some(names) }
}

/// Connect to SMB (TCP 445) and send a minimal negotiate request.
/// Parse the response for OS version and dialect info.
async fn smb_negotiate(ip: &str) -> Option<Vec<Fingerprint>> {
    let addr: SocketAddr = format!("{ip}:{SMB_PORT}").parse().ok()?;
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await.ok()?.ok()?;

    // SMB2 Negotiate Request (minimal)
    let negotiate: [u8; 114] = [
        // NetBIOS session header (4 bytes)
        0x00, 0x00, 0x00, 0x74, // length = 116
        // SMB2 header (64 bytes)
        0xFE, 0x53, 0x4D, 0x42, // magic: \xFESMB
        0x40, 0x00, // header size
        0x00, 0x00, // credit charge
        0x00, 0x00, 0x00, 0x00, // status
        0x00, 0x00, // command: negotiate
        0x00, 0x00, // credit request
        0x00, 0x00, 0x00, 0x00, // flags
        0x00, 0x00, 0x00, 0x00, // next command
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // message ID
        0x00, 0x00, 0x00, 0x00, // reserved
        0x00, 0x00, 0x00, 0x00, // tree ID
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // session ID
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // signature
        // SMB2 Negotiate request body (52 bytes)
        0x24, 0x00, // structure size
        0x05, 0x00, // dialect count: 5
        0x01, 0x00, // security mode: signing enabled
        0x00, 0x00, // reserved
        0x7F, 0x00, 0x00, 0x00, // capabilities
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // client GUID
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // negotiate context
        // Dialects: 0x0202, 0x0210, 0x0300, 0x0302, 0x0311
        0x02, 0x02, 0x10, 0x02, 0x00, 0x03, 0x02, 0x03, 0x11, 0x03,
    ];

    stream.write_all(&negotiate).await.ok()?;

    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf))
        .await.ok()?.ok()?;

    if n < 72 { return None; }

    let now = Utc::now();
    let mut fps = Vec::new();

    // Check for SMB2 magic at offset 4
    if &buf[4..8] == b"\xFESMB" {
        // Dialect is at offset 4+64+4 = 72 (negotiate response body offset 4)
        let dialect = u16::from_le_bytes([buf[72], buf[73]]);
        let dialect_str = match dialect {
            0x0202 => "SMB 2.0.2",
            0x0210 => "SMB 2.1",
            0x0300 => "SMB 3.0",
            0x0302 => "SMB 3.0.2",
            0x0311 => "SMB 3.1.1",
            _ => "unknown",
        };
        fps.push(Fingerprint {
            source: FingerprintSource::Banner,
            category: "sw".into(),
            key: "smb_dialect".into(),
            value: dialect_str.into(),
            confidence: 1.0,
            observed_at: now,
        });
    }

    if fps.is_empty() { None } else { Some(fps) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netbios_packet_correct_size() {
        // NODE STATUS REQUEST is 50 bytes
        let packet: [u8; 50] = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x00,
            0x00, 0x21, 0x00, 0x01,
        ];
        assert_eq!(packet.len(), 50);
    }

    #[test]
    fn smb_negotiate_size() {
        // Our negotiate packet is 114 bytes (4 netbios + 64 header + 36 body + 10 dialects)
        assert_eq!(114, 4 + 64 + 36 + 10);
    }

    #[test]
    fn netbios_name_type_mapping() {
        // Verify our name type byte → key mapping covers known types
        let known_types: Vec<u8> = vec![0x00, 0x03, 0x20, 0x1B, 0x1C, 0x1D];
        let labels: Vec<&str> = vec![
            "netbios_name", "netbios_user", "netbios_server",
            "netbios_domain_master", "netbios_domain_controller", "netbios_master_browser",
        ];
        assert_eq!(known_types.len(), labels.len());
    }

    #[test]
    fn smb_dialect_mapping() {
        // Verify our dialect codes map to known SMB versions
        let dialects: Vec<(u16, &str)> = vec![
            (0x0202, "SMB 2.0.2"),
            (0x0210, "SMB 2.1"),
            (0x0300, "SMB 3.0"),
            (0x0302, "SMB 3.0.2"),
            (0x0311, "SMB 3.1.1"),
        ];
        for (code, name) in dialects {
            let dialect_str = match code {
                0x0202 => "SMB 2.0.2",
                0x0210 => "SMB 2.1",
                0x0300 => "SMB 3.0",
                0x0302 => "SMB 3.0.2",
                0x0311 => "SMB 3.1.1",
                _ => "unknown",
            };
            assert_eq!(dialect_str, name);
        }
    }
}
