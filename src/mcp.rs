//! MCP server for amimori. Queries the daemon's gRPC endpoint.
//!
//! 7 tools: network_snapshot, network_hosts, network_changes,
//! network_host_detail, wifi_networks, network_interfaces, network_stats

use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
};
use serde::Deserialize;
use std::fmt::Write;

use crate::grpc::proto::{self, network_profiler_client::NetworkProfilerClient};

// ── Tool input schemas ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SnapshotInput {
    #[schemars(description = "Filter by interface name (e.g. 'en0'). Omit for all.")]
    interface: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct HostsInput {
    #[schemars(description = "Filter by interface name")]
    interface: Option<String>,

    #[schemars(description = "Filter by vendor name (case-insensitive substring)")]
    vendor: Option<String>,

    #[schemars(description = "Filter by port number (show only hosts with this port open)")]
    port: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ChangesInput {
    #[schemars(description = "Max events to return (default 50, max 500)")]
    limit: Option<usize>,

    #[schemars(description = "Return events since this sequence number (0 = all available)")]
    since_sequence: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct HostDetailInput {
    #[schemars(description = "MAC address or IP address of the host")]
    address: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct WifiInput {
    #[schemars(description = "Filter by interface name")]
    interface: Option<String>,

    #[schemars(description = "Minimum signal strength (RSSI, e.g. -70)")]
    min_rssi: Option<i32>,

    #[schemars(description = "Filter by security type (substring, e.g. 'WPA3')")]
    security: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct WakeInput {
    #[schemars(description = "MAC address of the host to wake")]
    mac: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ExportInput {
    #[schemars(description = "Export format: csv or json")]
    format: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct EmptyInput {}

// ── MCP Server ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct AmimoriMcp {
    /// Lazy-initialized, reusable gRPC channel. Tonic channels multiplex
    /// requests over a single HTTP/2 connection — no per-call overhead.
    channel: tonic::transport::Channel,
    tool_router: ToolRouter<Self>,
}

impl AmimoriMcp {
    fn client(&self) -> NetworkProfilerClient<tonic::transport::Channel> {
        NetworkProfilerClient::new(self.channel.clone())
    }
}

#[tool_router]
impl AmimoriMcp {
    fn new(channel: tonic::transport::Channel) -> Self {
        Self {
            channel,
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Get full network snapshot — all interfaces, hosts, and WiFi networks")]
    async fn network_snapshot(&self, Parameters(input): Parameters<SnapshotInput>) -> String {
        let mut client = self.client();

        match client
            .get_snapshot(proto::SnapshotRequest {
                interface: input.interface.unwrap_or_default(),
            })
            .await
        {
            Ok(resp) => format_snapshot(&resp.into_inner()),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(description = "List discovered hosts with optional filters by interface, vendor, or port")]
    async fn network_hosts(&self, Parameters(input): Parameters<HostsInput>) -> String {
        let mut client = self.client();

        match client
            .get_snapshot(proto::SnapshotRequest {
                interface: input.interface.unwrap_or_default(),
            })
            .await
        {
            Ok(resp) => {
                let mut hosts = resp.into_inner().hosts;

                if let Some(ref vendor) = input.vendor {
                    let v = vendor.to_lowercase();
                    hosts.retain(|h| h.vendor.to_lowercase().contains(&v));
                }
                if let Some(port) = input.port {
                    hosts.retain(|h| h.services.iter().any(|s| s.port == port));
                }

                format_hosts(&hosts)
            }
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(description = "Get recent network change events (host/wifi added/removed/updated)")]
    async fn network_changes(&self, Parameters(input): Parameters<ChangesInput>) -> String {
        let mut client = self.client();

        let limit = input.limit.unwrap_or(50).min(500);
        match client
            .get_changes(proto::ChangesRequest {
                since_sequence: input.since_sequence.unwrap_or(0),
                limit: limit as u32,
            })
            .await
        {
            Ok(resp) => {
                let resp = resp.into_inner();
                format_changes(&resp.events, resp.current_sequence)
            }
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(description = "Get detailed host info by MAC or IP address, including services")]
    async fn network_host_detail(&self, Parameters(input): Parameters<HostDetailInput>) -> String {
        let mut client = self.client();

        match client
            .get_host(proto::HostRequest {
                address: input.address,
            })
            .await
        {
            Ok(resp) => format_host_detail(&resp.into_inner()),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(description = "List visible WiFi networks, sorted by signal strength")]
    async fn wifi_networks(&self, Parameters(input): Parameters<WifiInput>) -> String {
        let mut client = self.client();

        match client.list_wifi_networks(proto::Empty {}).await {
            Ok(resp) => {
                let mut networks = resp.into_inner().networks;

                if let Some(ref iface) = input.interface {
                    networks.retain(|n| n.interface == *iface);
                }
                if let Some(min_rssi) = input.min_rssi {
                    networks.retain(|n| n.rssi >= min_rssi);
                }
                if let Some(ref sec) = input.security {
                    let s = sec.to_lowercase();
                    networks.retain(|n| n.security.to_lowercase().contains(&s));
                }

                networks.sort_by(|a, b| b.rssi.cmp(&a.rssi));
                format_wifi(&networks)
            }
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(description = "List all monitored network interfaces with IP, gateway, DNS, and status")]
    async fn network_interfaces(&self, Parameters(_): Parameters<EmptyInput>) -> String {
        let mut client = self.client();

        match client.list_interfaces(proto::Empty {}).await {
            Ok(resp) => format_interfaces(&resp.into_inner().interfaces),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(description = "Send Wake-on-LAN magic packet to a host by MAC address")]
    async fn network_wake(&self, Parameters(input): Parameters<WakeInput>) -> String {
        let mac_bytes: Vec<u8> = input.mac.split(':')
            .filter_map(|s| u8::from_str_radix(s, 16).ok())
            .collect();

        if mac_bytes.len() != 6 {
            return format!("error: invalid MAC address '{}'", input.mac);
        }

        let mut mac_arr = [0u8; 6];
        mac_arr.copy_from_slice(&mac_bytes);
        let packet = wake_on_lan::MagicPacket::new(&mac_arr);
        match packet.send() {
            Ok(()) => format!("WoL magic packet sent to {}", input.mac),
            Err(e) => format!("error sending WoL: {e}"),
        }
    }

    #[tool(description = "Export full host inventory as CSV or JSON")]
    async fn network_export(&self, Parameters(input): Parameters<ExportInput>) -> String {
        let mut client = self.client();

        match client.get_snapshot(proto::SnapshotRequest::default()).await {
            Ok(resp) => {
                let snapshot = resp.into_inner();
                let format = input.format.as_deref().unwrap_or("json");

                // Convert proto hosts to model hosts for export
                let hosts: Vec<crate::model::HostInfo> = snapshot.hosts.iter().map(|h| {
                    crate::model::HostInfo {
                        mac: h.mac.clone(),
                        vendor: h.vendor.clone(),
                        addresses: h.ipv4.iter().chain(h.ipv6.iter())
                            .filter_map(|s| s.parse().ok()).collect(),
                        hostname: if h.hostname.is_empty() { None } else { Some(h.hostname.clone()) },
                        os_hint: if h.os_hint.is_empty() { None } else { Some(h.os_hint.clone()) },
                        services: h.services.iter().map(|s| crate::model::ServiceInfo {
                            port: s.port as u16,
                            protocol: s.protocol.clone(),
                            name: s.name.clone(),
                            version: s.version.clone(),
                            state: s.state.clone(),
                            banner: String::new(),
                        }).collect(),
                        fingerprints: Vec::new(),
                        interface: h.interface.clone(),
                        network_id: String::new(),
                        first_seen: chrono::Utc::now(),
                        last_seen: chrono::Utc::now(),
                    }
                }).collect();

                match format {
                    "csv" => crate::export::to_csv(&hosts),
                    _ => crate::export::to_json(&hosts),
                }
            }
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(description = "Show network topology — subnets, gateways, host distribution")]
    async fn network_topology(&self, Parameters(_): Parameters<EmptyInput>) -> String {
        let mut client = self.client();

        match client.get_snapshot(proto::SnapshotRequest::default()).await {
            Ok(resp) => {
                let snapshot = resp.into_inner();

                let hosts: Vec<crate::model::HostInfo> = snapshot.hosts.iter().map(|h| {
                    crate::model::HostInfo {
                        mac: h.mac.clone(),
                        vendor: h.vendor.clone(),
                        addresses: h.ipv4.iter().chain(h.ipv6.iter())
                            .filter_map(|s| s.parse().ok()).collect(),
                        hostname: if h.hostname.is_empty() { None } else { Some(h.hostname.clone()) },
                        os_hint: None, services: vec![], fingerprints: vec![],
                        interface: h.interface.clone(), network_id: String::new(),
                        first_seen: chrono::Utc::now(), last_seen: chrono::Utc::now(),
                    }
                }).collect();

                let interfaces: Vec<crate::model::InterfaceInfo> = snapshot.interfaces.iter().map(|i| {
                    crate::model::InterfaceInfo {
                        name: i.name.clone(),
                        mac: i.mac.clone(),
                        ipv4: i.ipv4.iter().filter_map(|s| s.parse().ok()).collect(),
                        ipv6: i.ipv6.iter().filter_map(|s| s.parse().ok()).collect(),
                        gateway: i.gateway.clone(),
                        subnet: i.subnet.clone(),
                        is_up: i.is_up,
                        kind: crate::model::InterfaceKind::from_name(&i.name),
                        dns: i.dns.clone(),
                    }
                }).collect();

                let topo = crate::topology::build_topology(&hosts, &interfaces);
                crate::topology::format_topology(&topo)
            }
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(description = "Get profiler daemon health, statistics, and configuration")]
    async fn network_stats(&self, Parameters(_): Parameters<EmptyInput>) -> String {
        let mut client = self.client();

        match client
            .get_snapshot(proto::SnapshotRequest::default())
            .await
        {
            Ok(resp) => {
                let s = resp.into_inner();
                let mut out = String::new();
                let _ = writeln!(out, "amimori: healthy");
                let _ = writeln!(out, "  status: connected");
                let _ = writeln!(out, "  sequence: {}", s.sequence);
                let _ = writeln!(out, "  interfaces: {}", s.interfaces.len());
                let _ = writeln!(out, "  hosts: {}", s.hosts.len());
                let _ = writeln!(out, "  wifi_networks: {}", s.wifi_networks.len());
                out
            }
            Err(e) => format!("amimori: unavailable\nerror: {e}"),
        }
    }
}

#[tool_handler]
impl ServerHandler for AmimoriMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "amimori — continuous network profiler. Query network state, \
                 hosts, WiFi, and change events from the running daemon."
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

// ── Formatting ─────────────────────────────────────────────────────────────

fn format_snapshot(s: &proto::NetworkSnapshot) -> String {
    let mut out = String::with_capacity(2048);
    let _ = writeln!(out, "Network Snapshot (seq: {})\n", s.sequence);

    let _ = writeln!(out, "Interfaces ({})", s.interfaces.len());
    for i in &s.interfaces {
        let status = if i.is_up { "UP" } else { "DOWN" };
        let _ = writeln!(
            out, "  {} [{}] {status} mac={} ipv4={:?} gw={}",
            i.name, i.kind, i.mac, i.ipv4, i.gateway,
        );
    }

    let _ = writeln!(out, "\nHosts ({})", s.hosts.len());
    for h in &s.hosts {
        let svcs = if h.services.is_empty() {
            String::new()
        } else {
            format!(" [{} svc]", h.services.len())
        };
        let _ = writeln!(
            out, "  {} {} {:?} on {}{svcs}",
            h.mac, h.vendor, h.ipv4, h.interface,
        );
    }

    let _ = writeln!(out, "\nWiFi ({})", s.wifi_networks.len());
    for w in &s.wifi_networks {
        let _ = writeln!(
            out, "  {} ch{} {} rssi={} {}",
            w.ssid, w.channel, w.band, w.rssi, w.security,
        );
    }

    out
}

fn format_hosts(hosts: &[proto::Host]) -> String {
    let mut out = String::with_capacity(1024);
    let _ = writeln!(out, "{} hosts", hosts.len());
    for h in hosts {
        let svcs = h
            .services
            .iter()
            .map(|s| {
                if s.name.is_empty() {
                    format!("{}/{}", s.port, s.protocol)
                } else {
                    format!("{}({})", s.port, s.name)
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        let _ = writeln!(
            out, "  {} | {} | {} | {:?} {}",
            h.mac, h.vendor, h.hostname, h.ipv4,
            if svcs.is_empty() { String::new() } else { format!("| {svcs}") },
        );
    }
    out
}

fn format_host_detail(h: &proto::Host) -> String {
    let mut out = String::with_capacity(1024);
    let _ = writeln!(out, "MAC: {}", h.mac);
    let _ = writeln!(out, "Vendor: {}", h.vendor);
    let _ = writeln!(out, "Hostname: {}", h.hostname);
    let _ = writeln!(out, "IPv4: {:?}", h.ipv4);
    let _ = writeln!(out, "IPv6: {:?}", h.ipv6);
    let _ = writeln!(out, "OS: {}", h.os_hint);
    let _ = writeln!(out, "Interface: {}", h.interface);
    let _ = writeln!(out, "Outlier Score: {:.1}/5.0", h.outlier_score);
    if !h.services.is_empty() {
        let _ = writeln!(out, "Services:");
        for s in &h.services {
            let _ = writeln!(
                out, "  {}/{} {} {} [{}]",
                s.port, s.protocol, s.name, s.version, s.state,
            );
        }
    }
    if !h.fingerprints.is_empty() {
        let _ = writeln!(out, "Fingerprints:");
        for fp in &h.fingerprints {
            let _ = writeln!(
                out, "  {}.{} = {} ({} {:.0}%)",
                fp.category, fp.key, fp.value, fp.source,
                fp.confidence * 100.0,
            );
        }
    }
    out
}

fn format_wifi(networks: &[proto::WifiNetwork]) -> String {
    let mut out = String::with_capacity(1024);
    let _ = writeln!(out, "{} WiFi networks", networks.len());
    for w in networks {
        let snr = w.rssi - w.noise;
        let _ = writeln!(
            out, "  {:32} ch{:<3} {:5} rssi={:<4} snr={:<3} {}",
            w.ssid, w.channel, w.band, w.rssi, snr, w.security,
        );
    }
    out
}

fn format_changes(events: &[proto::DeltaUpdate], current_seq: u64) -> String {
    if events.is_empty() {
        return format!("No changes (current sequence: {current_seq})");
    }

    let mut out = String::with_capacity(2048);
    let _ = writeln!(out, "{} events (sequence: {current_seq})\n", events.len());

    for e in events {
        let desc = match &e.change {
            Some(proto::delta_update::Change::HostAdded(h)) => {
                let name = if h.hostname.is_empty() { &h.vendor } else { &h.hostname };
                format!("+ host {} ({}) {:?}", h.mac, name, h.ipv4)
            }
            Some(proto::delta_update::Change::HostRemoved(h)) => {
                format!("- host {}", h.mac)
            }
            Some(proto::delta_update::Change::HostUpdated(h)) => {
                let name = if h.hostname.is_empty() { &h.vendor } else { &h.hostname };
                format!("~ host {} ({}) {:?}", h.mac, name, h.ipv4)
            }
            Some(proto::delta_update::Change::ServiceChanged(sc)) => {
                let svc = sc.service.as_ref().map_or("?".into(), |s| {
                    format!("{}/{} {}", s.port, s.protocol, s.name)
                });
                format!("  svc {} {} {}", sc.change_type, sc.host_mac, svc)
            }
            Some(proto::delta_update::Change::WifiAdded(w)) => {
                format!("+ wifi {} (ch{} {})", w.ssid, w.channel, w.security)
            }
            Some(proto::delta_update::Change::WifiRemoved(w)) => {
                format!("- wifi {}", w.bssid)
            }
            Some(proto::delta_update::Change::WifiUpdated(w)) => {
                format!("~ wifi {} rssi={}", w.ssid, w.rssi)
            }
            Some(proto::delta_update::Change::InterfaceChanged(i)) => {
                let status = if i.is_up { "UP" } else { "DOWN" };
                format!("~ iface {} {status} {:?}", i.name, i.ipv4)
            }
            Some(proto::delta_update::Change::NetworkChanged(nc)) => {
                format!(
                    "! network {} → {} on {} (cleared {} hosts)",
                    nc.old_network_id, nc.new_network_id, nc.interface, nc.hosts_cleared
                )
            }
            None => "? unknown event".into(),
        };
        let _ = writeln!(out, "  [{:>6}] {desc}", e.sequence);
    }
    out
}

fn format_interfaces(interfaces: &[proto::NetworkInterface]) -> String {
    let mut out = String::with_capacity(512);
    let _ = writeln!(out, "{} interfaces", interfaces.len());
    for i in interfaces {
        let status = if i.is_up { "UP" } else { "DOWN" };
        let _ = writeln!(
            out, "  {} [{}] {status} ipv4={:?} gw={} dns={:?}",
            i.name, i.kind, i.ipv4, i.gateway, i.dns,
        );
    }
    out
}

// ── Entry point ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn proto_host() -> proto::Host {
        proto::Host {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            vendor: "Apple".into(),
            ipv4: vec!["10.0.0.1".into()],
            ipv6: vec!["fe80::1".into()],
            hostname: "macbook".into(),
            os_hint: "macOS".into(),
            services: vec![proto::Service {
                port: 22,
                protocol: "tcp".into(),
                name: "ssh".into(),
                version: "OpenSSH 9".into(),
                state: "open".into(),
            }],
            interface: "en0".into(),
            first_seen: None,
            last_seen: None,
            ..Default::default()
        }
    }

    fn proto_wifi() -> proto::WifiNetwork {
        proto::WifiNetwork {
            ssid: "HomeNet".into(),
            bssid: "11:22:33:44:55:66".into(),
            rssi: -55,
            noise: -90,
            channel: 36,
            band: "5GHz".into(),
            security: "WPA3".into(),
            interface: "en0".into(),
        }
    }

    fn proto_iface() -> proto::NetworkInterface {
        proto::NetworkInterface {
            name: "en0".into(),
            mac: "aa:bb:cc:dd:ee:ff".into(),
            ipv4: vec!["10.0.0.5".into()],
            ipv6: vec![],
            gateway: "10.0.0.1".into(),
            subnet: "255.255.255.0".into(),
            is_up: true,
            kind: "wifi".into(),
            dns: vec!["8.8.8.8".into()],
        }
    }

    // ── format_snapshot ────────────────────────────────────────────────

    #[test]
    fn format_snapshot_empty() {
        let snap = proto::NetworkSnapshot {
            interfaces: vec![],
            hosts: vec![],
            wifi_networks: vec![],
            sequence: 0,
            timestamp: None,
        };
        let out = format_snapshot(&snap);
        assert!(out.contains("Interfaces (0)"));
        assert!(out.contains("Hosts (0)"));
        assert!(out.contains("WiFi (0)"));
    }

    #[test]
    fn format_snapshot_with_data() {
        let snap = proto::NetworkSnapshot {
            interfaces: vec![proto_iface()],
            hosts: vec![proto_host()],
            wifi_networks: vec![proto_wifi()],
            sequence: 42,
            timestamp: None,
        };
        let out = format_snapshot(&snap);
        assert!(out.contains("seq: 42"));
        assert!(out.contains("Interfaces (1)"));
        assert!(out.contains("en0"));
        assert!(out.contains("Hosts (1)"));
        assert!(out.contains("aa:bb:cc:dd:ee:ff"));
        assert!(out.contains("WiFi (1)"));
        assert!(out.contains("HomeNet"));
    }

    // ── format_hosts ───────────────────────────────────────────────────

    #[test]
    fn format_hosts_empty() {
        let out = format_hosts(&[]);
        assert!(out.contains("0 hosts"));
    }

    #[test]
    fn format_hosts_with_services() {
        let out = format_hosts(&[proto_host()]);
        assert!(out.contains("1 hosts"));
        assert!(out.contains("22(ssh)"));
    }

    #[test]
    fn format_hosts_service_without_name() {
        let mut h = proto_host();
        h.services[0].name = String::new();
        let out = format_hosts(&[h]);
        assert!(out.contains("22/tcp"));
    }

    // ── format_host_detail ─────────────────────────────────────────────

    #[test]
    fn format_host_detail_all_fields() {
        let out = format_host_detail(&proto_host());
        assert!(out.contains("MAC: aa:bb:cc:dd:ee:ff"));
        assert!(out.contains("Vendor: Apple"));
        assert!(out.contains("Hostname: macbook"));
        assert!(out.contains("OS: macOS"));
        assert!(out.contains("Interface: en0"));
        assert!(out.contains("Services:"));
        assert!(out.contains("22/tcp ssh OpenSSH 9 [open]"));
    }

    #[test]
    fn format_host_detail_no_services() {
        let mut h = proto_host();
        h.services.clear();
        let out = format_host_detail(&h);
        assert!(!out.contains("Services:"));
    }

    // ── format_wifi ────────────────────────────────────────────────────

    #[test]
    fn format_wifi_empty() {
        let out = format_wifi(&[]);
        assert!(out.contains("0 WiFi networks"));
    }

    #[test]
    fn format_wifi_with_snr() {
        let out = format_wifi(&[proto_wifi()]);
        assert!(out.contains("HomeNet"));
        assert!(out.contains("rssi=-55"));
        // SNR = -55 - (-90) = 35
        assert!(out.contains("snr=35"));
    }

    // ── format_interfaces ──────────────────────────────────────────────

    #[test]
    fn format_interfaces_empty() {
        let out = format_interfaces(&[]);
        assert!(out.contains("0 interfaces"));
    }

    #[test]
    fn format_interfaces_up_down() {
        let mut down = proto_iface();
        down.name = "en4".into();
        down.is_up = false;
        let out = format_interfaces(&[proto_iface(), down]);
        assert!(out.contains("2 interfaces"));
        assert!(out.contains("en0") && out.contains("UP"));
        assert!(out.contains("en4") && out.contains("DOWN"));
    }

    // ── format_changes ────────────────────────────────────────────────

    #[test]
    fn format_changes_empty() {
        let out = format_changes(&[], 42);
        assert!(out.contains("No changes"));
        assert!(out.contains("42"));
    }

    #[test]
    fn format_changes_host_added() {
        let events = vec![proto::DeltaUpdate {
            sequence: 1,
            timestamp: None,
            change: Some(proto::delta_update::Change::HostAdded(proto_host())),
        }];
        let out = format_changes(&events, 1);
        assert!(out.contains("1 events"));
        assert!(out.contains("+ host"));
        assert!(out.contains("aa:bb:cc:dd:ee:ff"));
        assert!(out.contains("macbook")); // hostname shown
    }

    #[test]
    fn format_changes_host_removed() {
        let events = vec![proto::DeltaUpdate {
            sequence: 2,
            timestamp: None,
            change: Some(proto::delta_update::Change::HostRemoved(proto::Host {
                mac: "aa:bb:cc:dd:ee:ff".into(),
                ..Default::default()
            })),
        }];
        let out = format_changes(&events, 2);
        assert!(out.contains("- host"));
    }

    #[test]
    fn format_changes_wifi_added() {
        let events = vec![proto::DeltaUpdate {
            sequence: 3,
            timestamp: None,
            change: Some(proto::delta_update::Change::WifiAdded(proto_wifi())),
        }];
        let out = format_changes(&events, 3);
        assert!(out.contains("+ wifi"));
        assert!(out.contains("HomeNet"));
    }

    #[test]
    fn format_changes_network_changed() {
        let events = vec![proto::DeltaUpdate {
            sequence: 4,
            timestamp: None,
            change: Some(proto::delta_update::Change::NetworkChanged(
                proto::NetworkChange {
                    interface: "en0".into(),
                    old_network_id: "10.0.0.1|/24".into(),
                    new_network_id: "192.168.1.1|/24".into(),
                    hosts_cleared: 12,
                },
            )),
        }];
        let out = format_changes(&events, 4);
        assert!(out.contains("! network"));
        assert!(out.contains("cleared 12 hosts"));
    }

    #[test]
    fn format_changes_service_changed() {
        let events = vec![proto::DeltaUpdate {
            sequence: 5,
            timestamp: None,
            change: Some(proto::delta_update::Change::ServiceChanged(
                proto::ServiceChange {
                    host_mac: "aa:bb:cc:dd:ee:ff".into(),
                    service: Some(proto::Service {
                        port: 443,
                        protocol: "tcp".into(),
                        name: "https".into(),
                        version: String::new(),
                        state: "open".into(),
                    }),
                    change_type: "added".into(),
                },
            )),
        }];
        let out = format_changes(&events, 5);
        assert!(out.contains("svc added"));
        assert!(out.contains("443/tcp https"));
    }
}

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let grpc_url = std::env::var("AMIMORI_GRPC_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:50051".to_string());

    // Connect once — the channel is cheap to clone and multiplexes over HTTP/2.
    let channel = tonic::transport::Endpoint::from_shared(grpc_url)?
        .connect_lazy();

    let server = AmimoriMcp::new(channel).serve(stdio()).await?;
    server.waiting().await?;
    Ok(())
}
