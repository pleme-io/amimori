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

        match client
            .get_snapshot(proto::SnapshotRequest::default())
            .await
        {
            Ok(resp) => {
                let snapshot = resp.into_inner();
                let limit = input.limit.unwrap_or(50).min(500);
                let mut out = String::new();
                let _ = writeln!(out, "Current sequence: {}", snapshot.sequence);
                let _ = writeln!(
                    out,
                    "State: {} hosts, {} interfaces, {} wifi networks",
                    snapshot.hosts.len(),
                    snapshot.interfaces.len(),
                    snapshot.wifi_networks.len(),
                );
                let _ = writeln!(
                    out,
                    "\nUse gRPC Subscribe RPC for streaming deltas (since_sequence={}, limit={limit})",
                    input.since_sequence.unwrap_or(0)
                );
                out
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
    let mut out = String::with_capacity(512);
    let _ = writeln!(out, "MAC: {}", h.mac);
    let _ = writeln!(out, "Vendor: {}", h.vendor);
    let _ = writeln!(out, "Hostname: {}", h.hostname);
    let _ = writeln!(out, "IPv4: {:?}", h.ipv4);
    let _ = writeln!(out, "IPv6: {:?}", h.ipv6);
    let _ = writeln!(out, "OS: {}", h.os_hint);
    let _ = writeln!(out, "Interface: {}", h.interface);
    if !h.services.is_empty() {
        let _ = writeln!(out, "Services:");
        for s in &h.services {
            let _ = writeln!(
                out, "  {}/{} {} {} [{}]",
                s.port, s.protocol, s.name, s.version, s.state,
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
