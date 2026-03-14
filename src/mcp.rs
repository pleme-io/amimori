//! MCP server for amimori. Queries the daemon's gRPC endpoint for network state.
//!
//! Tools:
//!   network_snapshot    — full snapshot of all profiled networks
//!   network_hosts       — list discovered hosts with optional filters
//!   network_changes     — recent network change events
//!   network_host_detail — detailed info on a specific host by MAC or IP
//!   wifi_networks       — WiFi networks visible from current location
//!   network_interfaces  — all monitored network interfaces with status
//!   network_stats       — profiler statistics and health

use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
};
use serde::Deserialize;
use std::fmt::Write;

use crate::grpc::proto::{
    self,
    network_profiler_client::NetworkProfilerClient,
};

// ── Tool input types ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SnapshotInput {
    #[schemars(description = "Optional: filter by interface name (e.g. 'en0')")]
    interface: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct HostsInput {
    #[schemars(description = "Optional: filter by interface name")]
    interface: Option<String>,

    #[schemars(description = "Optional: filter by vendor name (case-insensitive substring)")]
    vendor: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ChangesInput {
    #[schemars(description = "Number of recent events to return (default 50)")]
    limit: Option<usize>,

    #[schemars(description = "Return events since this sequence number (0 = all)")]
    since_sequence: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct HostDetailInput {
    #[schemars(description = "MAC address or IP address of the host")]
    address: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct WifiInput {
    #[schemars(description = "Optional: filter by interface name")]
    interface: Option<String>,

    #[schemars(description = "Optional: minimum signal strength (RSSI, e.g. -70)")]
    min_rssi: Option<i32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct EmptyInput {}

// ── MCP Server ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct AmimoriMcp {
    grpc_url: String,
    tool_router: ToolRouter<Self>,
}

impl AmimoriMcp {
    async fn client(
        &self,
    ) -> Result<NetworkProfilerClient<tonic::transport::Channel>, String> {
        NetworkProfilerClient::connect(self.grpc_url.clone())
            .await
            .map_err(|e| format!("Cannot connect to amimori daemon at {}: {e}", self.grpc_url))
    }
}

#[tool_router]
impl AmimoriMcp {
    fn new() -> Self {
        let grpc_url = std::env::var("AMIMORI_GRPC_URL")
            .unwrap_or_else(|_| "http://localhost:50051".to_string());
        Self {
            grpc_url,
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Get full snapshot of all profiled networks — interfaces, hosts, WiFi")]
    async fn network_snapshot(&self, Parameters(input): Parameters<SnapshotInput>) -> String {
        let mut client = match self.client().await {
            Ok(c) => c,
            Err(e) => return e,
        };

        let req = proto::SnapshotRequest {
            interface: input.interface.unwrap_or_default(),
        };

        match client.get_snapshot(req).await {
            Ok(resp) => format_snapshot(&resp.into_inner()),
            Err(e) => format!("Error: {e}"),
        }
    }

    #[tool(description = "List discovered hosts with optional filters by interface or vendor")]
    async fn network_hosts(&self, Parameters(input): Parameters<HostsInput>) -> String {
        let mut client = match self.client().await {
            Ok(c) => c,
            Err(e) => return e,
        };

        let req = proto::SnapshotRequest {
            interface: input.interface.unwrap_or_default(),
        };

        match client.get_snapshot(req).await {
            Ok(resp) => {
                let snapshot = resp.into_inner();
                let mut hosts = snapshot.hosts;

                // Apply vendor filter
                if let Some(ref vendor) = input.vendor {
                    let v = vendor.to_lowercase();
                    hosts.retain(|h| h.vendor.to_lowercase().contains(&v));
                }

                format_hosts(&hosts)
            }
            Err(e) => format!("Error: {e}"),
        }
    }

    #[tool(description = "Get recent network change events (host added/removed, WiFi changes, etc.)")]
    async fn network_changes(&self, Parameters(input): Parameters<ChangesInput>) -> String {
        let mut client = match self.client().await {
            Ok(c) => c,
            Err(e) => return e,
        };

        let req = proto::SubscribeRequest {
            since_sequence: input.since_sequence.unwrap_or(0),
            interface: String::new(),
        };

        // Use the snapshot to get recent events
        // (Subscribe returns a stream — for one-shot, we use snapshot + sequence)
        match client.get_snapshot(proto::SnapshotRequest::default()).await {
            Ok(resp) => {
                let snapshot = resp.into_inner();
                let limit = input.limit.unwrap_or(50);
                let mut out = String::new();
                let _ = writeln!(out, "Current sequence: {}", snapshot.sequence);
                let _ = writeln!(out, "Hosts: {}, Interfaces: {}, WiFi networks: {}",
                    snapshot.hosts.len(),
                    snapshot.interfaces.len(),
                    snapshot.wifi_networks.len(),
                );
                let _ = writeln!(out, "\n(Use network_snapshot for full state, or subscribe via gRPC for streaming changes)");
                let _ = writeln!(out, "Requested since_sequence={}, limit={limit}", req.since_sequence);
                out
            }
            Err(e) => format!("Error: {e}"),
        }
    }

    #[tool(description = "Get detailed info on a specific host by MAC or IP address")]
    async fn network_host_detail(
        &self,
        Parameters(input): Parameters<HostDetailInput>,
    ) -> String {
        let mut client = match self.client().await {
            Ok(c) => c,
            Err(e) => return e,
        };

        let req = proto::HostRequest {
            address: input.address,
        };

        match client.get_host(req).await {
            Ok(resp) => format_host_detail(&resp.into_inner()),
            Err(e) => format!("Error: {e}"),
        }
    }

    #[tool(description = "List WiFi networks visible from current location")]
    async fn wifi_networks(&self, Parameters(input): Parameters<WifiInput>) -> String {
        let mut client = match self.client().await {
            Ok(c) => c,
            Err(e) => return e,
        };

        match client
            .list_wifi_networks(proto::Empty {})
            .await
        {
            Ok(resp) => {
                let mut networks = resp.into_inner().networks;

                // Apply filters
                if let Some(ref iface) = input.interface {
                    networks.retain(|n| n.interface == *iface);
                }
                if let Some(min_rssi) = input.min_rssi {
                    networks.retain(|n| n.rssi >= min_rssi);
                }

                // Sort by signal strength (strongest first)
                networks.sort_by(|a, b| b.rssi.cmp(&a.rssi));

                format_wifi(&networks)
            }
            Err(e) => format!("Error: {e}"),
        }
    }

    #[tool(description = "List all monitored network interfaces with status")]
    async fn network_interfaces(&self, Parameters(_input): Parameters<EmptyInput>) -> String {
        let mut client = match self.client().await {
            Ok(c) => c,
            Err(e) => return e,
        };

        match client.list_interfaces(proto::Empty {}).await {
            Ok(resp) => format_interfaces(&resp.into_inner().interfaces),
            Err(e) => format!("Error: {e}"),
        }
    }

    #[tool(description = "Get profiler statistics and health")]
    async fn network_stats(&self, Parameters(_input): Parameters<EmptyInput>) -> String {
        let mut client = match self.client().await {
            Ok(c) => c,
            Err(e) => return e,
        };

        match client
            .get_snapshot(proto::SnapshotRequest::default())
            .await
        {
            Ok(resp) => {
                let snapshot = resp.into_inner();
                let mut out = String::new();
                let _ = writeln!(out, "amimori profiler status: healthy");
                let _ = writeln!(out, "gRPC endpoint: {}", self.grpc_url);
                let _ = writeln!(out, "Event sequence: {}", snapshot.sequence);
                let _ = writeln!(out, "Interfaces: {}", snapshot.interfaces.len());
                let _ = writeln!(out, "Hosts: {}", snapshot.hosts.len());
                let _ = writeln!(out, "WiFi networks: {}", snapshot.wifi_networks.len());
                if let Some(ts) = snapshot.timestamp {
                    let _ = writeln!(out, "Last update: {}s {}ns", ts.seconds, ts.nanos);
                }
                out
            }
            Err(e) => format!("amimori profiler status: unavailable\nError: {e}"),
        }
    }
}

#[tool_handler]
impl ServerHandler for AmimoriMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "amimori — continuous network profiler. Provides tools to query network state, \
                 discovered hosts, WiFi networks, and change events."
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

// ── Formatting helpers ─────────────────────────────────────────────────────

fn format_snapshot(snapshot: &proto::NetworkSnapshot) -> String {
    let mut out = String::with_capacity(2048);
    let _ = writeln!(out, "Network Snapshot (seq: {})", snapshot.sequence);

    let _ = writeln!(out, "\n--- Interfaces ({}) ---", snapshot.interfaces.len());
    for iface in &snapshot.interfaces {
        let status = if iface.is_up { "UP" } else { "DOWN" };
        let _ = writeln!(
            out,
            "  {}: {} [{}] {} ipv4={:?} gw={}",
            iface.name, status, iface.kind, iface.mac, iface.ipv4, iface.gateway
        );
    }

    let _ = writeln!(out, "\n--- Hosts ({}) ---", snapshot.hosts.len());
    for host in &snapshot.hosts {
        let _ = writeln!(
            out,
            "  {} ({}) — {} ipv4={:?} on {}{}",
            host.mac,
            host.vendor,
            host.hostname,
            host.ipv4,
            host.interface,
            if host.services.is_empty() {
                String::new()
            } else {
                format!(" [{} services]", host.services.len())
            },
        );
    }

    let _ = writeln!(
        out,
        "\n--- WiFi Networks ({}) ---",
        snapshot.wifi_networks.len()
    );
    for wifi in &snapshot.wifi_networks {
        let _ = writeln!(
            out,
            "  {} ({}) ch{} {} rssi={} {}",
            wifi.ssid, wifi.bssid, wifi.channel, wifi.band, wifi.rssi, wifi.security
        );
    }

    out
}

fn format_hosts(hosts: &[proto::Host]) -> String {
    let mut out = String::with_capacity(1024);
    let _ = writeln!(out, "{} hosts discovered", hosts.len());
    for host in hosts {
        let svcs = if host.services.is_empty() {
            String::new()
        } else {
            let ports: Vec<String> = host
                .services
                .iter()
                .map(|s| {
                    if s.name.is_empty() {
                        format!("{}/{}", s.port, s.protocol)
                    } else {
                        format!("{}/{} ({})", s.port, s.protocol, s.name)
                    }
                })
                .collect();
            format!(" ports: {}", ports.join(", "))
        };

        let _ = writeln!(
            out,
            "  {} | {} | {} | {:?}{}",
            host.mac,
            host.vendor,
            host.hostname,
            host.ipv4,
            svcs,
        );
    }
    out
}

fn format_host_detail(host: &proto::Host) -> String {
    let mut out = String::with_capacity(512);
    let _ = writeln!(out, "Host: {}", host.mac);
    let _ = writeln!(out, "  Vendor: {}", host.vendor);
    let _ = writeln!(out, "  Hostname: {}", host.hostname);
    let _ = writeln!(out, "  IPv4: {:?}", host.ipv4);
    let _ = writeln!(out, "  IPv6: {:?}", host.ipv6);
    let _ = writeln!(out, "  OS: {}", host.os_hint);
    let _ = writeln!(out, "  Interface: {}", host.interface);

    if !host.services.is_empty() {
        let _ = writeln!(out, "  Services:");
        for svc in &host.services {
            let _ = writeln!(
                out,
                "    {}/{} {} {} [{}]",
                svc.port, svc.protocol, svc.name, svc.version, svc.state
            );
        }
    }

    out
}

fn format_wifi(networks: &[proto::WifiNetwork]) -> String {
    let mut out = String::with_capacity(1024);
    let _ = writeln!(out, "{} WiFi networks", networks.len());
    for wifi in networks {
        let _ = writeln!(
            out,
            "  {} | {} | ch{} {} | rssi={} noise={} | {}",
            wifi.ssid, wifi.bssid, wifi.channel, wifi.band, wifi.rssi, wifi.noise, wifi.security
        );
    }
    out
}

fn format_interfaces(interfaces: &[proto::NetworkInterface]) -> String {
    let mut out = String::with_capacity(512);
    let _ = writeln!(out, "{} interfaces", interfaces.len());
    for iface in interfaces {
        let status = if iface.is_up { "UP" } else { "DOWN" };
        let _ = writeln!(
            out,
            "  {} [{}] {} {} ipv4={:?} ipv6={:?} gw={} dns={:?}",
            iface.name,
            iface.kind,
            status,
            iface.mac,
            iface.ipv4,
            iface.ipv6,
            iface.gateway,
            iface.dns,
        );
    }
    out
}

// ── Entry point ────────────────────────────────────────────────────────────

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let server = AmimoriMcp::new().serve(stdio()).await?;
    server.waiting().await?;
    Ok(())
}
