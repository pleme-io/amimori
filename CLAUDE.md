# amimori (網守) — Continuous Network Profiler

Persistent macOS service that continuously profiles all attached networks
(WiFi + Ethernet), tracks deltas efficiently, and exposes state via gRPC
(streaming) and MCP (for Claude/agents).

## Architecture

```
Collectors (interval-based)        State Engine            Servers
┌──────────────┐                  ┌─────────────┐       ┌──────────┐
│ ArpCollector  │─(5s)──────────▶│ DashMap     │◀─────▶│ gRPC     │
│ IfaceCollector│─(5s)──────────▶│ + Delta Log │       │ :50051   │
│ WifiCollector │─(15s, macOS)──▶│ + SQLite    │       ├──────────┤
│ NmapCollector │─(60s)─────────▶│             │       │ MCP      │
└──────────────┘                  └─────────────┘       │ (stdio)  │
                                                         └──────────┘
```

## Modes

- **daemon** — persistent service with collectors + gRPC server + SQLite
- **mcp** — MCP server (default when no args), queries daemon via gRPC
- **scan** — one-shot scan, prints JSON to stdout
- **status** — check if daemon is running via gRPC health check

## Key Design Decisions

1. No tsunagu — launchd handles lifecycle (KeepAlive/RunAtLoad)
2. No passive BPF in MVP — `arp -a` polling (no root needed)
3. CoreWLAN for WiFi — `objc2-core-wlan`, macOS-only behind `#[cfg]`
4. nmap via shell-out — `tokio::process::Command`
5. gRPC streaming — tonic server-side streaming for Subscribe
6. SQLite via SeaORM — full Sea stack (entities, migrations, query builder)

## Dependencies

- **shikumi** — config discovery, hot-reload, env override
- **kaname** — MCP server framework (rmcp 0.15)
- **sea-orm** — SQLite ORM with migrations
- **tonic/prost** — gRPC server + proto codegen
- **dashmap** — concurrent in-memory state
- **network-interface** — interface enumeration (no root)
- **objc2-core-wlan** — WiFi scanning (macOS only)
- **mac_oui** — MAC address vendor lookup

## Config

```yaml
# ~/.config/amimori/amimori.yaml
interfaces: [en0, en4]
grpc_port: 50051
arp_interval: 5
interface_interval: 5
wifi_interval: 15
scan_interval: 60
db_path: ~/.local/share/amimori/state.db
event_buffer_size: 10000
nmap:
  enable: true
  bin: nmap
  service_detection: false
```

## MCP Tools (7)

| Tool | Description |
|------|-------------|
| network_snapshot | Full snapshot of all profiled networks |
| network_hosts | List discovered hosts with filters |
| network_changes | Recent network change events |
| network_host_detail | Detailed host info by MAC or IP |
| wifi_networks | Visible WiFi networks |
| network_interfaces | All monitored interfaces with status |
| network_stats | Profiler health and statistics |

## Building

```bash
cargo build                    # debug build
cargo run -- scan              # one-shot scan
cargo run -- daemon --config amimori.yaml
cargo run -- status            # check daemon
nix build                     # via substrate
```

## File Structure

```
src/
├── main.rs              # clap dispatch: daemon | mcp | scan | status
├── config.rs            # shikumi YAML config
├── daemon.rs            # orchestrate collectors + gRPC server
├── state.rs             # DashMap + event log + delta engine
├── db/
│   ├── mod.rs           # SeaORM database layer
│   ├── entity/          # SeaORM entities (host, service, interface, wifi)
│   └── migration/       # SeaORM migrations
├── model.rs             # Core types: Host, Service, WiFi, Interface, Delta
├── collector/
│   ├── mod.rs           # Collector trait + scheduler
│   ├── arp.rs           # parse `arp -a`
│   ├── interface.rs     # network-interface + netstat + scutil
│   ├── wifi.rs          # CoreWLAN (macOS only)
│   └── scanner.rs       # nmap shell-out
├── grpc.rs              # tonic server + proto types
└── mcp.rs               # rmcp MCP server (7 tools)
```
