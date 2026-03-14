# amimori (網守) — Continuous Network Profiler

Persistent macOS/Linux service that continuously profiles all attached networks
(WiFi + Ethernet), tracks deltas efficiently, and exposes state via gRPC
(streaming) and MCP (for Claude/agents).

## Architecture

```
Collectors (configurable intervals)   State Engine             Servers
┌──────────────────────────────┐     ┌──────────────────┐    ┌──────────┐
│ ArpCollector     (5s)        │────▶│ DashMap state     │◀──▶│ gRPC     │
│ InterfaceCollector (5s)      │────▶│ Delta ring buffer │    │ (config) │
│ WifiCollector    (15s, macOS)│────▶│ SQLite (SeaORM)   │    ├──────────┤
│ NmapCollector    (60s, opt)  │────▶│ OUI vendor lookup │    │ MCP      │
└──────────────────────────────┘     │ Filter engine     │    │ (stdio)  │
  ↑ auto-disable on max_failures    │ Stale host pruner │    └──────────┘
  ↑ configurable per-collector       └──────────────────┘
```

## Modes

| Mode | Description |
|------|-------------|
| `daemon` | Persistent service: collectors + gRPC + SQLite + pruner |
| `mcp` | MCP server (default), queries daemon via gRPC |
| `scan` | One-shot scan, JSON to stdout |
| `status` | Query daemon health via gRPC |

## Configuration

Nested YAML config via shikumi. Every aspect is configurable:

```yaml
# ~/.config/amimori/amimori.yaml
interfaces: [en0, en4]  # empty = auto-detect all non-loopback

grpc:
  address: "127.0.0.1"
  port: 50051

collectors:
  arp:
    enable: true
    interval: 5          # seconds
    max_failures: 10     # auto-disable after N consecutive failures
  interface:
    enable: true
    interval: 5
    max_failures: 10
  wifi:
    enable: true
    interval: 15
    max_failures: 10
  nmap:
    enable: true
    interval: 60
    bin: nmap
    timeout: 120         # kill nmap after this many seconds
    service_detection: false
    subnets: []          # empty = auto-derive from active interfaces
    max_failures: 3

storage:
  db_path: ~/.local/share/amimori/state.db
  event_buffer_size: 10000
  retention:
    host_ttl: 86400      # prune hosts not seen for 24h (0 = keep forever)
    prune_interval: 300  # run pruner every 5 min

filters:
  exclude_macs: []         # MAC addresses to never track
  exclude_ips: []          # IPs to never track
  exclude_interfaces: []   # interfaces to ignore
  include_vendors: []      # if non-empty, only track these vendors

logging:
  level: info              # trace, debug, info, warn, error
  format: text             # text or json
```

Environment variables override config: `AMIMORI_GRPC__PORT=50052`, `AMIMORI_CONFIG=/path`.

## Key Design

- **Per-collector lifecycle**: Each collector tracks consecutive failures and auto-disables after `max_failures`. Recovery resets the counter.
- **Filter engine**: MAC/IP/interface exclusion + vendor inclusion applied at the state engine level, before persistence.
- **Stale host pruning**: Background task removes hosts not seen within `host_ttl`.
- **Subnet auto-discovery**: nmap derives CIDRs from active interface addresses instead of hardcoded subnets.
- **nmap timeout**: `tokio::time::timeout` kills hung scans.
- **nmap capability detection**: Checks `nmap --version` at startup; disables scanner if not found.
- **Robust XML parsing**: `quick-xml` for nmap output instead of hand-rolled string ops.
- **Structured logging**: JSON format option for log aggregation.

## Dependencies

| Crate | Purpose |
|-------|---------|
| shikumi | Config discovery, hot-reload, env override |
| kaname/rmcp | MCP server framework |
| sea-orm | SQLite ORM with migrations |
| tonic/prost | gRPC server + proto codegen |
| dashmap | Concurrent in-memory state |
| quick-xml | Robust nmap XML parsing |
| network-interface | Interface enumeration |
| objc2-core-wlan | WiFi scanning (macOS) |
| mac_oui | MAC vendor lookup |
| thiserror | Error types |

## MCP Tools (7)

| Tool | Description |
|------|-------------|
| `network_snapshot` | Full snapshot — interfaces, hosts, WiFi |
| `network_hosts` | List hosts with interface/vendor/port filters |
| `network_changes` | Recent delta events |
| `network_host_detail` | Detailed host info by MAC or IP |
| `wifi_networks` | Visible WiFi sorted by signal, with security/RSSI filter |
| `network_interfaces` | All interfaces with IP, gateway, DNS, status |
| `network_stats` | Daemon health and statistics |

## File Structure

```
src/
├── main.rs              # clap: daemon | mcp | scan | status
├── config.rs            # nested config with validation
├── daemon.rs            # orchestrate collectors + gRPC + pruner
├── state.rs             # DashMap + delta engine + filters + pruning
├── model.rs             # domain types, MAC utils, serde
├── db/
│   ├── mod.rs           # SeaORM CRUD layer
│   ├── entity/          # host, service, interface, wifi entities
│   └── migration/       # schema migrations
├── collector/
│   ├── mod.rs           # trait + scheduler with failure tracking
│   ├── arp.rs           # parse arp -a
│   ├── interface.rs     # network-interface + netstat + scutil
│   ├── wifi.rs          # CoreWLAN (macOS, #[cfg])
│   └── scanner.rs       # nmap with quick-xml, timeout, auto-subnets
├── grpc.rs              # tonic server, configurable bind
└── mcp.rs               # 7 MCP tools via rmcp
```
