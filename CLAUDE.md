# amimori (網守) — Continuous Network Profiler

Persistent macOS/Linux service that continuously profiles all attached networks
(WiFi + Ethernet), tracks deltas efficiently, and exposes state via gRPC
(streaming) and MCP (for Claude/agents).

## Architecture

See [docs/architecture.md](docs/architecture.md) for detailed ADRs.
See [docs/data-model.md](docs/data-model.md) for entity relationships and host lifecycle.

```
Collectors (per-actor scheduling)    State Engine                 Servers
┌──────────────────────────────┐    ┌────────────────────────┐   ┌──────────┐
│ ArpCollector     (5s, react) │───▶│ NetworkState (DashMap)  │◀─▶│ gRPC     │
│ InterfaceCollector (5s)      │───▶│ insert_host() gate      │   │ GetChanges│
│ WifiCollector    (15s, macOS)│───▶│ Progressive enrichment  │   │ Subscribe│
│ NmapCollector    (60s, react)│───▶│ Service change detection│   ├──────────┤
└──────────────────────────────┘    │ Event timeline (3-tier) │   │ MCP      │
  ↑ reactive triggers (event bus)   │ SQLite (SeaORM)         │   │ (stdio)  │
  ↑ auto-disable on max_failures    │ OUI vendor lookup       │   └──────────┘
  ↑ configurable per-collector      │ Filter engine           │
                                    │ Stale host/event pruner │
                                    └────────────────────────┘
```

### Three-Tier Event System (ADR-001)

1. **Durable** — `events` table in SQLite (append-only, survives restarts)
2. **Fast** — In-memory ring buffer (bounded, serves GetChanges RPC)
3. **Real-time** — broadcast channel (streams to gRPC Subscribe)

### Key Invariants

- **MAC gate**: `NetworkState::insert_host()` rejects broadcast, multicast, zero,
  and self MACs. All host insertions go through this single gate. (ADR-002)
- **Progressive enrichment**: hostname/OS only overwritten with richer data.
  Services tracked with add/remove detection. (ADR-004)
- **normalize_mac**: returns `Option<String>`, validates AND normalizes. Every
  MAC in the system passed through it. (ADR-005)

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
interfaces: [en0]  # empty = auto-detect all non-loopback

grpc:
  address: "127.0.0.1"
  port: 50051

collectors:
  arp:
    enable: true
    interval: 5          # seconds
    max_failures: 10     # auto-disable after N consecutive failures
    reactive: true       # re-run on network changes
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
    service_detection: true   # -sV (version probes)
    os_detection: true        # -O --osscan-guess (requires root)
    top_ports: 200            # --top-ports N
    version_intensity: 7      # 0-9 probe depth
    subnets: []          # empty = auto-derive from active interfaces
    max_failures: 3
    reactive: true       # re-run on network changes
    reactive_cooldown: 5

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

## Trait Boundaries (ADR-007)

Every external dependency is behind a trait for testability:

| Trait | Real Impl | Mock | Used By |
|-------|-----------|------|---------|
| `StorageBackend` | `Database` (SeaORM/SQLite) | `InMemoryStorage` | StateEngine |
| `VendorLookup` | `OuiVendorLookup` (mac_oui) | `MockVendorLookup` | StateEngine |
| `CommandRunner` | `SystemCommandRunner` | `MockCommandRunner` | (TODO: collectors) |

**Gaps to close:**
- Collectors call `tokio::process::Command` directly — should use `CommandRunner`
- No trait for time source — prevents deterministic pruning tests
- WiFi collector uses CoreWLAN directly — platform-specific, no trait
- `platform::system_bin()` is a function, not a trait — works for now

## Dependencies

| Crate | Purpose |
|-------|---------|
| shikumi | Config discovery, env override |
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
| `network_changes` | Recent delta events from GetChanges RPC |
| `network_host_detail` | Detailed host info by MAC or IP |
| `wifi_networks` | Visible WiFi sorted by signal, with security/RSSI filter |
| `network_interfaces` | All interfaces with IP, gateway, DNS, status |
| `network_stats` | Daemon health and statistics |

## gRPC API

| RPC | Type | Description |
|-----|------|-------------|
| `GetSnapshot` | Unary | Full network state with optional interface filter |
| `GetChanges` | Unary | Buffered delta events since a sequence number |
| `Subscribe` | Server stream | Live delta events (replay + stream) |
| `GetHost` | Unary | Host detail by MAC or IP |
| `ListInterfaces` | Unary | All monitored interfaces |
| `ListWifiNetworks` | Unary | All visible WiFi networks |

## File Structure

```
src/
├── main.rs              # clap: daemon | mcp | scan | status
├── config.rs            # nested config with validation
├── daemon.rs            # orchestrate collectors + gRPC + pruner
├── state.rs             # DashMap + delta engine + filters + pruning + emit
├── model.rs             # domain types, MAC gate, serde
├── platform.rs          # system binary resolution (ADR-003)
├── error.rs             # error types
├── event_bus.rs         # trigger events for reactive scheduling
├── traits.rs            # trait boundaries + mocks (ADR-007)
├── db/
│   ├── mod.rs           # SeaORM CRUD + event timeline
│   ├── entity/          # host, service, interface, wifi, event entities
│   └── migration/       # 3 migrations: tables, network_id, event_log
├── collector/
│   ├── mod.rs           # Collector trait + actor scheduler (ADR-006)
│   ├── arp.rs           # parse arp -a (via platform::system_bin)
│   ├── interface.rs     # network-interface + netstat + scutil
│   ├── wifi.rs          # CoreWLAN (macOS, #[cfg])
│   └── scanner.rs       # nmap with deep fingerprinting (ADR-008)
├── grpc.rs              # tonic server + proto conversions
├── mcp.rs               # 7 MCP tools via rmcp
docs/
├── architecture.md      # ADR decisions
└── data-model.md        # entity relationships, host lifecycle, event types
proto/
└── amimori.proto        # gRPC service definition
module/
├── default.nix          # HM module (MCP server entry)
├── darwin/default.nix   # nix-darwin module (launchd daemon)
└── nixos/default.nix    # NixOS module (systemd service)
```

## Building

```bash
# Development (needs protoc)
PROTOC=$(nix build nixpkgs#protobuf --print-out-paths --no-link)/bin/protoc cargo build

# Tests (210+)
PROTOC=... cargo test

# Nix build (production, cross-compiled)
nix build
```

## Platform Notes

- **macOS WiFi SSID**: CoreWLAN requires Location Services entitlement to return
  SSIDs. The daemon binary from Nix doesn't have Apple entitlements, so SSIDs
  appear empty. Connected network info may still work for root daemons.
- **macOS system binaries**: `arp`, `netstat`, `scutil` live at `/usr/sbin/`.
  The `platform::system_bin()` layer resolves these. launchd daemons have
  minimal PATH (only nix store paths).
- **nmap -O**: requires root. The daemon runs as root via launchd/systemd.
  If run as non-root user, `-O` causes nmap to exit with error. The scanner
  handles this gracefully.
