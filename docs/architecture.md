# Architecture Decisions

This document records the architectural decisions in amimori. Each decision
includes the context, the choice made, and the reasoning. New code should
follow these patterns — if you disagree, update the decision first.

## ADR-001: Three-Tier Event System

**Context:** Network state changes need to be available for real-time streaming
(gRPC Subscribe), fast unary queries (GetChanges RPC), and historical analysis
(what happened last week?).

**Decision:** Events flow through three tiers:
1. **Durable** — `emit()` appends every `DeltaEvent` to the SQLite `events` table.
   Survives daemon restarts. Pruned on the same schedule as stale hosts.
2. **Fast** — In-memory `VecDeque` ring buffer serves `GetChanges` RPC. Bounded
   by `storage.event_buffer_size`. Lost on restart (rebuilt from live collectors).
3. **Real-time** — `tokio::sync::broadcast` channel fans out to active gRPC
   `Subscribe` streams. Zero-copy for connected clients.

**Consequence:** Event persistence adds ~1 SQLite write per state change. At
typical collector rates (ARP every 5s, nmap every 60s, ~20 hosts), this is
<50 writes/minute. SQLite WAL handles this trivially.

## ADR-002: Structural MAC Filtering at NetworkState Boundary

**Context:** Broadcast (`ff:ff:ff:ff:ff:ff`), multicast (`01:00:5e:*`), and
self MACs were polluting the host table. Multiple callers (ARP apply, nmap apply,
DB restore) each needed to remember to filter.

**Decision:** `NetworkState::insert_host()` is the single gate for all host
insertions. It rejects non-host MACs (via `is_non_host_mac()`) and self MACs
(via `is_self_mac()`). Callers use `insert_host()` instead of raw `DashMap::insert()`.

**Consequence:** The host table structurally cannot contain non-unicast MACs.
New callers get filtering for free. Tests that need to insert specific MACs
for setup can still use raw `DashMap::insert()` directly.

## ADR-003: Platform Binary Resolution Layer

**Context:** macOS launchd daemons run with a minimal PATH (only nix store
paths). System binaries like `arp`, `netstat`, `scutil` live at `/usr/sbin/`
and silently fail when called by bare name.

**Decision:** `platform::system_bin(name)` resolves system binary paths.
All collectors and daemon preflight checks use this instead of bare names.
One file to update when adding Linux/BSD support.

**Consequence:** Adding a new platform means updating one match arm in
`platform.rs`. No collector code needs to change.

## ADR-004: Progressive Delta Patching for Host Enrichment

**Context:** Multiple collectors discover overlapping data about the same host.
ARP finds the host first (MAC + IP + maybe hostname). nmap adds services,
OS fingerprint, and sometimes a better hostname. Neither should clobber the other.

**Decision:** State engine merges progressively — fields are only overwritten
when the new value is richer (longer string for hostname/os_hint, union for
IP addresses, append-only for new services, retain-based removal for closed ports).

**Consequence:** Host data quality improves monotonically over time. ARP
provides fast initial discovery, nmap enriches with depth. The host's
`first_seen` is never overwritten; `last_seen` always advances.

## ADR-005: normalize_mac as Universal Validation Gate

**Context:** MAC addresses enter the system from ARP output, nmap XML, and
database restore. Invalid, broadcast, and multicast MACs need consistent
rejection at every entry point.

**Decision:** `normalize_mac()` returns `Option<String>` — it normalizes AND
validates in one call. Rejects non-hex chars, wrong octet count, broadcast,
multicast (group bit), and zero MACs. All callers use `let Some(mac) = normalize_mac(...) else { continue }`.

**Consequence:** No separate validation step needed. The type system enforces
that every MAC in the system passed through normalization. Tests use known-good
unicast MACs (even first octet).

## ADR-006: Reactive + Interval Collector Scheduling

**Context:** Some collectors benefit from immediate re-runs when the network
changes (ARP should re-scan after a network transition), while others should
only run on fixed intervals (interface polling).

**Decision:** The actor system supports two scheduling modes per collector:
- **Interval-only**: tick every N seconds (interface, wifi)
- **Reactive + interval**: listen for `TriggerEvent` from the event bus, run
  immediately with debounce cooldown, reset interval timer after reactive run
  to prevent double-scanning

**Consequence:** Network transitions trigger immediate ARP + nmap re-scans.
The cooldown prevents thundering herd on rapid network flapping.

## ADR-007: Trait Boundaries for External Dependencies

**Context:** Business logic in the state engine depends on database, vendor
lookup, and (future) system commands. These must be mockable for unit testing.

**Decision:** Every external boundary has a trait:
- `StorageBackend` — database CRUD + event persistence
- `VendorLookup` — MAC → vendor name
- `CommandRunner` — system command execution (defined but not yet used by collectors)

Mock implementations live in `traits::mocks` behind `#[cfg(test)]`.

**Gaps (TODO):**
- Collectors still use `tokio::process::Command` directly instead of `CommandRunner`
- No trait for time source (prevents deterministic time-based tests)
- WiFi collector uses CoreWLAN directly (platform-specific, hard to mock)

## ADR-008: Deep Fingerprinting via nmap Configuration

**Context:** Basic `-sn` ping scans discover hosts but provide no service or
OS information. `-sV` adds service detection. `-O` adds OS fingerprinting.
These are progressively more expensive.

**Decision:** nmap scanning is fully configurable:
- `service_detection`: enables `-sV` (default: true in Nix module)
- `os_detection`: enables `-O --osscan-guess` (default: true, requires root)
- `top_ports`: number of ports to scan (default: 200)
- `version_intensity`: probe depth 0-9 (default: 7)

The Nix module defaults to full fingerprinting. The daemon runs as root via
launchd/systemd so `-O` works.

**Consequence:** Every host progressively accumulates service + OS data.
The state engine's delta patching ensures richer data replaces weaker data
without clobbering.

## ADR-010: Non-Blocking Event Broadcast

**Context:** The state engine emitted events to gRPC subscribers via
`Vec<mpsc::Sender>`. If any subscriber was slow or hung, the `emit()`
call blocked, stalling all state updates for all clients.

**Decision:** Replace `Vec<mpsc::Sender>` with `tokio::sync::broadcast::Sender`.
Broadcast is non-blocking — if a receiver is slow, it falls behind and gets
`RecvError::Lagged(n)`. The gRPC Subscribe handler logs lagged events and
continues. Clients can catch up via the `GetChanges` RPC.

**Consequence:** No single client can stall the state engine. The broadcast
channel capacity is `storage.event_buffer_size` (default 10,000). Clients
that fall behind lose events but never block other clients.

## ADR-011: IP→MAC Reverse Index

**Context:** `get_host(addr)` accepted both MAC and IP but IP lookup was
O(n) — linear scan over all hosts checking `addresses.contains(&ip)`.
With 10,000 hosts this is measurable latency on every gRPC query.

**Decision:** `NetworkState` maintains a `DashMap<IpAddr, String>` reverse
index. `insert_host()` updates it automatically. Host removal cleans it.
`get_host()` tries MAC first, then IP index — both O(1).

**Consequence:** IP lookups are constant time. The index adds ~40 bytes per
IP address (IpAddr + String MAC key). For 10,000 hosts with 1-2 IPs each,
this is ~400-800 KB — trivial.

## ADR-015: Network Convergence Detection

**Context:** After starting the daemon, how do you know when the network
scan is "done" — when it's safe to analyze results vs still discovering?
Networks also change over time, so convergence is not permanent.

**Decision:** `ConvergenceTracker` computes a 0.0-1.0 score from 5 weighted
factors: time since last new host (30%), time since last new service (25%),
stable ARP cycles (20%), stable nmap cycles (15%), collector coverage (10%).

Four phases: Discovering → Enriching → NearConverged → Converged.

The tracker auto-resets on network transitions (gateway/subnet change).
New host discoveries drop the score immediately (de-convergence).

**Consequence:** MCP and gRPC clients can poll `network_convergence` /
`GetConvergence` to determine when analysis is meaningful. Automation
can wait for convergence before running reports.

## ADR-009: DNS Deduplication at Parse Time

**Context:** macOS `scutil --dns` lists dozens of resolver stanzas for the
same interface (dnsmasq, mDNS, scoped queries), each with `127.0.0.1`.
Without dedup, interfaces showed 90+ duplicate DNS entries.

**Decision:** `parse_scutil_dns()` deduplicates per-interface server lists
at parse time using `Vec::contains()`. Preserves insertion order (first seen wins).

**Consequence:** DNS output is clean and concise. Scutil changes don't require
re-visiting the dedup logic — it's structural in the parser.
