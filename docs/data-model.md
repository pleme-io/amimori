# Data Model

## Entity Relationships

```
NetworkState (in-memory, DashMap)
├── interfaces: {name → InterfaceInfo}
│   └── network_id() = "{gateway}|{subnet}"
├── hosts: {mac → HostInfo}          ← insert_host() enforces MAC validity
│   ├── services: [ServiceInfo]
│   ├── first_seen / last_seen
│   └── network_id (bound to interface at discovery time)
├── wifi_networks: {bssid → WifiInfo}
└── sequence: AtomicU64 (monotonic event counter)

SQLite (durable, SeaORM)
├── hosts           ← same fields, JSON-encoded IP arrays
├── services        ← FK to hosts(mac), CASCADE delete
├── interfaces      ← current state only
├── wifi_networks   ← current state only
└── events          ← append-only timeline (ADR-001)
    ├── sequence, timestamp
    ├── event_type (indexed discriminant)
    ├── subject_mac, subject_name (indexed)
    └── change_json (full Change enum as JSON)
```

## Host Lifecycle

```
                ARP discovers MAC+IP
                       │
                       ▼
              ┌─── HostAdded ───┐
              │  first_seen=now │
              │  last_seen=now  │
              └────────┬────────┘
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
   ARP update     nmap enriches   nmap finds
   (new IP)       (services, OS)  closed port
        │              │              │
        ▼              ▼              ▼
   HostUpdated    HostUpdated +   HostUpdated +
   (addresses     ServiceChanged  ServiceChanged
    extended)     (Added)         (Removed)
        │              │              │
        └──────────────┼──────────────┘
                       │
              host_ttl expires
                       │
                       ▼
              ┌── HostRemoved ──┐
              │  pruner deletes │
              │  from memory    │
              │  + database     │
              └─────────────────┘
```

## Progressive Enrichment (ADR-004)

Each collector contributes what it can. The state engine merges progressively:

| Source | MAC | IP | Hostname | OS | Services | Vendor |
|--------|-----|-----|----------|-----|----------|--------|
| ARP    | yes | yes | partial  | no  | no       | no     |
| nmap   | yes | yes | FQDN     | yes | yes      | no     |
| OUI    | -   | -   | -        | -   | -        | yes    |

Merge rules:
- **IP addresses**: union (both sources contribute)
- **Hostname**: longer string wins (FQDN > short name > empty)
- **OS hint**: longer string wins
- **Services**: set union on (port, protocol) key; removed if absent in nmap scan
- **Vendor**: set once from OUI lookup, never overwritten

## MAC Address Invariants

Every MAC in `NetworkState.hosts` has passed through `normalize_mac()`:
- Lowercase, colon-separated, zero-padded: `"0a:0b:0c:0d:0e:0f"`
- 6 octets, all hex characters
- Not broadcast (`ff:ff:ff:ff:ff:ff`)
- Not zero (`00:00:00:00:00:00`)
- Not multicast (first octet group bit = 0)
- Not a monitored interface's own MAC

## Event Types

| event_type | subject_mac | subject_name | Trigger |
|------------|-------------|--------------|---------|
| host_added | MAC | hostname | ARP/nmap discovers new host |
| host_removed | MAC | | pruner TTL or network transition |
| host_updated | MAC | hostname | IP/hostname/OS change |
| service_added | MAC | port/proto | nmap finds new open port |
| service_removed | MAC | port/proto | nmap finds port closed |
| service_updated | MAC | port/proto | version or state change |
| wifi_added | BSSID | SSID | new WiFi network seen |
| wifi_removed | BSSID | | WiFi network disappeared |
| wifi_updated | BSSID | SSID | RSSI/channel/security change |
| interface_changed | | interface name | IP/gateway/status change |
| network_changed | | interface name | gateway+subnet fingerprint changed |
