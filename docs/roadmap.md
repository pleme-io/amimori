# Roadmap — Best-in-Class Network Profiling

Informed by competitive analysis of runZero, Shodan, Nmap NSE, p0f, Zeek, and NetBox.
See `docs/architecture.md` for existing ADRs.

## Current State

amimori has solid foundations: reactive actor-based collectors, DashMap concurrent
state, three-tier event system, progressive enrichment, and structural MAC filtering.
But the data it collects is shallow compared to best-in-class tools.

## Gap Analysis (vs competitive landscape)

| Capability | runZero | Shodan | amimori | Priority |
|-----------|---------|--------|---------|----------|
| ARP/L2 discovery | yes (arp-scan) | n/a | yes (arp -a) | upgrade to active ARP |
| Service version detection | yes | yes (banner) | config exists, nmap -sV | working |
| OS fingerprinting | yes + confidence | yes | config exists, nmap -O | working |
| Structured fingerprints | fp.os.certainty | protocol objects | flat strings | **P1** |
| Passive TCP fingerprinting | no | no | no | P2 |
| TLS certificate analysis | yes | yes (full chain) | no | **P1** |
| mDNS/Bonjour discovery | yes | no | no | **P1** |
| DHCP fingerprinting | yes | no | no | P2 |
| Banner grabbing | yes | yes (primary data) | no | **P1** |
| CPE identifiers | yes | yes | no | P2 |
| Outlier/anomaly scoring | yes (0-5) | no | no | P3 |
| Event sourcing | snapshot diffs | banner-centric | timeline table | enhance |
| Probe classification (safe/intrusive) | implicit | n/a | no | P2 |
| Correlation by multi-attribute | MAC+hostname+IP | IP+banner | MAC only | P2 |
| Webhook/event output | NetBox pattern | firehose API | gRPC stream | P3 |

## Phase 1: Structured Fingerprints + Enrichment Pipeline

### Fingerprint Schema (inspired by runZero)

Replace flat `os_hint: Option<String>` with structured fingerprints:

```rust
pub struct Fingerprint {
    pub source: FingerprintSource,  // arp, nmap, mdns, tls, passive
    pub category: &'static str,     // "os", "hw", "sw", "net"
    pub key: String,                // "os.name", "hw.vendor", "tls.cn"
    pub value: String,              // "macOS 15.2", "Apple Inc.", "*.example.com"
    pub confidence: f32,            // 0.0 - 1.0
    pub timestamp: DateTime<Utc>,
}
```

Every enrichment source produces fingerprints. The state engine merges them
by (category, key) — higher confidence wins, ties broken by recency.

### Enrichment Pipeline (inspired by Nmap NSE + runZero)

```
Phase 1: ARP discovery (5s)        → MAC, IP, hostname (from arp table)
Phase 2: Interface polling (5s)    → gateway, DNS, subnet, link type
Phase 3: mDNS probe (15s)         → Bonjour service names, device model
Phase 4: Port scan (60s)          → open ports, service names
Phase 5: Banner grab (on new svc) → raw banner text, version strings
Phase 6: TLS cert (on TLS ports)  → CN, SAN, issuer, expiry, cipher
Phase 7: OS fingerprint (60s)     → nmap -O confidence, TCP stack analysis
```

Each phase is a separate collector with its own interval and trigger.
Later phases only target hosts discovered by earlier phases.

### mDNS Discovery

mDNS (port 5353, multicast 224.0.0.251) is the richest passive discovery
source on local networks. Apple devices, printers, Chromecasts, and smart
home devices all advertise via mDNS/Bonjour.

Data available without any active probing:
- Device model (e.g., "MacBook Pro 16-inch")
- Service types (_http._tcp, _airplay._tcp, _printer._tcp)
- Hostname (FQDN)
- IP address
- TXT records (firmware version, capabilities)

Implementation: listen on multicast, parse DNS-SD responses.

### Banner Grabbing

For each open port discovered by nmap, connect and read the service banner:
- TCP connect → read first 1024 bytes (SSH, SMTP, FTP banners)
- HTTP GET / → response headers + server string
- TLS → certificate chain

This is separate from nmap -sV (which probes actively). Banner grabbing
is passive once the connection is established.

### TLS Certificate Collection

For every port with TLS (443, 8443, 993, 995, etc.):
- Connect, negotiate TLS, extract certificate
- Store: subject CN, SANs, issuer, validity dates, key type/size, cipher suite
- Certificates reveal: org name, internal hostnames, software identity, security posture

## Phase 2: Passive Fingerprinting + Classification

### TCP Stack Fingerprinting (p0f pattern)

Analyze TCP SYN packets observed on the network (requires raw socket or pcap):
- Initial TTL, TCP window size, MSS, option order, DF bit
- These fingerprint the OS without any active probing
- p0f signature database for matching

### DHCP Fingerprinting

DHCP requests contain device-identifying fields:
- Option 55 (Parameter Request List) — unique per OS/device type
- Option 60 (Vendor Class Identifier) — "MSFT 5.0", "android-dhcp-13"
- Option 12 (Hostname)
- Fingerbank database for matching

### Probe Classification (Nmap NSE pattern)

Every enrichment technique gets a safety classification:

| Level | Name | Examples |
|-------|------|---------|
| 0 | passive | ARP table read, mDNS listen, DHCP observe |
| 1 | safe | TCP connect, TLS handshake, banner read |
| 2 | discovery | nmap -sV, HTTP GET, SMB negotiate |
| 3 | intrusive | nmap -O, SNMP walk, brute force |

Config: `collectors.max_probe_level: 2` — only run probes at or below this level.

## Phase 3: Intelligence Layer

### Outlier Scoring (runZero pattern)

Score each host 0-5 based on how unusual it is:
- New device type never seen before on this network → +2
- Unusual open ports for its vendor class → +1
- Different OS than other devices from same vendor → +1
- High port count relative to network average → +1

### CPE Identification

Map observed service/version strings to CPE 2.3 identifiers:
- `cpe:2.3:o:apple:macos:15.2:*:*:*:*:*:*:*`
- `cpe:2.3:a:openssh:openssh:9.6:*:*:*:*:*:*:*`

Enables integration with vulnerability databases (NVD, CVE).

### Multi-Attribute Correlation (runZero pattern)

Current: host identity = MAC address only.
Better: identity = f(MAC, hostname, fingerprints, IP pattern).

When a device gets a new MAC (WiFi randomization), maintain identity if
enough other attributes match. When a MAC appears with completely different
characteristics, create a new host rather than overwriting.

## Implementation Priority

1. **Structured fingerprints** — data model foundation, everything builds on this
2. **mDNS discovery** — highest value passive enrichment, zero active probing
3. **Banner grabbing** — connect to open ports, read service banners
4. **TLS certificate collection** — rich metadata from every HTTPS service
5. **Probe classification** — safety framework before adding intrusive probes
6. **TCP passive fingerprinting** — OS detection without active scanning
7. **DHCP fingerprinting** — device classification from DHCP traffic
8. **Outlier scoring** — anomaly detection for security monitoring
9. **CPE mapping** — vulnerability correlation
10. **Multi-attribute correlation** — survive MAC randomization
