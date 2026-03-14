# Roadmap — Best-in-Class Network Profiling

Informed by competitive analysis of runZero, Shodan, Nmap NSE, p0f, Zeek,
NetBox, LibreNMS, ntopng, Fing, and Lansweeper.

## Completed (Phase 1)

| # | Item | Collector | Probe Level |
|---|------|-----------|-------------|
| 1 | Structured fingerprints | model.rs | — |
| 2 | mDNS/Bonjour discovery | mdns.rs | Passive |
| 3 | Banner grabbing | banner.rs | Safe |
| 4 | TLS certificate collection | tls.rs | Safe |
| 5 | Probe classification framework | model.rs + config.rs | — |
| 6 | Passive TCP fingerprinting | passive.rs | Passive |
| 7 | DHCP fingerprinting (via capture) | passive.rs | Passive |
| 8 | Outlier scoring | model.rs | — |
| 9 | CPE mapping | enrichment.rs | — |
| 10 | Multi-attribute correlation | enrichment.rs | — |

## Phase 2: Quick Wins (est. 20-30h)

High value-to-effort ratio. Each item completes a capability gap.

### 2.1 Active ARP Scanning

**Priority: CRITICAL.** Current ARP table read misses 50-80% of hosts.
Active scanning sends ARP requests for every IP in the subnet — hosts MUST
respond (ARP is not optional at Layer 2). Completes a /24 in 2-3 seconds.
Cannot be blocked by firewalls.

- **Data:** MAC, IP for every live host on the subnet
- **Probe level:** Discovery (sends ARP requests)
- **Approach:** `pnet` raw sockets, send ARP request per IP, collect responses
- **Effort:** 8-12h
- **Competitive value:** Table stakes — every serious scanner does this

### 2.2 Reverse DNS (PTR Records)

**Priority: HIGH.** For every discovered IP, query the PTR record. Often
reveals descriptive hostnames like `printer-3rd-floor.company.com` or
`ap-lobby.company.com`. Trivial to implement, enriches every host.

- **Data:** IP → hostname mapping via DNS
- **Probe level:** Discovery (standard DNS queries)
- **Approach:** `hickory-dns` async resolver, batch PTR queries
- **Effort:** 4-6h
- **Competitive value:** Table stakes

### 2.3 Wake-on-LAN

Send magic packets to wake sleeping devices. Track power state over time.

- **Data:** Device power state (online/offline/sleeping)
- **Probe level:** Management (changes device state)
- **Approach:** `wake-on-lan` crate, UDP broadcast of magic packet
- **Effort:** 4-6h
- **Competitive value:** Nice-to-have (Fing has this)

### 2.4 DNS-SD SRV Enumeration

Complement mDNS with DNS-based Service Discovery queries to enterprise
DNS servers. Finds services registered outside the .local domain.

- **Data:** Service instances, ports, hostnames
- **Probe level:** Discovery (DNS queries)
- **Approach:** `hickory-dns` SRV queries
- **Effort:** 4-6h
- **Competitive value:** Table stakes (alongside mDNS)

## Phase 3: Consumer Differentiation (est. 30-40h)

Features that make amimori stand out for home/SOHO users.

### 3.1 UPnP/SSDP Discovery

Find smart TVs, gaming consoles, Chromecast, Sonos, smart home hubs,
and NAS devices that don't respond to port scanning. Passive (NOTIFY
listen) or active (M-SEARCH). Fetches device description XML for
manufacturer, model, firmware, serial, and service list.

- **Data:** Device type, manufacturer, model, serial, firmware, services
- **Probe level:** Passive (NOTIFY) or Discovery (M-SEARCH)
- **Crates:** `ssdp-client` (async, well-maintained), `rupnp` (full UPnP)
- **Effort:** 8-12h
- **Competitive value:** Differentiating — few scanners outside Fing do this

### 3.2 Container/VM Detection

Classify hosts as physical, VM, or container based on MAC ranges,
open ports, and API probes:

| Platform | MAC prefix | Probe port |
|----------|-----------|------------|
| VMware | 00:0C:29, 00:50:56 | 443 (ESXi) |
| Hyper-V | 00:15:5D | — |
| VirtualBox | 08:00:27 | — |
| KVM/QEMU | 52:54:00 | — |
| Docker | 02:42 | 2375/2376 |
| Xen | 00:16:3E | — |
| Kubernetes | — | 6443, 10250 |

- **Effort:** 8-12h
- **Competitive value:** Differentiating for modern infrastructure

### 3.3 Cloud Instance Detection

Identify AWS/GCP/Azure hosts via reverse DNS patterns and MAC ranges:
- AWS: `ec2-X-X-X-X.compute-1.amazonaws.com`
- GCP: `X.X.X.X.bc.googleusercontent.com`
- Azure: `00:0D:3A:*`, `00:17:FA:*`

- **Effort:** 6-10h
- **Competitive value:** Differentiating for hybrid cloud environments

### 3.4 DNS Zone Transfer

Attempt AXFR against discovered DNS servers. If misconfigured, returns
ALL records in the zone — complete host enumeration. Security audit feature.

- **Approach:** `hickory-dns` AXFR client
- **Effort:** 4h
- **Competitive value:** Differentiating (security auditing)

## Phase 4: Enterprise Features (est. 40-60h)

Features required for enterprise network visibility.

### 4.1 LLDP/CDP Passive Capture

Purely passive — listen for Link Layer Discovery Protocol and Cisco
Discovery Protocol frames on the wire. Reveals switch model, IOS version,
port ID, VLAN, PoE status, management addresses. Invisible to the network
(zero packets sent). Requires raw socket capture (already have via pnet).

- **Data:** Switch/router/AP identity, firmware, port topology, VLANs
- **Probe level:** Passive (read-only L2 capture)
- **Effort:** 12-16h (LLDP TLV parsing + CDP parsing)
- **Competitive value:** Highly differentiating — reveals infrastructure

### 4.2 SNMP Discovery

Query managed devices for structured inventory data. Single richest source
of device information. Key OIDs: sysDescr, sysObjectID, sysUpTime, sysName,
ifTable, ipAddrTable. Try common community strings (public, community).

- **Data:** Device type, firmware, uptime, interfaces, routing tables
- **Probe level:** Discovery (UDP 161)
- **Approach:** Shell out to `snmpget` initially, native UDP+BER later
- **Effort:** 16-24h
- **Competitive value:** Table stakes for enterprise networks

### 4.3 Vulnerability Correlation (NVD API)

Given CPE identifiers (already extracted by enrichment.rs), query NVD
for known CVEs with CVSS scores. Transforms network scanner into
vulnerability scanner.

- **Data:** CVE IDs, CVSS scores, affected version ranges, exploit status
- **Probe level:** None (API query only, no network probing)
- **API:** `services.nvd.nist.gov/rest/json/cves/2.0?cpeName=<cpe>`
- **Effort:** 16-24h (API + CPE version range matching)
- **Competitive value:** Highly differentiating — "what vulns are on my network?"

### 4.4 Asset Inventory Export

Structured export for enterprise systems:
- CSV/JSON/YAML (universal)
- NetBox API (open-source IPAM/DCIM)
- Nmap XML (industry standard)

- **Effort:** 4-12h depending on integrations
- **Competitive value:** Table stakes for enterprise adoption

## Phase 5: Advanced (est. 50-80h)

### 5.1 NetBIOS/SMB Fingerprinting

Discover Windows hosts, domain membership, file servers. NetBIOS name
query (UDP 137) reveals computer name, domain, logged-in user. SMB
negotiate (TCP 445) reveals OS version before authentication.

- **Effort:** 12-16h
- **Competitive value:** Table stakes for Windows networks

### 5.2 Traffic Analysis / Connection Patterns

Basic behavioral profiling from observed connections:
- "Talks to 3 IPs on MQTT — IoT sensor"
- "200 unique destinations on 443 — workstation browsing"
- "Only talks to gateway — smart plug"

- **Effort:** 8-16h (passive DNS + connection tracking)
- **Competitive value:** Differentiating to novel

### 5.3 Network Topology Mapping

Build network graph from traceroute, SNMP ARP/MAC tables, and
LLDP/CDP neighbor data. Requires SNMP (4.2) and LLDP (4.1) first.

- **Effort:** 24-40h
- **Competitive value:** Highly differentiating

### 5.4 NetFlow/IPFIX Collection

Receive flow summaries from managed switches/routers. Enterprise-grade
traffic visibility without packet capture.

- **Effort:** 16-24h
- **Competitive value:** Differentiating for enterprise

## Deferred

| Item | Reason |
|------|--------|
| WMI/WinRM | Requires credentials, massive protocol complexity (40h+) |
| Full DPI | Dedicated monitoring tool territory |
| Passive DNS logging | Privacy concerns, needs careful scoping |

## Collector Architecture (Current + Planned)

```
Safety Level 0 (Passive — zero packets sent):
  ├── InterfaceCollector     5s   network-interface + netstat + scutil
  ├── ArpCollector (table)   5s   kernel ARP cache read
  ├── WifiCollector         15s   CoreWLAN (macOS)
  ├── MdnsCollector         30s   mdns-sd multicast listen
  ├── PassiveCollector      30s   pnet BPF TCP SYN capture
  └── [future] LLDP/CDP    60s   pnet L2 frame capture

Safety Level 1 (Safe — TCP connect + read only):
  ├── BannerCollector      120s   TCP connect, read banner
  └── TlsCollector         180s   TLS handshake, extract cert

Safety Level 2 (Discovery — active probing):
  ├── NmapCollector         60s   nmap -sV port/service scan
  ├── [future] ArpScanner    5s   active ARP request per IP
  ├── [future] ReverseDns   60s   PTR queries for all IPs
  ├── [future] SsdpCollector 30s  UPnP M-SEARCH + NOTIFY
  ├── [future] SnmpCollector 60s  SNMP GET sysDescr/sysName
  └── [future] SmbCollector  60s  NetBIOS name + SMB negotiate

Safety Level 3 (Intrusive — aggressive probing):
  └── NmapCollector (with -O) 60s  OS fingerprinting

Post-Collection Enrichment (no network activity):
  ├── CPE mapping           enrichment.rs
  ├── Vulnerability lookup  [future] NVD API
  ├── Outlier scoring       model.rs
  ├── Correlation           enrichment.rs
  ├── Cloud detection       [future] reverse DNS patterns
  └── VM/Container classify [future] MAC + port patterns
```

## MCP Tool Expansion (Planned)

| Tool | Description | Phase |
|------|-------------|-------|
| `network_topology` | Network graph with hop/switch relationships | 5 |
| `network_vulnerabilities` | CVEs for discovered services | 4 |
| `network_wake` | Send WoL packet to a host by MAC | 2 |
| `network_export` | Export inventory as CSV/JSON/NetBox | 4 |
| `network_anomalies` | Hosts with high outlier scores | 3 |
| `network_classify` | VM/container/cloud/physical classification | 3 |
