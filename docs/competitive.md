# Competitive Positioning

## Landscape

| Tool | Type | Strengths | Weaknesses | Our Advantage |
|------|------|-----------|------------|---------------|
| **runZero** | Enterprise scanner | Rich fingerprints, confidence scores, asset correlation | Expensive, SaaS-dependent, no MCP | We have structured fingerprints + MCP for AI agents |
| **Shodan** | Internet scanner | Massive scale, banner-centric, CVE correlation | Internet-facing only, no local networks | We do local LAN discovery (ARP, mDNS, passive) |
| **Nmap** | Port scanner | Gold standard for port/OS scanning, NSE scripts | Point-in-time, no continuous monitoring, no state | We run continuously with delta tracking |
| **Fing** | Consumer scanner | Great UX, device recognition, UPnP/WoL | Closed source, no API, no automation | We have gRPC + MCP for automation |
| **LibreNMS** | Enterprise NMS | SNMP polling, alerting, topology maps | Heavy (PHP/MySQL), SNMP-only discovery | We're lightweight (single binary) with multi-source |
| **Zeek/Bro** | Passive monitor | Deep traffic analysis, protocol logs | No active scanning, complex setup | We combine active + passive |
| **p0f** | Passive fingerprinter | Zero-probe OS detection | Abandoned (2016), limited to TCP | We have passive + active + mDNS + banner |
| **ntopng** | Flow analyzer | Real-time traffic visualization | Focused on flow, not asset inventory | We focus on host inventory with enrichment |

## Our Differentiators

1. **MCP-native** — Claude and AI agents can query network state conversationally
2. **Multi-source enrichment** — 8 collectors feeding structured fingerprints with confidence
3. **Continuous + progressive** — data quality improves over time without re-scanning
4. **Three-tier events** — durable history + fast queries + real-time streaming
5. **Probe classification** — users choose risk tolerance for fragile networks
6. **Single binary** — Nix-built, zero runtime deps, runs as launchd/systemd service
7. **Pure Rust** — no C deps for capture (pnet BPF), parsing (etherparse), or mDNS (mdns-sd)

## Capability Matrix (Current)

| Capability | amimori | runZero | Shodan | Nmap | Fing |
|-----------|---------|---------|--------|------|------|
| ARP discovery | cache read | active scan | — | ping sweep | active scan |
| Port scanning | nmap -sV | custom | custom | native | basic |
| OS fingerprinting | nmap -O + passive TCP | custom + p0f-like | banner-based | native | basic |
| mDNS/Bonjour | yes (mdns-sd) | yes | — | nse script | yes |
| TLS cert extraction | yes (rustls) | yes | yes | nse script | — |
| Banner grabbing | yes (TCP+HTTP) | yes | yes (primary) | nse | — |
| Passive TCP fingerprint | yes (pnet) | — | — | — | — |
| Structured fingerprints | yes (confidence) | yes (fp.*) | partial | — | — |
| Outlier scoring | yes (0-5) | yes (0-5) | — | — | — |
| CPE identification | yes (14 mappings) | yes (full NVD) | yes | — | — |
| Continuous monitoring | yes (daemon) | yes (explorer) | crawl-based | — | yes |
| Event history | yes (SQLite) | snapshot diffs | 30-day TTL | — | — |
| MCP/AI integration | yes (native) | — | API | — | — |
| gRPC streaming | yes | — | firehose ($$) | — | — |
| UPnP/SSDP | planned | yes | — | nse | yes |
| SNMP | planned | yes | partial | nse | — |
| LLDP/CDP | planned | — | — | — | — |
| Vulnerability correlation | planned (NVD) | yes | yes (native) | vulners nse | — |
| Wake-on-LAN | planned | — | — | — | yes |
| Topology mapping | planned | partial | — | traceroute | — |

## Target Users

1. **Security researchers** — "what's on this network?" with rich fingerprints
2. **Home lab operators** — continuous device inventory with MCP for Claude
3. **DevOps/SRE** — infrastructure discovery, VM/container classification
4. **Pentesters** — progressive profiling without being noisy (passive + safe modes)
5. **IT admins** — asset inventory, change tracking, vulnerability awareness
