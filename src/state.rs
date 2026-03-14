use std::collections::{HashSet, VecDeque};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use chrono::{Duration as ChronoDuration, Utc};
use tokio::sync::{RwLock, broadcast};
use tokio_util::sync::CancellationToken;

use crate::config::{Config, FilterConfig};
use crate::db::Database;
use crate::event_bus::TriggerEvent;
use crate::model::{
    ArpEntry, Change, ChangeType, DeltaEvent, Fingerprint, FingerprintSource, HostInfo,
    InterfaceInfo, NetworkState, NmapHost, WifiInfo, normalize_mac,
};
use crate::traits::{OuiVendorLookup, StorageBackend, VendorLookup};

/// Central state engine. Applies collector data, computes deltas, broadcasts events,
/// persists to database, publishes trigger events to the internal actor bus,
/// and prunes stale entries.
pub struct StateEngine {
    pub state: Arc<NetworkState>,
    event_log: Arc<RwLock<VecDeque<DeltaEvent>>>,
    /// Non-blocking broadcast for live event subscribers (gRPC Subscribe).
    /// Unlike Vec<mpsc::Sender>, a single slow/hung client cannot block
    /// the state engine from emitting events to all other clients.
    event_broadcast: broadcast::Sender<DeltaEvent>,
    db: Arc<dyn StorageBackend>,
    vendor: Arc<dyn VendorLookup>,
    trigger_bus: Option<broadcast::Sender<TriggerEvent>>,
    filters: FilterConfig,
    buffer_size: usize,
}

impl StateEngine {
    /// Production constructor — opens real database and OUI lookup.
    pub async fn new(
        config: &Config,
        trigger_bus: Option<broadcast::Sender<TriggerEvent>>,
    ) -> anyhow::Result<Self> {
        let db = Database::open(&config.resolved_db_path()).await?;
        let vendor = OuiVendorLookup::new();

        let (interfaces, hosts, wifi) = db.load_all().await?;

        let state = Arc::new(NetworkState::new());
        for iface in interfaces {
            state.interfaces.insert(iface.name.clone(), iface);
        }
        // Interfaces must be loaded first — insert_host checks self-MACs
        let mut rejected = 0usize;
        for host in hosts {
            if !state.insert_host(host.mac.clone(), host) {
                rejected += 1;
            }
        }
        for w in wifi {
            state.wifi_networks.insert(w.bssid.clone(), w);
        }

        tracing::info!(
            hosts = state.hosts.len(),
            interfaces = state.interfaces.len(),
            wifi = state.wifi_networks.len(),
            rejected,
            "state restored from database"
        );

        let (event_broadcast, _) = broadcast::channel(config.storage.event_buffer_size);

        Ok(Self {
            state,
            event_log: Arc::new(RwLock::new(VecDeque::with_capacity(
                config.storage.event_buffer_size,
            ))),
            event_broadcast,
            db: Arc::new(db),
            vendor: Arc::new(vendor),
            trigger_bus,
            filters: config.filters.clone(),
            buffer_size: config.storage.event_buffer_size,
        })
    }

    /// Test constructor — inject mocks for storage and vendor lookup.
    /// No trigger bus (None) — tests don't need the event bus.
    #[cfg(test)]
    pub fn with_mocks(
        db: Arc<dyn StorageBackend>,
        vendor: Arc<dyn VendorLookup>,
        filters: FilterConfig,
        buffer_size: usize,
    ) -> Self {
        let (event_broadcast, _) = broadcast::channel(buffer_size);

        Self {
            state: Arc::new(NetworkState::new()),
            event_log: Arc::new(RwLock::new(VecDeque::with_capacity(buffer_size))),
            event_broadcast,
            db,
            vendor,
            trigger_bus: None,
            filters,
            buffer_size,
        }
    }

    /// Subscribe to live delta events. Returns a broadcast receiver.
    /// Non-blocking: a slow subscriber doesn't stall the state engine.
    /// Lagged subscribers get `RecvError::Lagged(n)` and can catch up
    /// via `events_since(last_seq)`.
    pub fn subscribe(&self) -> broadcast::Receiver<DeltaEvent> {
        self.event_broadcast.subscribe()
    }

    pub async fn events_since(&self, seq: u64) -> Vec<DeltaEvent> {
        self.event_log
            .read()
            .await
            .iter()
            .filter(|e| e.sequence > seq)
            .cloned()
            .collect()
    }

    /// Look up a host by MAC or IP. IP lookup is O(1) via reverse index.
    pub fn get_host(&self, addr: &str) -> Option<HostInfo> {
        self.state.get_host(addr)
    }

    /// Get the current network_id for an interface (gateway|subnet fingerprint).
    pub fn network_id_for(&self, interface: &str) -> String {
        self.state
            .interfaces
            .get(interface)
            .map(|i| i.network_id())
            .unwrap_or_default()
    }

    // ── Apply methods ──────────────────────────────────────────────────

    pub async fn apply_arp_results(&self, entries: &[ArpEntry]) -> anyhow::Result<()> {
        let now = Utc::now();

        for entry in entries {
            let Some(mac) = normalize_mac(&entry.mac) else {
                continue;
            };

            // Non-host and self-MAC filtering is enforced by NetworkState::insert_host,
            // but we check filters here to avoid unnecessary vendor lookups.
            if self.state.is_self_mac(&mac)
                || self.filters.should_exclude_mac(&mac)
                || self.filters.should_exclude_ip(&entry.ip)
            {
                continue;
            }

            if let Some(mut existing) = self.state.hosts.get_mut(&mac) {
                let mut changed = false;

                if !existing.addresses.contains(&entry.ip) {
                    existing.addresses.push(entry.ip);
                    self.state.ip_to_mac.insert(entry.ip, mac.clone());
                    changed = true;
                }
                if entry.hostname.is_some() && existing.hostname != entry.hostname {
                    existing.hostname.clone_from(&entry.hostname);
                    changed = true;
                }
                existing.last_seen = now;
                let snapshot = existing.clone();
                drop(existing); // release DashMap lock before async emit/db

                if changed {
                    self.emit(Change::HostUpdated(snapshot.clone())).await;
                }
                self.db.upsert_host(&snapshot).await?;
            } else {
                let vendor = self.vendor.lookup(&mac);
                if !self.filters.vendor_matches(&vendor) {
                    continue;
                }

                let network_id = self.network_id_for(&entry.interface);
                let mut fingerprints = Vec::new();
                if !vendor.is_empty() {
                    fingerprints.push(Fingerprint {
                        source: FingerprintSource::Arp,
                        category: "hw".into(),
                        key: "vendor".into(),
                        value: vendor.clone(),
                        confidence: 0.9, // OUI lookup is high confidence
                        observed_at: now,
                    });
                }
                let host = HostInfo {
                    mac: mac.clone(),
                    vendor,
                    addresses: vec![entry.ip],
                    hostname: entry.hostname.clone(),
                    os_hint: None,
                    services: Vec::new(),
                    fingerprints,
                    interface: entry.interface.clone(),
                    network_id,
                    first_seen: now,
                    last_seen: now,
                };

                self.state.insert_host(mac, host.clone());
                self.emit(Change::HostAdded(host.clone())).await;
                self.db.upsert_host(&host).await?;
            }
        }

        Ok(())
    }

    pub async fn apply_interface_state(&self, interfaces: &[InterfaceInfo]) -> anyhow::Result<()> {
        for iface in interfaces {
            if self.filters.should_exclude_interface(&iface.name) {
                continue;
            }

            // Detect network transition (gateway/subnet changed = different network)
            let (changed, network_transition) = self
                .state
                .interfaces
                .get(&iface.name)
                .map_or((true, None), |existing| {
                    let old_net = existing.network_id();
                    let new_net = iface.network_id();
                    let net_changed = !old_net.is_empty()
                        && !new_net.is_empty()
                        && old_net != new_net;

                    let field_changed = existing.is_up != iface.is_up
                        || existing.ipv4 != iface.ipv4
                        || existing.ipv6 != iface.ipv6
                        || existing.gateway != iface.gateway
                        || existing.dns != iface.dns;

                    let transition = if net_changed {
                        Some((old_net, new_net))
                    } else {
                        None
                    };

                    (field_changed, transition)
                });

            self.state
                .interfaces
                .insert(iface.name.clone(), iface.clone());

            // If the network changed, clear hosts and trigger reactive collectors
            if let Some((old_net, new_net)) = network_transition {
                let cleared = self.clear_hosts_on_interface(&iface.name).await?;
                tracing::info!(
                    interface = %iface.name,
                    old_network = %old_net,
                    new_network = %new_net,
                    hosts_cleared = cleared,
                    "network transition detected"
                );
                self.emit(Change::NetworkChanged {
                    interface: iface.name.clone(),
                    old_network_id: old_net.clone(),
                    new_network_id: new_net.clone(),
                    hosts_cleared: cleared,
                })
                .await;

                // Publish to internal actor bus — triggers immediate ARP sweep + nmap scan
                self.publish_trigger(TriggerEvent::NetworkChanged {
                    interface: iface.name.clone(),
                    old_network_id: old_net,
                    new_network_id: new_net,
                });
            }

            if changed {
                self.emit(Change::InterfaceChanged(iface.clone())).await;
                self.db.upsert_interface(iface).await?;

                // Publish interface change trigger for reactive collectors
                self.publish_trigger(TriggerEvent::InterfaceChanged {
                    interface: iface.name.clone(),
                });
            }
        }

        // Detect interfaces that went down (present in state but not in latest scan)
        let active_names: HashSet<&str> = interfaces.iter().map(|i| i.name.as_str()).collect();
        let disappeared: Vec<String> = self
            .state
            .interfaces
            .iter()
            .filter(|e| e.value().is_up && !active_names.contains(e.key().as_str()))
            .map(|e| e.key().clone())
            .collect();

        for name in disappeared {
            if let Some(mut iface) = self.state.interfaces.get_mut(&name) {
                if iface.is_up {
                    let old_net = iface.network_id();
                    iface.is_up = false;
                    let snapshot = iface.clone();
                    drop(iface);

                    // Clear hosts from the downed interface
                    let cleared = self.clear_hosts_on_interface(&name).await?;
                    tracing::info!(
                        interface = %name,
                        hosts_cleared = cleared,
                        "interface went down"
                    );

                    if !old_net.is_empty() && cleared > 0 {
                        self.emit(Change::NetworkChanged {
                            interface: name.clone(),
                            old_network_id: old_net,
                            new_network_id: String::new(),
                            hosts_cleared: cleared,
                        })
                        .await;
                    }

                    self.emit(Change::InterfaceChanged(snapshot.clone())).await;
                    self.db.upsert_interface(&snapshot).await?;

                    self.publish_trigger(TriggerEvent::InterfaceDown {
                        interface: name.clone(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Clear in-memory hosts for an interface (network transition).
    /// Hosts remain in the database for historical querying — only the live
    /// in-memory view is reset so the new network starts fresh.
    async fn clear_hosts_on_interface(&self, interface: &str) -> anyhow::Result<usize> {
        // Collect keys first — can't hold DashMap iterator across await points.
        let removed: Vec<String> = self
            .state
            .hosts
            .iter()
            .filter(|e| e.value().interface == interface)
            .map(|e| e.key().clone())
            .collect();

        for mac in &removed {
            // Clean IP reverse index before removing host
            if let Some((_, host)) = self.state.hosts.remove(mac) {
                for addr in &host.addresses {
                    self.state.ip_to_mac.remove(addr);
                }
            }
            self.emit(Change::HostRemoved { mac: mac.clone() }).await;
        }

        Ok(removed.len())
    }

    pub async fn apply_wifi_scan(&self, networks: &[WifiInfo]) -> anyhow::Result<()> {
        let mut seen: HashSet<String> = HashSet::with_capacity(networks.len());

        for network in networks {
            seen.insert(network.bssid.clone());

            let changed = self
                .state
                .wifi_networks
                .get(&network.bssid)
                .map_or(true, |existing| {
                    existing.rssi != network.rssi
                        || existing.channel != network.channel
                        || existing.security != network.security
                        || existing.ssid != network.ssid
                });

            if changed {
                let is_new = !self.state.wifi_networks.contains_key(&network.bssid);
                self.state
                    .wifi_networks
                    .insert(network.bssid.clone(), network.clone());

                if is_new {
                    self.emit(Change::WifiAdded(network.clone())).await;
                } else {
                    self.emit(Change::WifiUpdated(network.clone())).await;
                }
                self.db.upsert_wifi(network).await?;
            }
        }

        let vanished: Vec<String> = self
            .state
            .wifi_networks
            .iter()
            .filter(|e| !seen.contains(e.key()))
            .map(|e| e.key().clone())
            .collect();

        for bssid in vanished {
            self.state.wifi_networks.remove(&bssid);
            self.emit(Change::WifiRemoved {
                bssid: bssid.clone(),
            })
            .await;
            self.db.remove_wifi(&bssid).await?;
        }

        Ok(())
    }

    pub async fn apply_nmap_results(
        &self,
        interface: &str,
        nmap_hosts: &[NmapHost],
    ) -> anyhow::Result<()> {
        let now = Utc::now();

        for nmap_host in nmap_hosts {
            let Some(raw_mac) = &nmap_host.mac else {
                continue;
            };
            let Some(mac) = normalize_mac(raw_mac) else {
                continue;
            };

            if self.state.is_self_mac(&mac) || self.filters.should_exclude_mac(&mac) {
                continue;
            }

            if let Some(existing_ref) = self.state.hosts.get(&mac) {
                // Detect added services (in nmap but not existing)
                let added_services: Vec<_> = nmap_host
                    .services
                    .iter()
                    .filter(|svc| {
                        !existing_ref
                            .services
                            .iter()
                            .any(|s| s.port == svc.port && s.protocol == svc.protocol)
                    })
                    .cloned()
                    .collect();

                // Detect removed services (in existing but not in nmap)
                let removed_services: Vec<_> = existing_ref
                    .services
                    .iter()
                    .filter(|svc| {
                        !nmap_host
                            .services
                            .iter()
                            .any(|s| s.port == svc.port && s.protocol == svc.protocol)
                    })
                    .cloned()
                    .collect();
                drop(existing_ref);

                let updated = if let Some(mut existing) = self.state.hosts.get_mut(&mac) {
                    let mut changed = false;

                    if !existing.addresses.contains(&nmap_host.ip) {
                        existing.addresses.push(nmap_host.ip);
                        self.state.ip_to_mac.insert(nmap_host.ip, mac.clone());
                        changed = true;
                    }
                    // Progressive enrichment: accept richer data, never overwrite
                    // with empty. This lets ARP provide hostnames early and nmap
                    // upgrade them with FQDNs later.
                    if let Some(ref new_name) = nmap_host.hostname {
                        let dominated = existing.hostname.as_ref().map_or(true, |old| {
                            old.len() < new_name.len()
                        });
                        if dominated {
                            existing.hostname = Some(new_name.clone());
                            changed = true;
                        }
                    }
                    if let Some(ref new_os) = nmap_host.os_hint {
                        let dominated = existing.os_hint.as_ref().map_or(true, |old| {
                            old.len() < new_os.len()
                        });
                        if dominated {
                            existing.os_hint = Some(new_os.clone());
                            changed = true;
                        }
                        // Structured fingerprint for OS detection
                        changed |= existing.merge_fingerprint(Fingerprint {
                            source: FingerprintSource::Nmap,
                            category: "os".into(),
                            key: "name".into(),
                            value: new_os.clone(),
                            confidence: 0.7, // nmap OS guess ~70% typical
                            observed_at: now,
                        });
                    }
                    for svc in &added_services {
                        existing.services.push(svc.clone());
                        changed = true;
                    }
                    if !removed_services.is_empty() {
                        existing.services.retain(|s| {
                            !removed_services
                                .iter()
                                .any(|r| r.port == s.port && r.protocol == s.protocol)
                        });
                        changed = true;
                    }
                    existing.last_seen = now;

                    if changed {
                        Some(existing.clone())
                    } else {
                        None
                    }
                } else {
                    None
                };

                for svc in &added_services {
                    self.emit(Change::ServiceChanged {
                        mac: mac.clone(),
                        service: svc.clone(),
                        change_type: ChangeType::Added,
                    })
                    .await;
                }
                for svc in &removed_services {
                    self.emit(Change::ServiceChanged {
                        mac: mac.clone(),
                        service: svc.clone(),
                        change_type: ChangeType::Removed,
                    })
                    .await;
                }
                if let Some(host) = updated {
                    self.emit(Change::HostUpdated(host.clone())).await;
                    self.db.upsert_host(&host).await?;
                }
            } else {
                let vendor = self.vendor.lookup(&mac);
                if !self.filters.vendor_matches(&vendor) {
                    continue;
                }

                let mut fingerprints = Vec::new();
                if !vendor.is_empty() {
                    fingerprints.push(Fingerprint {
                        source: FingerprintSource::Nmap,
                        category: "hw".into(),
                        key: "vendor".into(),
                        value: vendor.clone(),
                        confidence: 0.9,
                        observed_at: now,
                    });
                }
                if let Some(ref os) = nmap_host.os_hint {
                    fingerprints.push(Fingerprint {
                        source: FingerprintSource::Nmap,
                        category: "os".into(),
                        key: "name".into(),
                        value: os.clone(),
                        confidence: 0.7,
                        observed_at: now,
                    });
                }
                let host = HostInfo {
                    mac: mac.clone(),
                    vendor,
                    addresses: vec![nmap_host.ip],
                    hostname: nmap_host.hostname.clone(),
                    os_hint: nmap_host.os_hint.clone(),
                    services: nmap_host.services.clone(),
                    fingerprints,
                    interface: interface.to_string(),
                    network_id: self.network_id_for(interface),
                    first_seen: now,
                    last_seen: now,
                };

                self.state.insert_host(mac, host.clone());
                self.emit(Change::HostAdded(host.clone())).await;
                self.db.upsert_host(&host).await?;
            }
        }

        Ok(())
    }

    // ── Pruning ────────────────────────────────────────────────────────

    pub async fn prune_stale_hosts(&self, ttl_secs: u64) -> anyhow::Result<usize> {
        if ttl_secs == 0 {
            return Ok(0);
        }

        let cutoff = Utc::now() - ChronoDuration::seconds(ttl_secs as i64);
        let stale_macs: Vec<String> = self
            .state
            .hosts
            .iter()
            .filter(|e| e.value().is_stale(cutoff))
            .map(|e| e.key().clone())
            .collect();

        let count = stale_macs.len();
        for mac in &stale_macs {
            if let Some((_, host)) = self.state.hosts.remove(mac) {
                for addr in &host.addresses {
                    self.state.ip_to_mac.remove(addr);
                }
            }
            self.emit(Change::HostRemoved { mac: mac.clone() }).await;
            self.db.remove_host(mac).await?;
        }

        if count > 0 {
            tracing::info!(count, ttl_secs, "pruned stale hosts");
        }

        Ok(count)
    }

    pub fn spawn_pruner(
        self: &Arc<Self>,
        ttl_secs: u64,
        interval_secs: u64,
        cancel: CancellationToken,
    ) {
        if ttl_secs == 0 || interval_secs == 0 {
            return;
        }

        let engine = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    () = cancel.cancelled() => break,
                    _ = interval.tick() => {
                        if let Err(e) = engine.prune_stale_hosts(ttl_secs).await {
                            tracing::error!(error = %e, "host pruning failed");
                        }
                        // Prune old events with same TTL as hosts
                        if let Err(e) = engine.db.prune_events(ttl_secs).await {
                            tracing::error!(error = %e, "event pruning failed");
                        }
                    }
                }
            }
        });
    }

    // ── Internal ───────────────────────────────────────────────────────

    /// Publish a trigger event to the internal actor bus.
    /// No-op if no bus is configured (tests, one-shot scan mode).
    fn publish_trigger(&self, event: TriggerEvent) {
        if let Some(ref bus) = self.trigger_bus {
            if bus.send(event).is_err() {
                tracing::debug!("trigger bus closed — no collector actors listening");
            }
        }
    }

    async fn emit(&self, change: Change) {
        let seq = self.state.sequence.fetch_add(1, Ordering::Relaxed) + 1;

        tracing::trace!(seq, change = %change, "delta event");

        let event = DeltaEvent {
            sequence: seq,
            timestamp: Utc::now(),
            change,
        };

        // Persist to durable timeline (survives restarts)
        if let Err(e) = self.db.append_event(&event).await {
            tracing::warn!(seq, error = %e, "failed to persist event to timeline");
        }

        // In-memory ring buffer (serves GetChanges RPC)
        {
            let mut log = self.event_log.write().await;
            if log.len() >= self.buffer_size {
                log.pop_front();
            }
            log.push_back(event.clone());
        }

        // Non-blocking broadcast to all live subscribers (gRPC Subscribe).
        // Lagged receivers get RecvError::Lagged and can catch up via events_since().
        let _ = self.event_broadcast.send(event);
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FilterConfig;
    use crate::model::{InterfaceKind, ServiceInfo};
    use crate::traits::mocks::{InMemoryStorage, MockVendorLookup};
    use std::sync::Arc;

    fn make_engine(filters: FilterConfig) -> StateEngine {
        StateEngine::with_mocks(
            Arc::new(InMemoryStorage::new()),
            Arc::new(MockVendorLookup::empty()),
            filters,
            100,
        )
    }

    fn make_engine_with_vendor(vendors: Vec<(&str, &str)>) -> StateEngine {
        StateEngine::with_mocks(
            Arc::new(InMemoryStorage::new()),
            Arc::new(MockVendorLookup::new(vendors)),
            FilterConfig::default(),
            100,
        )
    }

    fn arp_entry(mac: &str, ip: &str, iface: &str) -> ArpEntry {
        ArpEntry {
            ip: ip.parse().unwrap(),
            mac: mac.into(),
            interface: iface.into(),
            hostname: None,
        }
    }

    fn wifi(ssid: &str, bssid: &str, rssi: i32) -> WifiInfo {
        WifiInfo {
            ssid: ssid.into(),
            bssid: bssid.into(),
            rssi,
            noise: -90,
            channel: 6,
            band: "2.4GHz".into(),
            security: "WPA2".into(),
            interface: "en0".into(),
        }
    }

    fn iface(name: &str, is_up: bool) -> InterfaceInfo {
        InterfaceInfo {
            name: name.into(),
            mac: "00:00:00:00:00:00".into(),
            ipv4: vec!["10.0.0.1".parse().unwrap()],
            ipv6: vec![],
            gateway: "10.0.0.254".into(),
            subnet: "255.255.255.0".into(),
            is_up,
            kind: InterfaceKind::Wifi,
            dns: vec!["8.8.8.8".into()],
        }
    }

    // ── ARP apply ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn arp_adds_new_host() {
        let engine = make_engine(FilterConfig::default());
        engine
            .apply_arp_results(&[arp_entry("aa:bb:cc:dd:ee:ff", "10.0.0.1", "en0")])
            .await
            .unwrap();

        assert_eq!(engine.state.hosts.len(), 1);
        let host = engine.state.hosts.get("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(host.addresses[0].to_string(), "10.0.0.1");
    }

    #[tokio::test]
    async fn arp_updates_existing_host_new_ip() {
        let engine = make_engine(FilterConfig::default());
        engine
            .apply_arp_results(&[arp_entry("aa:bb:cc:dd:ee:ff", "10.0.0.1", "en0")])
            .await
            .unwrap();
        engine
            .apply_arp_results(&[arp_entry("aa:bb:cc:dd:ee:ff", "10.0.0.2", "en0")])
            .await
            .unwrap();

        let host = engine.state.hosts.get("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(host.addresses.len(), 2);
    }

    #[tokio::test]
    async fn arp_no_duplicate_ip() {
        let engine = make_engine(FilterConfig::default());
        engine
            .apply_arp_results(&[arp_entry("aa:bb:cc:dd:ee:ff", "10.0.0.1", "en0")])
            .await
            .unwrap();
        engine
            .apply_arp_results(&[arp_entry("aa:bb:cc:dd:ee:ff", "10.0.0.1", "en0")])
            .await
            .unwrap();

        let host = engine.state.hosts.get("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(host.addresses.len(), 1);
    }

    #[tokio::test]
    async fn arp_filter_excludes_mac() {
        let engine = make_engine(FilterConfig {
            exclude_macs: vec!["aa:bb:cc:dd:ee:ff".into()],
            ..Default::default()
        });
        engine
            .apply_arp_results(&[arp_entry("aa:bb:cc:dd:ee:ff", "10.0.0.1", "en0")])
            .await
            .unwrap();

        assert_eq!(engine.state.hosts.len(), 0);
    }

    #[tokio::test]
    async fn arp_filter_excludes_ip() {
        let engine = make_engine(FilterConfig {
            exclude_ips: vec!["10.0.0.1".into()],
            ..Default::default()
        });
        engine
            .apply_arp_results(&[arp_entry("aa:bb:cc:dd:ee:ff", "10.0.0.1", "en0")])
            .await
            .unwrap();

        assert_eq!(engine.state.hosts.len(), 0);
    }

    #[tokio::test]
    async fn arp_vendor_filter_rejects_unmatched() {
        let engine = StateEngine::with_mocks(
            Arc::new(InMemoryStorage::new()),
            Arc::new(MockVendorLookup::new(vec![(
                "aa:bb:cc:dd:ee:ff",
                "Samsung",
            )])),
            FilterConfig {
                include_vendors: vec!["Apple".into()],
                ..Default::default()
            },
            100,
        );
        engine
            .apply_arp_results(&[arp_entry("aa:bb:cc:dd:ee:ff", "10.0.0.1", "en0")])
            .await
            .unwrap();

        assert_eq!(engine.state.hosts.len(), 0, "Samsung should be filtered");
    }

    #[tokio::test]
    async fn arp_emits_host_added_event() {
        let engine = make_engine(FilterConfig::default());
        let mut rx = engine.subscribe();

        engine
            .apply_arp_results(&[arp_entry("aa:bb:cc:dd:ee:ff", "10.0.0.1", "en0")])
            .await
            .unwrap();

        let event = rx.try_recv().unwrap();
        assert!(matches!(event.change, Change::HostAdded(_)));
        assert_eq!(event.sequence, 1);
    }

    #[tokio::test]
    async fn arp_emits_host_updated_on_change() {
        let engine = make_engine(FilterConfig::default());
        engine
            .apply_arp_results(&[arp_entry("aa:bb:cc:dd:ee:ff", "10.0.0.1", "en0")])
            .await
            .unwrap();

        let mut rx = engine.subscribe();
        engine
            .apply_arp_results(&[arp_entry("aa:bb:cc:dd:ee:ff", "10.0.0.2", "en0")])
            .await
            .unwrap();

        let event = rx.try_recv().unwrap();
        assert!(matches!(event.change, Change::HostUpdated(_)));
    }

    #[tokio::test]
    async fn arp_no_event_when_unchanged() {
        let engine = make_engine(FilterConfig::default());
        engine
            .apply_arp_results(&[arp_entry("aa:bb:cc:dd:ee:ff", "10.0.0.1", "en0")])
            .await
            .unwrap();

        let mut rx = engine.subscribe();
        engine
            .apply_arp_results(&[arp_entry("aa:bb:cc:dd:ee:ff", "10.0.0.1", "en0")])
            .await
            .unwrap();

        // No HostUpdated event should be emitted (only last_seen changed)
        assert!(rx.try_recv().is_err());
    }

    // ── Interface apply ────────────────────────────────────────────────

    #[tokio::test]
    async fn interface_first_insert_emits_changed() {
        let engine = make_engine(FilterConfig::default());
        let mut rx = engine.subscribe();

        engine
            .apply_interface_state(&[iface("en0", true)])
            .await
            .unwrap();

        assert_eq!(engine.state.interfaces.len(), 1);
        let event = rx.try_recv().unwrap();
        assert!(matches!(event.change, Change::InterfaceChanged(_)));
    }

    #[tokio::test]
    async fn interface_no_event_when_unchanged() {
        let engine = make_engine(FilterConfig::default());
        engine
            .apply_interface_state(&[iface("en0", true)])
            .await
            .unwrap();

        let mut rx = engine.subscribe();
        engine
            .apply_interface_state(&[iface("en0", true)])
            .await
            .unwrap();

        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn interface_emits_on_state_change() {
        let engine = make_engine(FilterConfig::default());
        engine
            .apply_interface_state(&[iface("en0", true)])
            .await
            .unwrap();

        let mut rx = engine.subscribe();
        engine
            .apply_interface_state(&[iface("en0", false)])
            .await
            .unwrap();

        let event = rx.try_recv().unwrap();
        assert!(matches!(event.change, Change::InterfaceChanged(_)));
    }

    #[tokio::test]
    async fn interface_filter_excludes() {
        let engine = make_engine(FilterConfig {
            exclude_interfaces: vec!["lo0".into()],
            ..Default::default()
        });
        engine
            .apply_interface_state(&[iface("lo0", true)])
            .await
            .unwrap();

        assert_eq!(engine.state.interfaces.len(), 0);
    }

    // ── WiFi apply ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn wifi_adds_new_network() {
        let engine = make_engine(FilterConfig::default());
        let mut rx = engine.subscribe();

        engine
            .apply_wifi_scan(&[wifi("MyNet", "aa:bb:cc:dd:ee:ff", -60)])
            .await
            .unwrap();

        assert_eq!(engine.state.wifi_networks.len(), 1);
        let event = rx.try_recv().unwrap();
        assert!(matches!(event.change, Change::WifiAdded(_)));
    }

    #[tokio::test]
    async fn wifi_updates_on_rssi_change() {
        let engine = make_engine(FilterConfig::default());
        engine
            .apply_wifi_scan(&[wifi("MyNet", "aa:bb:cc:dd:ee:ff", -60)])
            .await
            .unwrap();

        let mut rx = engine.subscribe();
        engine
            .apply_wifi_scan(&[wifi("MyNet", "aa:bb:cc:dd:ee:ff", -70)])
            .await
            .unwrap();

        let event = rx.try_recv().unwrap();
        assert!(matches!(event.change, Change::WifiUpdated(_)));
    }

    #[tokio::test]
    async fn wifi_no_event_when_unchanged() {
        let engine = make_engine(FilterConfig::default());
        engine
            .apply_wifi_scan(&[wifi("MyNet", "aa:bb:cc:dd:ee:ff", -60)])
            .await
            .unwrap();

        let mut rx = engine.subscribe();
        engine
            .apply_wifi_scan(&[wifi("MyNet", "aa:bb:cc:dd:ee:ff", -60)])
            .await
            .unwrap();

        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn wifi_removes_vanished_network() {
        let engine = make_engine(FilterConfig::default());
        engine
            .apply_wifi_scan(&[
                wifi("Net1", "10:11:11:11:11:11", -60),
                wifi("Net2", "22:22:22:22:22:22", -70),
            ])
            .await
            .unwrap();
        assert_eq!(engine.state.wifi_networks.len(), 2);

        let mut rx = engine.subscribe();
        // Second scan only has Net1 — Net2 vanished
        engine
            .apply_wifi_scan(&[wifi("Net1", "10:11:11:11:11:11", -60)])
            .await
            .unwrap();

        assert_eq!(engine.state.wifi_networks.len(), 1);
        let event = rx.try_recv().unwrap();
        assert!(matches!(
            event.change,
            Change::WifiRemoved { ref bssid } if bssid == "22:22:22:22:22:22"
        ));
    }

    // ── Nmap apply ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn nmap_skips_host_without_mac() {
        let engine = make_engine(FilterConfig::default());
        let nmap_host = NmapHost {
            ip: "10.0.0.1".parse().unwrap(),
            mac: None,
            hostname: None,
            os_hint: None,
            services: vec![],
        };
        engine
            .apply_nmap_results("en0", &[nmap_host])
            .await
            .unwrap();
        assert_eq!(engine.state.hosts.len(), 0);
    }

    #[tokio::test]
    async fn nmap_adds_new_host_with_services() {
        let engine = make_engine(FilterConfig::default());
        let nmap_host = NmapHost {
            ip: "10.0.0.1".parse().unwrap(),
            mac: Some("aa:bb:cc:dd:ee:ff".into()),
            hostname: Some("server".into()),
            os_hint: Some("Linux".into()),
            services: vec![ServiceInfo {
                port: 22,
                protocol: "tcp".into(),
                name: "ssh".into(),
                version: "OpenSSH 8.9".into(),
                state: "open".into(), banner: String::new(),
            }],
        };
        engine
            .apply_nmap_results("en0", &[nmap_host])
            .await
            .unwrap();

        let host = engine.state.hosts.get("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(host.services.len(), 1);
        assert_eq!(host.hostname.as_deref(), Some("server"));
        assert_eq!(host.os_hint.as_deref(), Some("Linux"));
    }

    #[tokio::test]
    async fn nmap_filter_excludes_mac() {
        let engine = make_engine(FilterConfig {
            exclude_macs: vec!["aa:bb:cc:dd:ee:ff".into()],
            ..Default::default()
        });
        let nmap_host = NmapHost {
            ip: "10.0.0.1".parse().unwrap(),
            mac: Some("aa:bb:cc:dd:ee:ff".into()),
            hostname: None,
            os_hint: None,
            services: vec![],
        };
        engine
            .apply_nmap_results("en0", &[nmap_host])
            .await
            .unwrap();
        assert_eq!(engine.state.hosts.len(), 0);
    }

    // ── Pruning ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn prune_ttl_zero_is_noop() {
        let engine = make_engine(FilterConfig::default());
        let result = engine.prune_stale_hosts(0).await.unwrap();
        assert_eq!(result, 0);
    }

    #[tokio::test]
    async fn prune_removes_stale_hosts() {
        let engine = make_engine(FilterConfig::default());
        // Add a host and backdate it
        let host = HostInfo {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            vendor: String::new(),
            addresses: vec!["10.0.0.1".parse().unwrap()],
            hostname: None,
            os_hint: None,
            services: vec![],
            fingerprints: vec![],
            interface: "en0".into(),
            network_id: String::new(),
            first_seen: Utc::now() - chrono::Duration::hours(48),
            last_seen: Utc::now() - chrono::Duration::hours(25),
        };
        engine
            .state
            .hosts
            .insert(host.mac.clone(), host.clone());

        let removed = engine.prune_stale_hosts(86400).await.unwrap(); // 24h TTL
        assert_eq!(removed, 1);
        assert_eq!(engine.state.hosts.len(), 0);
    }

    #[tokio::test]
    async fn prune_keeps_fresh_hosts() {
        let engine = make_engine(FilterConfig::default());
        let host = HostInfo {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            vendor: String::new(),
            addresses: vec!["10.0.0.1".parse().unwrap()],
            hostname: None,
            os_hint: None,
            services: vec![],
            fingerprints: vec![],
            interface: "en0".into(),
            network_id: String::new(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        };
        engine
            .state
            .hosts
            .insert(host.mac.clone(), host);

        let removed = engine.prune_stale_hosts(86400).await.unwrap();
        assert_eq!(removed, 0);
        assert_eq!(engine.state.hosts.len(), 1);
    }

    // ── Event log ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn events_since_returns_newer_events() {
        let engine = make_engine(FilterConfig::default());
        engine
            .apply_arp_results(&[
                arp_entry("10:11:11:11:11:11", "10.0.0.1", "en0"),
                arp_entry("22:22:22:22:22:22", "10.0.0.2", "en0"),
                arp_entry("30:33:33:33:33:33", "10.0.0.3", "en0"),
            ])
            .await
            .unwrap();

        let events = engine.events_since(1).await;
        assert_eq!(events.len(), 2); // seq 2 and 3
        assert_eq!(events[0].sequence, 2);
        assert_eq!(events[1].sequence, 3);
    }

    #[tokio::test]
    async fn event_sequence_is_monotonic() {
        let engine = make_engine(FilterConfig::default());
        engine
            .apply_arp_results(&[
                arp_entry("10:11:11:11:11:11", "10.0.0.1", "en0"),
                arp_entry("22:22:22:22:22:22", "10.0.0.2", "en0"),
            ])
            .await
            .unwrap();

        let events = engine.events_since(0).await;
        for window in events.windows(2) {
            assert!(window[1].sequence > window[0].sequence);
        }
    }

    // ── Host lookup ────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_host_by_mac() {
        let engine = make_engine(FilterConfig::default());
        engine
            .apply_arp_results(&[arp_entry("aa:bb:cc:dd:ee:ff", "10.0.0.1", "en0")])
            .await
            .unwrap();

        let host = engine.get_host("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(host.addresses[0].to_string(), "10.0.0.1");
    }

    #[tokio::test]
    async fn get_host_by_ip() {
        let engine = make_engine(FilterConfig::default());
        engine
            .apply_arp_results(&[arp_entry("aa:bb:cc:dd:ee:ff", "10.0.0.1", "en0")])
            .await
            .unwrap();

        let host = engine.get_host("10.0.0.1").unwrap();
        assert_eq!(host.mac, "aa:bb:cc:dd:ee:ff");
    }

    #[tokio::test]
    async fn get_host_not_found() {
        let engine = make_engine(FilterConfig::default());
        assert!(engine.get_host("nonexistent").is_none());
    }

    // ── Network transitions ────────────────────────────────────────────

    #[tokio::test]
    async fn network_transition_clears_in_memory_hosts() {
        let engine = make_engine(FilterConfig::default());

        // Set up initial interface on network A
        let mut iface_a = iface("en0", true);
        iface_a.gateway = "10.0.0.1".into();
        iface_a.subnet = "255.255.255.0".into();
        engine
            .apply_interface_state(&[iface_a])
            .await
            .unwrap();

        // Add hosts on network A
        engine
            .apply_arp_results(&[
                arp_entry("aa:bb:cc:dd:ee:ff", "10.0.0.2", "en0"),
                arp_entry("10:22:33:44:55:66", "10.0.0.3", "en0"),
            ])
            .await
            .unwrap();
        assert_eq!(engine.state.hosts.len(), 2);

        // Switch to network B (different gateway)
        let mut iface_b = iface("en0", true);
        iface_b.gateway = "192.168.1.1".into();
        iface_b.subnet = "255.255.255.0".into();
        engine
            .apply_interface_state(&[iface_b])
            .await
            .unwrap();

        // Old hosts should be cleared from in-memory state
        assert_eq!(
            engine.state.hosts.len(),
            0,
            "hosts from old network should be cleared on network transition"
        );
    }

    #[tokio::test]
    async fn network_transition_emits_network_changed_event() {
        let engine = make_engine(FilterConfig::default());

        // Set up initial network
        let mut iface_a = iface("en0", true);
        iface_a.gateway = "10.0.0.1".into();
        iface_a.subnet = "255.255.255.0".into();
        engine
            .apply_interface_state(&[iface_a])
            .await
            .unwrap();

        // Add a host
        engine
            .apply_arp_results(&[arp_entry("aa:bb:cc:dd:ee:ff", "10.0.0.2", "en0")])
            .await
            .unwrap();

        let mut rx = engine.subscribe();

        // Switch network
        let mut iface_b = iface("en0", true);
        iface_b.gateway = "192.168.1.1".into();
        iface_b.subnet = "255.255.255.0".into();
        engine
            .apply_interface_state(&[iface_b])
            .await
            .unwrap();

        // Should see: HostRemoved + NetworkChanged + InterfaceChanged
        let mut found_network_changed = false;
        let mut found_host_removed = false;
        while let Ok(event) = rx.try_recv() {
            match event.change {
                Change::NetworkChanged { ref interface, hosts_cleared, .. } => {
                    assert_eq!(interface, "en0");
                    assert_eq!(hosts_cleared, 1);
                    found_network_changed = true;
                }
                Change::HostRemoved { .. } => {
                    found_host_removed = true;
                }
                _ => {}
            }
        }
        assert!(found_network_changed, "should emit NetworkChanged");
        assert!(found_host_removed, "should emit HostRemoved for cleared host");
    }

    #[tokio::test]
    async fn same_network_no_transition() {
        let engine = make_engine(FilterConfig::default());

        // Set up initial network
        let mut iface_a = iface("en0", true);
        iface_a.gateway = "10.0.0.1".into();
        iface_a.subnet = "255.255.255.0".into();
        engine
            .apply_interface_state(&[iface_a.clone()])
            .await
            .unwrap();

        // Add a host
        engine
            .apply_arp_results(&[arp_entry("aa:bb:cc:dd:ee:ff", "10.0.0.2", "en0")])
            .await
            .unwrap();

        // Re-apply same interface state (same gateway/subnet)
        engine
            .apply_interface_state(&[iface_a])
            .await
            .unwrap();

        // Host should still be there — no transition happened
        assert_eq!(engine.state.hosts.len(), 1, "no transition = hosts preserved");
    }

    #[tokio::test]
    async fn hosts_get_network_id_tag() {
        let engine = make_engine(FilterConfig::default());

        // Set up interface with known gateway/subnet
        let mut iface = iface("en0", true);
        iface.gateway = "10.0.0.1".into();
        iface.subnet = "255.255.255.0".into();
        engine
            .apply_interface_state(&[iface])
            .await
            .unwrap();

        // Add host
        engine
            .apply_arp_results(&[arp_entry("aa:bb:cc:dd:ee:ff", "10.0.0.2", "en0")])
            .await
            .unwrap();

        let host = engine.state.hosts.get("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(
            host.network_id, "10.0.0.1|255.255.255.0",
            "host should be tagged with network fingerprint"
        );
    }

    #[tokio::test]
    async fn new_hosts_after_transition_get_new_network_id() {
        let engine = make_engine(FilterConfig::default());

        // Network A
        let mut iface_a = iface("en0", true);
        iface_a.gateway = "10.0.0.1".into();
        iface_a.subnet = "255.255.255.0".into();
        engine
            .apply_interface_state(&[iface_a])
            .await
            .unwrap();
        engine
            .apply_arp_results(&[arp_entry("aa:bb:cc:dd:ee:ff", "10.0.0.2", "en0")])
            .await
            .unwrap();

        // Transition to network B
        let mut iface_b = iface("en0", true);
        iface_b.gateway = "192.168.1.1".into();
        iface_b.subnet = "255.255.255.0".into();
        engine
            .apply_interface_state(&[iface_b])
            .await
            .unwrap();

        // New host on network B
        engine
            .apply_arp_results(&[arp_entry("ba:cc:dd:ee:ff:00", "192.168.1.50", "en0")])
            .await
            .unwrap();

        let host = engine.state.hosts.get("ba:cc:dd:ee:ff:00").unwrap();
        assert_eq!(
            host.network_id, "192.168.1.1|255.255.255.0",
            "host on new network should have new network_id"
        );
    }

    #[tokio::test]
    async fn interface_going_down_detected() {
        let engine = make_engine(FilterConfig::default());

        engine
            .apply_interface_state(&[iface("en0", true)])
            .await
            .unwrap();
        assert!(engine.state.interfaces.get("en0").unwrap().is_up);

        // Next scan doesn't include en0 — it went down
        engine.apply_interface_state(&[]).await.unwrap();

        let i = engine.state.interfaces.get("en0").unwrap();
        assert!(!i.is_up, "interface should be marked down when absent from scan");
    }

    #[tokio::test]
    async fn interface_down_clears_hosts() {
        let engine = make_engine(FilterConfig::default());

        // Set up interface + hosts
        let mut if_up = iface("en0", true);
        if_up.gateway = "10.0.0.1".into();
        if_up.subnet = "255.255.255.0".into();
        engine
            .apply_interface_state(&[if_up])
            .await
            .unwrap();
        engine
            .apply_arp_results(&[
                arp_entry("aa:bb:cc:dd:ee:ff", "10.0.0.2", "en0"),
                arp_entry("10:22:33:44:55:66", "10.0.0.3", "en0"),
            ])
            .await
            .unwrap();
        assert_eq!(engine.state.hosts.len(), 2);

        // Interface disappears from scan
        engine.apply_interface_state(&[]).await.unwrap();

        assert_eq!(
            engine.state.hosts.len(),
            0,
            "hosts should be cleared when interface goes down"
        );
    }

    #[tokio::test]
    async fn multi_interface_transition_only_affects_changed() {
        let engine = make_engine(FilterConfig::default());

        // Set up two interfaces
        let mut en0 = iface("en0", true);
        en0.gateway = "10.0.0.1".into();
        en0.subnet = "255.255.255.0".into();
        let mut en4 = iface("en4", true);
        en4.gateway = "192.168.1.1".into();
        en4.subnet = "255.255.255.0".into();
        en4.kind = crate::model::InterfaceKind::Ethernet;
        engine
            .apply_interface_state(&[en0.clone(), en4.clone()])
            .await
            .unwrap();

        // Add hosts on both interfaces
        engine
            .apply_arp_results(&[
                arp_entry("aa:bb:cc:dd:ee:ff", "10.0.0.2", "en0"),
                arp_entry("10:22:33:44:55:66", "192.168.1.2", "en4"),
            ])
            .await
            .unwrap();
        assert_eq!(engine.state.hosts.len(), 2);

        // en0 switches network, en4 stays the same
        let mut en0_new = iface("en0", true);
        en0_new.gateway = "172.16.0.1".into();
        en0_new.subnet = "255.255.0.0".into();
        engine
            .apply_interface_state(&[en0_new, en4])
            .await
            .unwrap();

        // Only en0's host should be cleared; en4's host survives
        assert_eq!(engine.state.hosts.len(), 1);
        assert!(
            engine.state.hosts.get("10:22:33:44:55:66").is_some(),
            "en4's host should survive en0's network transition"
        );
        assert!(
            engine.state.hosts.get("aa:bb:cc:dd:ee:ff").is_none(),
            "en0's host should be cleared"
        );
    }

    #[tokio::test]
    async fn continuous_profiling_accumulates_on_stable_network() {
        let engine = make_engine(FilterConfig::default());

        // Set up interface
        let mut if_a = iface("en0", true);
        if_a.gateway = "10.0.0.1".into();
        if_a.subnet = "255.255.255.0".into();
        engine
            .apply_interface_state(&[if_a.clone()])
            .await
            .unwrap();

        // Simulate multiple ARP polls discovering hosts over time
        engine
            .apply_arp_results(&[arp_entry("aa:bb:cc:dd:ee:ff", "10.0.0.2", "en0")])
            .await
            .unwrap();
        engine
            .apply_arp_results(&[
                arp_entry("aa:bb:cc:dd:ee:ff", "10.0.0.2", "en0"),
                arp_entry("10:22:33:44:55:66", "10.0.0.3", "en0"),
            ])
            .await
            .unwrap();
        engine
            .apply_arp_results(&[
                arp_entry("aa:bb:cc:dd:ee:ff", "10.0.0.2", "en0"),
                arp_entry("10:22:33:44:55:66", "10.0.0.3", "en0"),
                arp_entry("22:33:44:55:66:77", "10.0.0.4", "en0"),
            ])
            .await
            .unwrap();

        // Re-apply same interface state (no transition)
        engine
            .apply_interface_state(&[if_a])
            .await
            .unwrap();

        // All 3 hosts should be accumulated, no data lost
        assert_eq!(engine.state.hosts.len(), 3);

        // All tagged with same network_id
        for entry in engine.state.hosts.iter() {
            assert_eq!(entry.value().network_id, "10.0.0.1|255.255.255.0");
        }
    }

    #[tokio::test]
    async fn network_id_empty_when_interface_not_set() {
        let engine = make_engine(FilterConfig::default());
        assert_eq!(engine.network_id_for("en0"), "");
    }

    #[tokio::test]
    async fn network_id_reflects_current_interface() {
        let engine = make_engine(FilterConfig::default());

        let mut if_a = iface("en0", true);
        if_a.gateway = "10.0.0.1".into();
        if_a.subnet = "255.255.255.0".into();
        engine
            .apply_interface_state(&[if_a])
            .await
            .unwrap();

        assert_eq!(engine.network_id_for("en0"), "10.0.0.1|255.255.255.0");
    }

    // ── Service change detection ──────────────────────────────────────

    #[tokio::test]
    async fn nmap_detects_new_service() {
        let engine = make_engine(FilterConfig::default());

        // Seed a host via ARP
        engine
            .apply_arp_results(&[arp_entry("aa:bb:cc:dd:ee:ff", "10.0.0.1", "en0")])
            .await
            .unwrap();
        assert!(engine.state.hosts.get("aa:bb:cc:dd:ee:ff").unwrap().services.is_empty());

        // nmap discovers SSH
        let nmap = crate::model::NmapHost {
            ip: "10.0.0.1".parse().unwrap(),
            mac: Some("aa:bb:cc:dd:ee:ff".into()),
            hostname: None,
            os_hint: None,
            services: vec![crate::model::ServiceInfo {
                port: 22,
                protocol: "tcp".into(),
                name: "ssh".into(),
                version: "OpenSSH 9".into(),
                state: "open".into(), banner: String::new(),
            }],
        };
        engine.apply_nmap_results("en0", &[nmap]).await.unwrap();

        let host = engine.state.hosts.get("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(host.services.len(), 1);
        assert_eq!(host.services[0].port, 22);

        // Check service_changed event was emitted
        let events = engine.events_since(0).await;
        assert!(events.iter().any(|e| matches!(
            &e.change,
            Change::ServiceChanged { change_type: ChangeType::Added, .. }
        )));
    }

    #[tokio::test]
    async fn nmap_detects_removed_service() {
        let engine = make_engine(FilterConfig::default());

        // Seed host with SSH service
        let host = HostInfo {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            vendor: String::new(),
            addresses: vec!["10.0.0.1".parse().unwrap()],
            hostname: None,
            os_hint: None,
            services: vec![
                crate::model::ServiceInfo {
                    port: 22,
                    protocol: "tcp".into(),
                    name: "ssh".into(),
                    version: "OpenSSH 9".into(),
                    state: "open".into(), banner: String::new(),
                },
                crate::model::ServiceInfo {
                    port: 80,
                    protocol: "tcp".into(),
                    name: "http".into(),
                    version: String::new(),
                    state: "open".into(), banner: String::new(),
                },
            ],
            fingerprints: vec![],
            interface: "en0".into(),
            network_id: String::new(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        };
        engine.state.hosts.insert(host.mac.clone(), host);

        // nmap now only sees SSH (port 80 closed)
        let nmap = crate::model::NmapHost {
            ip: "10.0.0.1".parse().unwrap(),
            mac: Some("aa:bb:cc:dd:ee:ff".into()),
            hostname: None,
            os_hint: None,
            services: vec![crate::model::ServiceInfo {
                port: 22,
                protocol: "tcp".into(),
                name: "ssh".into(),
                version: "OpenSSH 9".into(),
                state: "open".into(), banner: String::new(),
            }],
        };
        engine.apply_nmap_results("en0", &[nmap]).await.unwrap();

        // Port 80 should be gone
        let host = engine.state.hosts.get("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(host.services.len(), 1);
        assert_eq!(host.services[0].port, 22);

        // Check service_changed(removed) event was emitted
        let events = engine.events_since(0).await;
        assert!(events.iter().any(|e| matches!(
            &e.change,
            Change::ServiceChanged { service, change_type: ChangeType::Removed, .. }
            if service.port == 80
        )));
    }

    #[tokio::test]
    async fn nmap_invalid_mac_skipped() {
        let engine = make_engine(FilterConfig::default());

        let nmap = crate::model::NmapHost {
            ip: "10.0.0.1".parse().unwrap(),
            mac: Some("zz:yy:xx:ww:vv:uu".into()),
            hostname: None,
            os_hint: None,
            services: vec![],
        };
        engine.apply_nmap_results("en0", &[nmap]).await.unwrap();
        assert!(engine.state.hosts.is_empty());
    }
}
