use std::collections::VecDeque;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use chrono::Utc;
use mac_oui::Oui;
use tokio::sync::{RwLock, mpsc};

use crate::db::Database;
use crate::model::{
    ArpEntry, Change, ChangeType, DeltaEvent, HostInfo, InterfaceInfo, NmapHost, NetworkState,
    WifiInfo,
};

/// Central state engine. Receives collector data, computes deltas, broadcasts events,
/// and persists to the database.
pub struct StateEngine {
    pub state: Arc<NetworkState>,
    event_log: Arc<RwLock<VecDeque<DeltaEvent>>>,
    subscribers: Arc<RwLock<Vec<mpsc::Sender<DeltaEvent>>>>,
    db: Arc<Database>,
    oui_db: Option<Oui>,
    buffer_size: usize,
}

impl StateEngine {
    pub async fn new(db_path: &std::path::Path, buffer_size: usize) -> anyhow::Result<Self> {
        let db = Database::open(db_path).await?;
        let state = Arc::new(NetworkState::new());

        // Load OUI database for MAC vendor lookups
        let oui_db = match mac_oui::Oui::default() {
            Ok(db) => Some(db),
            Err(e) => {
                tracing::warn!("failed to load OUI database: {e}");
                None
            }
        };

        // Restore state from database
        let (interfaces, hosts, wifi) = db.load_all().await?;
        for iface in interfaces {
            state.interfaces.insert(iface.name.clone(), iface);
        }
        for host in hosts {
            state.hosts.insert(host.mac.clone(), host);
        }
        for w in wifi {
            state.wifi_networks.insert(w.bssid.clone(), w);
        }

        let host_count = state.hosts.len();
        let iface_count = state.interfaces.len();
        tracing::info!("restored {host_count} hosts, {iface_count} interfaces from database");

        Ok(Self {
            state,
            event_log: Arc::new(RwLock::new(VecDeque::with_capacity(buffer_size))),
            subscribers: Arc::new(RwLock::new(Vec::new())),
            db: Arc::new(db),
            oui_db,
            buffer_size,
        })
    }

    /// Look up vendor name for a MAC address.
    fn lookup_vendor(&self, mac: &str) -> String {
        self.oui_db
            .as_ref()
            .and_then(|db| db.lookup_by_mac(mac).ok().flatten())
            .map(|entry| entry.company_name.clone())
            .unwrap_or_default()
    }

    /// Subscribe to live delta events.
    pub async fn subscribe(&self) -> mpsc::Receiver<DeltaEvent> {
        let (tx, rx) = mpsc::channel(256);
        self.subscribers.write().await.push(tx);
        rx
    }

    /// Get events since a given sequence number.
    pub async fn events_since(&self, seq: u64) -> Vec<DeltaEvent> {
        let log = self.event_log.read().await;
        log.iter().filter(|e| e.sequence > seq).cloned().collect()
    }

    /// Get a host by MAC or IP address.
    pub fn get_host(&self, addr: &str) -> Option<HostInfo> {
        // Try MAC first
        if let Some(host) = self.state.hosts.get(addr) {
            return Some(host.clone());
        }

        // Try IP
        if let Ok(ip) = addr.parse::<std::net::IpAddr>() {
            for entry in self.state.hosts.iter() {
                if entry.value().addresses.contains(&ip) {
                    return Some(entry.value().clone());
                }
            }
        }

        None
    }

    // ── Apply methods ──────────────────────────────────────────────────

    pub async fn apply_arp_results(&self, entries: &[ArpEntry]) -> anyhow::Result<()> {
        let now = Utc::now();

        for entry in entries {
            if let Some(mut existing) = self.state.hosts.get_mut(&entry.mac) {
                // Update existing host
                let mut changed = false;

                if !existing.addresses.contains(&entry.ip) {
                    existing.addresses.push(entry.ip);
                    changed = true;
                }
                if entry.hostname.is_some() && existing.hostname != entry.hostname {
                    existing.hostname.clone_from(&entry.hostname);
                    changed = true;
                }
                existing.last_seen = now;

                if changed {
                    let host = existing.clone();
                    drop(existing);
                    self.emit(Change::HostUpdated(host.clone())).await;
                    self.db.upsert_host(&host).await?;
                } else {
                    let host = existing.clone();
                    drop(existing);
                    self.db.upsert_host(&host).await?;
                }
            } else {
                // New host
                let vendor = self.lookup_vendor(&entry.mac);
                let host = HostInfo {
                    mac: entry.mac.clone(),
                    vendor,
                    addresses: vec![entry.ip],
                    hostname: entry.hostname.clone(),
                    os_hint: None,
                    services: Vec::new(),
                    interface: entry.interface.clone(),
                    first_seen: now,
                    last_seen: now,
                };

                self.state.hosts.insert(entry.mac.clone(), host.clone());
                self.emit(Change::HostAdded(host.clone())).await;
                self.db.upsert_host(&host).await?;
            }
        }

        Ok(())
    }

    pub async fn apply_interface_state(
        &self,
        interfaces: &[InterfaceInfo],
    ) -> anyhow::Result<()> {
        for iface in interfaces {
            let changed = if let Some(existing) = self.state.interfaces.get(&iface.name) {
                existing.is_up != iface.is_up
                    || existing.ipv4 != iface.ipv4
                    || existing.ipv6 != iface.ipv6
                    || existing.gateway != iface.gateway
            } else {
                true
            };

            self.state
                .interfaces
                .insert(iface.name.clone(), iface.clone());

            if changed {
                self.emit(Change::InterfaceChanged(iface.clone())).await;
                self.db.upsert_interface(iface).await?;
            }
        }

        Ok(())
    }

    pub async fn apply_wifi_scan(&self, networks: &[WifiInfo]) -> anyhow::Result<()> {
        let mut seen_bssids: std::collections::HashSet<String> = std::collections::HashSet::new();

        for network in networks {
            seen_bssids.insert(network.bssid.clone());

            if let Some(existing) = self.state.wifi_networks.get(&network.bssid) {
                if existing.rssi != network.rssi
                    || existing.channel != network.channel
                    || existing.security != network.security
                {
                    drop(existing);
                    self.state
                        .wifi_networks
                        .insert(network.bssid.clone(), network.clone());
                    self.emit(Change::WifiUpdated(network.clone())).await;
                    self.db.upsert_wifi(network).await?;
                }
            } else {
                self.state
                    .wifi_networks
                    .insert(network.bssid.clone(), network.clone());
                self.emit(Change::WifiAdded(network.clone())).await;
                self.db.upsert_wifi(network).await?;
            }
        }

        // Remove networks no longer visible
        let to_remove: Vec<String> = self
            .state
            .wifi_networks
            .iter()
            .filter(|entry| !seen_bssids.contains(entry.key()))
            .map(|entry| entry.key().clone())
            .collect();

        for bssid in to_remove {
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
            let mac = nmap_host
                .mac
                .as_deref()
                .unwrap_or("")
                .to_string();

            if mac.is_empty() {
                continue;
            }

            if self.state.hosts.contains_key(&mac) {
                // Collect new services to add (outside of the lock)
                let new_services: Vec<_> = {
                    let existing = self.state.hosts.get(&mac).unwrap();
                    nmap_host
                        .services
                        .iter()
                        .filter(|svc| {
                            !existing
                                .services
                                .iter()
                                .any(|s| s.port == svc.port && s.protocol == svc.protocol)
                        })
                        .cloned()
                        .collect()
                };

                // Apply mutations
                let host = {
                    let mut existing = self.state.hosts.get_mut(&mac).unwrap();
                    let mut changed = false;

                    if !existing.addresses.contains(&nmap_host.ip) {
                        existing.addresses.push(nmap_host.ip);
                        changed = true;
                    }
                    if nmap_host.hostname.is_some() && existing.hostname.is_none() {
                        existing.hostname.clone_from(&nmap_host.hostname);
                        changed = true;
                    }
                    if nmap_host.os_hint.is_some() && existing.os_hint.is_none() {
                        existing.os_hint.clone_from(&nmap_host.os_hint);
                        changed = true;
                    }
                    for svc in &new_services {
                        existing.services.push(svc.clone());
                        changed = true;
                    }
                    existing.last_seen = now;

                    if changed {
                        Some(existing.clone())
                    } else {
                        None
                    }
                };

                // Emit events outside the lock
                for svc in &new_services {
                    self.emit(Change::ServiceChanged {
                        mac: mac.clone(),
                        service: svc.clone(),
                        change_type: ChangeType::Added,
                    })
                    .await;
                }
                if let Some(host) = host {
                    self.emit(Change::HostUpdated(host.clone())).await;
                    self.db.upsert_host(&host).await?;
                }
            } else {
                let vendor = self.lookup_vendor(&mac);
                let host = HostInfo {
                    mac: mac.clone(),
                    vendor,
                    addresses: vec![nmap_host.ip],
                    hostname: nmap_host.hostname.clone(),
                    os_hint: nmap_host.os_hint.clone(),
                    services: nmap_host.services.clone(),
                    interface: interface.to_string(),
                    first_seen: now,
                    last_seen: now,
                };

                self.state.hosts.insert(mac.clone(), host.clone());
                self.emit(Change::HostAdded(host.clone())).await;
                self.db.upsert_host(&host).await?;
            }
        }

        Ok(())
    }

    // ── Internal ───────────────────────────────────────────────────────

    async fn emit(&self, change: Change) {
        let seq = self
            .state
            .sequence
            .fetch_add(1, Ordering::Relaxed)
            + 1;

        let event = DeltaEvent {
            sequence: seq,
            timestamp: Utc::now(),
            change,
        };

        {
            let mut log = self.event_log.write().await;
            if log.len() >= self.buffer_size {
                log.pop_front();
            }
            log.push_back(event.clone());
        }

        {
            let mut subs = self.subscribers.write().await;
            subs.retain(|tx| !tx.is_closed());
            for tx in subs.iter() {
                let _ = tx.try_send(event.clone());
            }
        }
    }
}
