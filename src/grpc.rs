use std::pin::Pin;
use std::sync::Arc;

use chrono::Utc;
use prost_types::Timestamp;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::{Stream, wrappers::ReceiverStream};
use tonic::{Request, Response, Status};
use tokio_util::sync::CancellationToken;

use crate::model::{Change, DeltaEvent, HostInfo, InterfaceInfo, ServiceInfo, WifiInfo};
use crate::state::StateEngine;

pub mod proto {
    tonic::include_proto!("amimori");
}

use proto::network_profiler_server::{NetworkProfiler, NetworkProfilerServer};
use proto::{
    ChangesRequest, ChangesResponse, DeltaUpdate, Empty, Host, HostRequest, InterfaceList,
    NetworkInterface, NetworkSnapshot, Service, ServiceChange, SnapshotRequest, SubscribeRequest,
    WifiNetwork, WifiNetworkList, NetworkList, NetworkRecord, NetworkHostsRequest,
    DbStatsResponse, DbMaintenanceResponse, PurgeEventsRequest,
};

struct ProfilerService {
    engine: Arc<StateEngine>,
}

#[tonic::async_trait]
impl NetworkProfiler for ProfilerService {
    async fn get_snapshot(
        &self,
        request: Request<SnapshotRequest>,
    ) -> Result<Response<NetworkSnapshot>, Status> {
        let filter = {
            let iface = &request.get_ref().interface;
            if iface.is_empty() {
                None
            } else {
                Some(iface.clone())
            }
        };

        Ok(Response::new(build_snapshot(
            &self.engine,
            filter.as_deref(),
        )))
    }

    async fn get_convergence(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<proto::ConvergenceStatus>, Status> {
        let conv = self.engine.convergence.score();
        let enriched = self.engine.state.hosts.iter()
            .filter(|e| !e.value().fingerprints.is_empty())
            .count() as u32;

        Ok(Response::new(proto::ConvergenceStatus {
            score: conv.score,
            phase: conv.phase.to_string(),
            since_new_host_secs: conv.since_new_host,
            since_new_service_secs: conv.since_new_service,
            stable_arp_cycles: conv.stable_arp_cycles,
            stable_nmap_cycles: conv.stable_nmap_cycles,
            collectors_reported: conv.collectors_reported,
            expected_collectors: conv.expected_collectors,
            uptime_secs: conv.uptime,
            total_hosts: self.engine.state.hosts.len() as u32,
            enriched_hosts: enriched,
        }))
    }

    async fn wait_for_convergence(
        &self,
        request: Request<proto::ConvergenceRequest>,
    ) -> Result<Response<proto::ConvergenceStatus>, Status> {
        let req = request.into_inner();
        let threshold = if req.threshold <= 0.0 { 0.95 } else { req.threshold };
        let timeout = if req.timeout_secs == 0 { 300 } else { req.timeout_secs };

        let score = self.engine.convergence.wait_for_convergence(
            &self.engine.convergence_notifier,
            threshold,
            std::time::Duration::from_secs(timeout as u64),
        ).await;

        let enriched = self.engine.state.hosts.iter()
            .filter(|e| !e.value().fingerprints.is_empty())
            .count() as u32;

        Ok(Response::new(proto::ConvergenceStatus {
            score: score.score,
            phase: score.phase.to_string(),
            since_new_host_secs: score.since_new_host,
            since_new_service_secs: score.since_new_service,
            stable_arp_cycles: score.stable_arp_cycles,
            stable_nmap_cycles: score.stable_nmap_cycles,
            collectors_reported: score.collectors_reported,
            expected_collectors: score.expected_collectors,
            uptime_secs: score.uptime,
            total_hosts: self.engine.state.hosts.len() as u32,
            enriched_hosts: enriched,
        }))
    }

    async fn get_changes(
        &self,
        request: Request<ChangesRequest>,
    ) -> Result<Response<ChangesResponse>, Status> {
        let req = request.into_inner();
        let limit = if req.limit == 0 { 50 } else { req.limit.min(500) } as usize;

        let all = self.engine.events_since(req.since_sequence).await;
        let events: Vec<DeltaUpdate> = all.iter().take(limit).map(delta_to_proto).collect();
        let seq = self.engine.state.sequence.load(std::sync::atomic::Ordering::Relaxed);

        Ok(Response::new(ChangesResponse {
            events,
            current_sequence: seq,
        }))
    }

    type SubscribeStream = Pin<Box<dyn Stream<Item = Result<DeltaUpdate, Status>> + Send>>;

    async fn subscribe(
        &self,
        request: Request<SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let req = request.into_inner();
        let (tx, rx) = mpsc::channel(256);

        // Replay events since requested sequence
        for event in self.engine.events_since(req.since_sequence).await {
            if tx.send(Ok(delta_to_proto(&event))).await.is_err() {
                return Ok(Response::new(Box::pin(ReceiverStream::new(rx))));
            }
        }

        // Stream live updates via broadcast receiver.
        // Lagged events are skipped (client can catch up via GetChanges).
        let mut live_rx = self.engine.subscribe();
        tokio::spawn(async move {
            loop {
                match live_rx.recv().await {
                    Ok(event) => {
                        if tx.send(Ok(delta_to_proto(&event))).await.is_err() {
                            break; // client disconnected
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::debug!(skipped = n, "gRPC subscriber lagged");
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn get_host(
        &self,
        request: Request<HostRequest>,
    ) -> Result<Response<Host>, Status> {
        let addr = &request.get_ref().address;
        self.engine
            .get_host(addr)
            .map(|h| Response::new(host_to_proto(&h)))
            .ok_or_else(|| Status::not_found(format!("host {addr} not found")))
    }

    async fn list_interfaces(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<InterfaceList>, Status> {
        let interfaces = self
            .engine
            .state
            .interfaces
            .iter()
            .map(|e| iface_to_proto(e.value()))
            .collect();
        Ok(Response::new(InterfaceList { interfaces }))
    }

    async fn list_wifi_networks(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<WifiNetworkList>, Status> {
        let networks = self
            .engine
            .state
            .wifi_networks
            .iter()
            .map(|e| wifi_to_proto(e.value()))
            .collect();
        Ok(Response::new(WifiNetworkList { networks }))
    }

    async fn list_networks(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<NetworkList>, Status> {
        let db_networks = self
            .engine
            .all_networks()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let mut records = Vec::with_capacity(db_networks.len());
        for net in &db_networks {
            let host_count = self
                .engine
                .hosts_for_network(&net.id)
                .await
                .map(|h| h.len() as u32)
                .unwrap_or(0);

            records.push(NetworkRecord {
                id: net.id.clone(),
                ssid: net.ssid.clone(),
                gateway_mac: net.gateway_mac.clone(),
                gateway_ip: net.gateway_ip.clone(),
                subnet_cidr: net.subnet_cidr.clone(),
                subnet_mask: net.subnet_mask.clone(),
                interface: net.interface.clone(),
                times_connected: net.times_connected,
                first_seen: Some(chrono_to_proto(net.first_seen)),
                last_seen: Some(chrono_to_proto(net.last_seen)),
                host_count,
            });
        }

        Ok(Response::new(NetworkList { networks: records }))
    }

    async fn get_network_hosts(
        &self,
        request: Request<NetworkHostsRequest>,
    ) -> Result<Response<NetworkSnapshot>, Status> {
        let network_id = &request.get_ref().network_id;
        let hosts = self
            .engine
            .hosts_for_network(network_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(NetworkSnapshot {
            interfaces: vec![],
            hosts: hosts.iter().map(host_to_proto).collect(),
            wifi_networks: vec![],
            sequence: self.engine.state.sequence.load(std::sync::atomic::Ordering::Relaxed),
            timestamp: Some(chrono_to_proto(Utc::now())),
        }))
    }

    // ── Database maintenance RPCs ─────────────────────────────────────

    async fn db_stats(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<DbStatsResponse>, Status> {
        let (networks, hosts, services, events, interfaces, wifi) = self
            .engine.db().table_counts().await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(DbStatsResponse {
            db_path: String::new(),
            db_size_bytes: 0, // Could stat the file but path isn't easily accessible
            total_networks: networks,
            total_hosts: hosts,
            total_services: services,
            total_events: events,
            total_interfaces: interfaces,
            total_wifi_networks: wifi,
        }))
    }

    async fn db_reset(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<DbMaintenanceResponse>, Status> {
        let rows = self.engine.db().reset_all().await
            .map_err(|e| Status::internal(e.to_string()))?;
        self.engine.clear_memory();
        Ok(Response::new(DbMaintenanceResponse {
            action: "reset".into(),
            rows_affected: rows,
            message: format!("deleted {rows} rows from all tables, cleared in-memory state"),
        }))
    }

    async fn db_delete_network(
        &self,
        request: Request<NetworkHostsRequest>,
    ) -> Result<Response<DbMaintenanceResponse>, Status> {
        let network_id = &request.get_ref().network_id;
        let rows = self.engine.db().delete_network(network_id).await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(DbMaintenanceResponse {
            action: "delete_network".into(),
            rows_affected: rows,
            message: format!("deleted network {network_id} and {rows} associated rows"),
        }))
    }

    async fn db_purge_stale_hosts(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<DbMaintenanceResponse>, Status> {
        let rows = self.engine.db().purge_stale_hosts().await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(DbMaintenanceResponse {
            action: "purge_stale_hosts".into(),
            rows_affected: rows,
            message: format!("purged {rows} stale hosts"),
        }))
    }

    async fn db_purge_events(
        &self,
        request: Request<PurgeEventsRequest>,
    ) -> Result<Response<DbMaintenanceResponse>, Status> {
        let older_than = request.get_ref().older_than_secs;
        let rows = if older_than == 0 {
            self.engine.db().purge_all_events().await
        } else {
            self.engine.db().prune_events(older_than).await
        }.map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(DbMaintenanceResponse {
            action: "purge_events".into(),
            rows_affected: rows,
            message: format!("purged {rows} events"),
        }))
    }

    async fn db_vacuum(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<DbMaintenanceResponse>, Status> {
        self.engine.db().vacuum().await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(DbMaintenanceResponse {
            action: "vacuum".into(),
            rows_affected: 0,
            message: "database vacuumed".into(),
        }))
    }
}

// ── Public proto→model conversions (used by CLI and MCP) ──────────────────

/// Convert a proto Host to the domain HostInfo. Shared by CLI, MCP, and
/// any other consumer that receives proto messages and needs the domain type.
pub fn proto_to_host_info(h: &Host) -> HostInfo {
    HostInfo {
        mac: h.mac.clone(),
        vendor: h.vendor.clone(),
        addresses: h.ipv4.iter().chain(h.ipv6.iter())
            .filter_map(|s| s.parse().ok()).collect(),
        hostname: if h.hostname.is_empty() { None } else { Some(h.hostname.clone()) },
        os_hint: if h.os_hint.is_empty() { None } else { Some(h.os_hint.clone()) },
        services: h.services.iter().map(|s| ServiceInfo {
            port: s.port as u16, protocol: s.protocol.clone(),
            name: s.name.clone(), version: s.version.clone(),
            state: s.state.clone(), banner: String::new(),
        }).collect(),
        fingerprints: h.fingerprints.iter().map(|f| crate::model::Fingerprint {
            source: match f.source.as_str() {
                "arp" => crate::model::FingerprintSource::Arp,
                "nmap" => crate::model::FingerprintSource::Nmap,
                "mdns" => crate::model::FingerprintSource::Mdns,
                "tls" => crate::model::FingerprintSource::Tls,
                "banner" => crate::model::FingerprintSource::Banner,
                "dhcp" => crate::model::FingerprintSource::Dhcp,
                "passive" => crate::model::FingerprintSource::Passive,
                _ => crate::model::FingerprintSource::Manual,
            },
            category: f.category.clone(),
            key: f.key.clone(),
            value: f.value.clone(),
            confidence: f.confidence,
            observed_at: chrono::Utc::now(),
        }).collect(),
        interface: h.interface.clone(),
        network_id: h.network_id.clone(),
        status: crate::model::HostStatus::default(),
        first_seen: h.first_seen.as_ref().map(|t| {
            chrono::DateTime::from_timestamp(t.seconds, t.nanos as u32)
                .unwrap_or_default()
        }).unwrap_or_default(),
        last_seen: h.last_seen.as_ref().map(|t| {
            chrono::DateTime::from_timestamp(t.seconds, t.nanos as u32)
                .unwrap_or_default()
        }).unwrap_or_default(),
    }
}

/// Convert a proto NetworkInterface to the domain InterfaceInfo.
pub fn proto_to_interface_info(i: &NetworkInterface) -> InterfaceInfo {
    InterfaceInfo {
        name: i.name.clone(),
        mac: i.mac.clone(),
        ipv4: i.ipv4.iter().filter_map(|s| s.parse().ok()).collect(),
        ipv6: i.ipv6.iter().filter_map(|s| s.parse().ok()).collect(),
        gateway: i.gateway.clone(),
        subnet: i.subnet.clone(),
        is_up: i.is_up,
        kind: crate::model::InterfaceKind::from_name(&i.name),
        dns: i.dns.clone(),
    }
}

// ── Server lifecycle ───────────────────────────────────────────────────────

pub async fn serve(
    engine: Arc<StateEngine>,
    addr: &str,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let addr = addr.parse()?;
    tracing::info!(%addr, "gRPC server listening");

    tonic::transport::Server::builder()
        // Pre-warm the accept loop — tonic handles connection concurrency internally
        // via tokio tasks but we configure limits to prevent resource exhaustion.
        .concurrency_limit_per_connection(64)
        .tcp_keepalive(Some(std::time::Duration::from_secs(60)))
        .add_service(NetworkProfilerServer::new(ProfilerService { engine }))
        .serve_with_shutdown(addr, cancel.cancelled_owned())
        .await?;

    tracing::info!("gRPC server stopped");
    Ok(())
}

// ── Proto conversions ──────────────────────────────────────────────────────

fn build_snapshot(engine: &StateEngine, filter: Option<&str>) -> NetworkSnapshot {
    let seq = engine.state.sequence.load(std::sync::atomic::Ordering::Relaxed);

    let interfaces = engine
        .state
        .interfaces
        .iter()
        .filter(|e| filter.is_none_or(|f| e.key() == f))
        .map(|e| iface_to_proto(e.value()))
        .collect();

    let hosts = engine
        .state
        .hosts
        .iter()
        .filter(|e| filter.is_none_or(|f| e.value().interface == f))
        .map(|e| host_to_proto(e.value()))
        .collect();

    let wifi_networks = engine
        .state
        .wifi_networks
        .iter()
        .filter(|e| filter.is_none_or(|f| e.value().interface == f))
        .map(|e| wifi_to_proto(e.value()))
        .collect();

    NetworkSnapshot {
        interfaces,
        hosts,
        wifi_networks,
        sequence: seq,
        timestamp: Some(chrono_to_proto(Utc::now())),
    }
}

fn host_to_proto(h: &HostInfo) -> Host {
    Host {
        mac: h.mac.clone(),
        vendor: h.vendor.clone(),
        ipv4: h.addresses.iter().filter(|a| a.is_ipv4()).map(ToString::to_string).collect(),
        ipv6: h.addresses.iter().filter(|a| a.is_ipv6()).map(ToString::to_string).collect(),
        hostname: h.hostname.clone().unwrap_or_default(),
        os_hint: h.os_hint.clone().unwrap_or_default(),
        services: h.services.iter().map(svc_to_proto).collect(),
        interface: h.interface.clone(),
        first_seen: Some(chrono_to_proto(h.first_seen)),
        last_seen: Some(chrono_to_proto(h.last_seen)),
        outlier_score: h.outlier_score(),
        fingerprints: h.fingerprints.iter().map(fp_to_proto).collect(),
        network_id: h.network_id.clone(),
        status: format!("{}", h.status),
    }
}

fn fp_to_proto(fp: &crate::model::Fingerprint) -> proto::Fingerprint {
    proto::Fingerprint {
        source: fp.source.to_string(),
        category: fp.category.clone(),
        key: fp.key.clone(),
        value: fp.value.clone(),
        confidence: fp.confidence,
    }
}

fn iface_to_proto(i: &InterfaceInfo) -> NetworkInterface {
    NetworkInterface {
        name: i.name.clone(),
        mac: i.mac.clone(),
        ipv4: i.ipv4.iter().map(ToString::to_string).collect(),
        ipv6: i.ipv6.iter().map(ToString::to_string).collect(),
        gateway: i.gateway.clone(),
        subnet: i.subnet.clone(),
        is_up: i.is_up,
        kind: i.kind.to_string(),
        dns: i.dns.clone(),
    }
}

fn wifi_to_proto(w: &WifiInfo) -> WifiNetwork {
    WifiNetwork {
        ssid: w.ssid.clone(),
        bssid: w.bssid.clone(),
        rssi: w.rssi,
        noise: w.noise,
        channel: w.channel,
        band: w.band.clone(),
        security: w.security.clone(),
        interface: w.interface.clone(),
    }
}

fn svc_to_proto(s: &ServiceInfo) -> Service {
    Service {
        port: u32::from(s.port),
        protocol: s.protocol.clone(),
        name: s.name.clone(),
        version: s.version.clone(),
        state: s.state.clone(),
    }
}

fn delta_to_proto(event: &DeltaEvent) -> DeltaUpdate {
    let change = match &event.change {
        Change::HostAdded(h) => proto::delta_update::Change::HostAdded(host_to_proto(h)),
        Change::HostRemoved { mac } => proto::delta_update::Change::HostRemoved(Host {
            mac: mac.clone(),
            ..Default::default()
        }),
        Change::HostUpdated(h) => proto::delta_update::Change::HostUpdated(host_to_proto(h)),
        Change::ServiceChanged {
            mac,
            service,
            change_type,
        } => proto::delta_update::Change::ServiceChanged(ServiceChange {
            host_mac: mac.clone(),
            service: Some(svc_to_proto(service)),
            change_type: change_type.to_string(),
        }),
        Change::WifiAdded(w) => proto::delta_update::Change::WifiAdded(wifi_to_proto(w)),
        Change::WifiRemoved { bssid } => proto::delta_update::Change::WifiRemoved(WifiNetwork {
            bssid: bssid.clone(),
            ..Default::default()
        }),
        Change::WifiUpdated(w) => proto::delta_update::Change::WifiUpdated(wifi_to_proto(w)),
        Change::InterfaceChanged(i) => {
            proto::delta_update::Change::InterfaceChanged(iface_to_proto(i))
        }
        Change::NetworkChanged {
            interface,
            old_network_id,
            new_network_id,
            hosts_cleared,
        } => proto::delta_update::Change::NetworkChanged(proto::NetworkChange {
            interface: interface.clone(),
            old_network_id: old_network_id.clone(),
            new_network_id: new_network_id.clone(),
            hosts_cleared: *hosts_cleared as u32,
        })
    };

    DeltaUpdate {
        sequence: event.sequence,
        timestamp: Some(chrono_to_proto(event.timestamp)),
        change: Some(change),
    }
}

fn chrono_to_proto(dt: chrono::DateTime<Utc>) -> Timestamp {
    Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FilterConfig;
    use crate::model::{
        Change, ChangeType, InterfaceKind, ServiceInfo,
    };
    use crate::traits::mocks::{InMemoryStorage, MockVendorLookup};
    use chrono::TimeZone;

    fn test_host() -> HostInfo {
        HostInfo {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            vendor: "TestVendor".into(),
            addresses: vec![
                "10.0.0.1".parse().unwrap(),
                "fe80::1".parse().unwrap(),
            ],
            hostname: Some("myhost".into()),
            os_hint: None,
            services: vec![ServiceInfo {
                port: 22,
                protocol: "tcp".into(),
                name: "ssh".into(),
                version: "OpenSSH 9".into(),
                state: "open".into(),
                banner: String::new(),
            }],
            fingerprints: vec![],
            interface: "en0".into(),
            network_id: "10.0.0.1|255.255.255.0".into(),
            status: crate::model::HostStatus::default(),
            first_seen: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            last_seen: Utc.with_ymd_and_hms(2025, 1, 2, 0, 0, 0).unwrap(),
        }
    }

    fn test_iface() -> InterfaceInfo {
        InterfaceInfo {
            name: "en0".into(),
            mac: "aa:bb:cc:dd:ee:ff".into(),
            ipv4: vec!["10.0.0.5".parse().unwrap()],
            ipv6: vec!["fe80::5".parse().unwrap()],
            gateway: "10.0.0.1".into(),
            subnet: "255.255.255.0".into(),
            is_up: true,
            kind: InterfaceKind::Wifi,
            dns: vec!["8.8.8.8".into(), "8.8.4.4".into()],
        }
    }

    fn test_wifi() -> WifiInfo {
        WifiInfo {
            ssid: "TestNet".into(),
            bssid: "11:22:33:44:55:66".into(),
            rssi: -55,
            noise: -90,
            channel: 36,
            band: "5GHz".into(),
            security: "WPA3 Personal".into(),
            interface: "en0".into(),
        }
    }

    // ── chrono_to_proto ────────────────────────────────────────────────

    #[test]
    fn chrono_to_proto_known_timestamp() {
        let dt = Utc.with_ymd_and_hms(2025, 6, 15, 12, 30, 45).unwrap();
        let ts = chrono_to_proto(dt);
        assert_eq!(ts.seconds, dt.timestamp());
        assert_eq!(ts.nanos, 0);
    }

    #[test]
    fn chrono_to_proto_epoch() {
        let dt = Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap();
        let ts = chrono_to_proto(dt);
        assert_eq!(ts.seconds, 0);
        assert_eq!(ts.nanos, 0);
    }

    // ── host_to_proto ──────────────────────────────────────────────────

    #[test]
    fn host_to_proto_splits_ipv4_ipv6() {
        let h = test_host();
        let p = host_to_proto(&h);
        assert_eq!(p.ipv4, vec!["10.0.0.1"]);
        assert_eq!(p.ipv6, vec!["fe80::1"]);
    }

    #[test]
    fn host_to_proto_maps_fields() {
        let h = test_host();
        let p = host_to_proto(&h);
        assert_eq!(p.mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(p.vendor, "TestVendor");
        assert_eq!(p.hostname, "myhost");
        assert_eq!(p.interface, "en0");
        assert!(p.first_seen.is_some());
        assert!(p.last_seen.is_some());
    }

    #[test]
    fn host_to_proto_converts_services() {
        let h = test_host();
        let p = host_to_proto(&h);
        assert_eq!(p.services.len(), 1);
        assert_eq!(p.services[0].port, 22);
        assert_eq!(p.services[0].name, "ssh");
        assert_eq!(p.services[0].version, "OpenSSH 9");
        assert_eq!(p.services[0].state, "open");
    }

    #[test]
    fn host_to_proto_none_fields_default_empty() {
        let mut h = test_host();
        h.hostname = None;
        h.os_hint = None;
        let p = host_to_proto(&h);
        assert_eq!(p.hostname, "");
        assert_eq!(p.os_hint, "");
    }

    // ── iface_to_proto ─────────────────────────────────────────────────

    #[test]
    fn iface_to_proto_maps_all_fields() {
        let i = test_iface();
        let p = iface_to_proto(&i);
        assert_eq!(p.name, "en0");
        assert_eq!(p.mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(p.ipv4, vec!["10.0.0.5"]);
        assert_eq!(p.ipv6, vec!["fe80::5"]);
        assert_eq!(p.gateway, "10.0.0.1");
        assert_eq!(p.subnet, "255.255.255.0");
        assert!(p.is_up);
        assert_eq!(p.kind, "wifi");
        assert_eq!(p.dns, vec!["8.8.8.8", "8.8.4.4"]);
    }

    // ── wifi_to_proto ──────────────────────────────────────────────────

    #[test]
    fn wifi_to_proto_maps_all_fields() {
        let w = test_wifi();
        let p = wifi_to_proto(&w);
        assert_eq!(p.ssid, "TestNet");
        assert_eq!(p.bssid, "11:22:33:44:55:66");
        assert_eq!(p.rssi, -55);
        assert_eq!(p.noise, -90);
        assert_eq!(p.channel, 36);
        assert_eq!(p.band, "5GHz");
        assert_eq!(p.security, "WPA3 Personal");
        assert_eq!(p.interface, "en0");
    }

    // ── svc_to_proto ───────────────────────────────────────────────────

    #[test]
    fn svc_to_proto_maps_port_as_u32() {
        let s = ServiceInfo {
            port: 443,
            protocol: "tcp".into(),
            name: "https".into(),
            version: "".into(),
            state: "open".into(), banner: String::new(),
        };
        let p = svc_to_proto(&s);
        assert_eq!(p.port, 443);
        assert_eq!(p.protocol, "tcp");
        assert_eq!(p.name, "https");
    }

    // ── delta_to_proto ─────────────────────────────────────────────────

    #[test]
    fn delta_to_proto_host_added() {
        let event = DeltaEvent {
            sequence: 1,
            timestamp: Utc::now(),
            change: Change::HostAdded(test_host()),
        };
        let p = delta_to_proto(&event);
        assert_eq!(p.sequence, 1);
        assert!(p.timestamp.is_some());
        assert!(matches!(
            p.change,
            Some(proto::delta_update::Change::HostAdded(_))
        ));
    }

    #[test]
    fn delta_to_proto_host_removed() {
        let event = DeltaEvent {
            sequence: 2,
            timestamp: Utc::now(),
            change: Change::HostRemoved {
                mac: "aa:bb:cc:dd:ee:ff".into(),
            },
        };
        let p = delta_to_proto(&event);
        if let Some(proto::delta_update::Change::HostRemoved(h)) = p.change {
            assert_eq!(h.mac, "aa:bb:cc:dd:ee:ff");
        } else {
            panic!("expected HostRemoved");
        }
    }

    #[test]
    fn delta_to_proto_host_updated() {
        let event = DeltaEvent {
            sequence: 3,
            timestamp: Utc::now(),
            change: Change::HostUpdated(test_host()),
        };
        let p = delta_to_proto(&event);
        assert!(matches!(
            p.change,
            Some(proto::delta_update::Change::HostUpdated(_))
        ));
    }

    #[test]
    fn delta_to_proto_service_changed() {
        let event = DeltaEvent {
            sequence: 4,
            timestamp: Utc::now(),
            change: Change::ServiceChanged {
                mac: "aa:bb:cc:dd:ee:ff".into(),
                service: ServiceInfo {
                    port: 80,
                    protocol: "tcp".into(),
                    name: "http".into(),
                    version: "".into(),
                    state: "open".into(), banner: String::new(),
                },
                change_type: ChangeType::Added,
            },
        };
        let p = delta_to_proto(&event);
        if let Some(proto::delta_update::Change::ServiceChanged(sc)) = p.change {
            assert_eq!(sc.host_mac, "aa:bb:cc:dd:ee:ff");
            assert_eq!(sc.change_type, "added");
            assert_eq!(sc.service.unwrap().port, 80);
        } else {
            panic!("expected ServiceChanged");
        }
    }

    #[test]
    fn delta_to_proto_wifi_added() {
        let event = DeltaEvent {
            sequence: 5,
            timestamp: Utc::now(),
            change: Change::WifiAdded(test_wifi()),
        };
        let p = delta_to_proto(&event);
        assert!(matches!(
            p.change,
            Some(proto::delta_update::Change::WifiAdded(_))
        ));
    }

    #[test]
    fn delta_to_proto_wifi_removed() {
        let event = DeltaEvent {
            sequence: 6,
            timestamp: Utc::now(),
            change: Change::WifiRemoved {
                bssid: "11:22:33:44:55:66".into(),
            },
        };
        let p = delta_to_proto(&event);
        if let Some(proto::delta_update::Change::WifiRemoved(w)) = p.change {
            assert_eq!(w.bssid, "11:22:33:44:55:66");
        } else {
            panic!("expected WifiRemoved");
        }
    }

    #[test]
    fn delta_to_proto_wifi_updated() {
        let event = DeltaEvent {
            sequence: 7,
            timestamp: Utc::now(),
            change: Change::WifiUpdated(test_wifi()),
        };
        let p = delta_to_proto(&event);
        assert!(matches!(
            p.change,
            Some(proto::delta_update::Change::WifiUpdated(_))
        ));
    }

    #[test]
    fn delta_to_proto_interface_changed() {
        let event = DeltaEvent {
            sequence: 8,
            timestamp: Utc::now(),
            change: Change::InterfaceChanged(test_iface()),
        };
        let p = delta_to_proto(&event);
        assert!(matches!(
            p.change,
            Some(proto::delta_update::Change::InterfaceChanged(_))
        ));
    }

    #[test]
    fn delta_to_proto_network_changed() {
        let event = DeltaEvent {
            sequence: 9,
            timestamp: Utc::now(),
            change: Change::NetworkChanged {
                interface: "en0".into(),
                old_network_id: "10.0.0.1|255.255.255.0".into(),
                new_network_id: "192.168.1.1|255.255.255.0".into(),
                hosts_cleared: 5,
            },
        };
        let p = delta_to_proto(&event);
        if let Some(proto::delta_update::Change::NetworkChanged(nc)) = p.change {
            assert_eq!(nc.interface, "en0");
            assert_eq!(nc.old_network_id, "10.0.0.1|255.255.255.0");
            assert_eq!(nc.new_network_id, "192.168.1.1|255.255.255.0");
            assert_eq!(nc.hosts_cleared, 5);
        } else {
            panic!("expected NetworkChanged");
        }
    }

    // ── build_snapshot ─────────────────────────────────────────────────

    #[test]
    fn build_snapshot_empty_state() {
        let engine = StateEngine::with_mocks(
            Arc::new(InMemoryStorage::new()),
            Arc::new(MockVendorLookup::empty()),
            FilterConfig::default(),
            100,
        );
        let snap = build_snapshot(&engine, None);
        assert!(snap.interfaces.is_empty());
        assert!(snap.hosts.is_empty());
        assert!(snap.wifi_networks.is_empty());
        assert_eq!(snap.sequence, 0);
        assert!(snap.timestamp.is_some());
    }

    #[test]
    fn build_snapshot_with_data() {
        let engine = StateEngine::with_mocks(
            Arc::new(InMemoryStorage::new()),
            Arc::new(MockVendorLookup::empty()),
            FilterConfig::default(),
            100,
        );
        engine
            .state
            .interfaces
            .insert("en0".into(), test_iface());
        engine
            .state
            .hosts
            .insert("aa:bb:cc:dd:ee:ff".into(), test_host());
        engine
            .state
            .wifi_networks
            .insert("11:22:33:44:55:66".into(), test_wifi());

        let snap = build_snapshot(&engine, None);
        assert_eq!(snap.interfaces.len(), 1);
        assert_eq!(snap.hosts.len(), 1);
        assert_eq!(snap.wifi_networks.len(), 1);
    }

    #[test]
    fn build_snapshot_filters_by_interface() {
        let engine = StateEngine::with_mocks(
            Arc::new(InMemoryStorage::new()),
            Arc::new(MockVendorLookup::empty()),
            FilterConfig::default(),
            100,
        );
        engine
            .state
            .interfaces
            .insert("en0".into(), test_iface());

        let mut iface2 = test_iface();
        iface2.name = "en4".into();
        engine.state.interfaces.insert("en4".into(), iface2);

        let snap = build_snapshot(&engine, Some("en0"));
        assert_eq!(snap.interfaces.len(), 1);
        assert_eq!(snap.interfaces[0].name, "en0");
    }
}
