use std::pin::Pin;
use std::sync::Arc;

use chrono::Utc;
use prost_types::Timestamp;
use tokio::sync::mpsc;
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
    DeltaUpdate, Empty, Host, HostRequest, InterfaceList, NetworkInterface, NetworkSnapshot,
    Service, ServiceChange, SnapshotRequest, SubscribeRequest, WifiNetwork, WifiNetworkList,
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

        // Stream live updates
        let mut live_rx = self.engine.subscribe().await;
        tokio::spawn(async move {
            while let Some(event) = live_rx.recv().await {
                if tx.send(Ok(delta_to_proto(&event))).await.is_err() {
                    break;
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
        Change::NetworkChanged { interface, .. } => {
            // Map network transitions to interface change in proto
            proto::delta_update::Change::InterfaceChanged(NetworkInterface {
                name: interface.clone(),
                ..Default::default()
            })
        }
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
