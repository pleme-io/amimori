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

pub struct ProfilerService {
    engine: Arc<StateEngine>,
}

impl ProfilerService {
    pub fn new(engine: Arc<StateEngine>) -> Self {
        Self { engine }
    }
}

#[tonic::async_trait]
impl NetworkProfiler for ProfilerService {
    async fn get_snapshot(
        &self,
        request: Request<SnapshotRequest>,
    ) -> Result<Response<NetworkSnapshot>, Status> {
        let req = request.into_inner();
        let filter = if req.interface.is_empty() {
            None
        } else {
            Some(req.interface.as_str())
        };

        let snapshot = build_snapshot(&self.engine, filter);
        Ok(Response::new(snapshot))
    }

    type SubscribeStream = Pin<Box<dyn Stream<Item = Result<DeltaUpdate, Status>> + Send>>;

    async fn subscribe(
        &self,
        request: Request<SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let req = request.into_inner();
        let (tx, rx) = mpsc::channel(256);

        // Replay events since requested sequence
        let replay = self.engine.events_since(req.since_sequence).await;
        for event in replay {
            let update = delta_to_proto(&event);
            if tx.send(Ok(update)).await.is_err() {
                // Client already disconnected
                let empty = ReceiverStream::new(rx);
                return Ok(Response::new(Box::pin(empty)));
            }
        }

        // Subscribe to live updates
        let mut live_rx = self.engine.subscribe().await;
        tokio::spawn(async move {
            while let Some(event) = live_rx.recv().await {
                let update = delta_to_proto(&event);
                if tx.send(Ok(update)).await.is_err() {
                    break;
                }
            }
        });

        let stream = ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(stream)))
    }

    async fn get_host(
        &self,
        request: Request<HostRequest>,
    ) -> Result<Response<Host>, Status> {
        let addr = &request.into_inner().address;
        let host = self
            .engine
            .get_host(addr)
            .ok_or_else(|| Status::not_found(format!("host {addr} not found")))?;

        Ok(Response::new(host_to_proto(&host)))
    }

    async fn list_interfaces(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<InterfaceList>, Status> {
        let interfaces: Vec<NetworkInterface> = self
            .engine
            .state
            .interfaces
            .iter()
            .map(|entry| iface_to_proto(entry.value()))
            .collect();

        Ok(Response::new(InterfaceList { interfaces }))
    }

    async fn list_wifi_networks(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<WifiNetworkList>, Status> {
        let networks: Vec<WifiNetwork> = self
            .engine
            .state
            .wifi_networks
            .iter()
            .map(|entry| wifi_to_proto(entry.value()))
            .collect();

        Ok(Response::new(WifiNetworkList { networks }))
    }
}

// ── Server lifecycle ───────────────────────────────────────────────────────

pub async fn serve(
    engine: Arc<StateEngine>,
    port: u16,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let addr = format!("0.0.0.0:{port}").parse()?;
    let service = ProfilerService::new(engine);

    tracing::info!("gRPC server listening on {addr}");

    tonic::transport::Server::builder()
        .add_service(NetworkProfilerServer::new(service))
        .serve_with_shutdown(addr, cancel.cancelled_owned())
        .await?;

    tracing::info!("gRPC server stopped");
    Ok(())
}

// ── Proto conversion helpers ───────────────────────────────────────────────

fn build_snapshot(engine: &StateEngine, filter: Option<&str>) -> NetworkSnapshot {
    let now = Utc::now();

    let interfaces: Vec<NetworkInterface> = engine
        .state
        .interfaces
        .iter()
        .filter(|e| filter.is_none_or(|f| e.key() == f))
        .map(|e| iface_to_proto(e.value()))
        .collect();

    let hosts: Vec<Host> = engine
        .state
        .hosts
        .iter()
        .filter(|e| filter.is_none_or(|f| e.value().interface == f))
        .map(|e| host_to_proto(e.value()))
        .collect();

    let wifi_networks: Vec<WifiNetwork> = engine
        .state
        .wifi_networks
        .iter()
        .filter(|e| filter.is_none_or(|f| e.value().interface == f))
        .map(|e| wifi_to_proto(e.value()))
        .collect();

    let seq = engine
        .state
        .sequence
        .load(std::sync::atomic::Ordering::Relaxed);

    NetworkSnapshot {
        interfaces,
        hosts,
        wifi_networks,
        sequence: seq,
        timestamp: Some(to_timestamp(now)),
    }
}

fn host_to_proto(host: &HostInfo) -> Host {
    let services: Vec<Service> = host
        .services
        .iter()
        .map(|s| Service {
            port: u32::from(s.port),
            protocol: s.protocol.clone(),
            name: s.name.clone(),
            version: s.version.clone(),
            state: s.state.clone(),
        })
        .collect();

    Host {
        mac: host.mac.clone(),
        vendor: host.vendor.clone(),
        ipv4: host
            .addresses
            .iter()
            .filter(|a| a.is_ipv4())
            .map(ToString::to_string)
            .collect(),
        ipv6: host
            .addresses
            .iter()
            .filter(|a| a.is_ipv6())
            .map(ToString::to_string)
            .collect(),
        hostname: host.hostname.clone().unwrap_or_default(),
        os_hint: host.os_hint.clone().unwrap_or_default(),
        services,
        interface: host.interface.clone(),
        first_seen: Some(to_timestamp(host.first_seen)),
        last_seen: Some(to_timestamp(host.last_seen)),
    }
}

fn iface_to_proto(iface: &InterfaceInfo) -> NetworkInterface {
    NetworkInterface {
        name: iface.name.clone(),
        mac: iface.mac.clone(),
        ipv4: iface.ipv4.iter().map(ToString::to_string).collect(),
        ipv6: iface.ipv6.iter().map(ToString::to_string).collect(),
        gateway: iface.gateway.clone(),
        subnet: iface.subnet.clone(),
        is_up: iface.is_up,
        kind: iface.kind.to_string(),
        dns: iface.dns.clone(),
    }
}

fn wifi_to_proto(wifi: &WifiInfo) -> WifiNetwork {
    WifiNetwork {
        ssid: wifi.ssid.clone(),
        bssid: wifi.bssid.clone(),
        rssi: wifi.rssi,
        noise: wifi.noise,
        channel: wifi.channel,
        band: wifi.band.clone(),
        security: wifi.security.clone(),
        interface: wifi.interface.clone(),
    }
}

fn delta_to_proto(event: &DeltaEvent) -> DeltaUpdate {
    let change = match &event.change {
        Change::HostAdded(host) => proto::delta_update::Change::HostAdded(host_to_proto(host)),
        Change::HostRemoved { mac } => {
            proto::delta_update::Change::HostRemoved(Host {
                mac: mac.clone(),
                ..Default::default()
            })
        }
        Change::HostUpdated(host) => proto::delta_update::Change::HostUpdated(host_to_proto(host)),
        Change::ServiceChanged {
            mac,
            service,
            change_type,
        } => proto::delta_update::Change::ServiceChanged(ServiceChange {
            host_mac: mac.clone(),
            service: Some(Service {
                port: u32::from(service.port),
                protocol: service.protocol.clone(),
                name: service.name.clone(),
                version: service.version.clone(),
                state: service.state.clone(),
            }),
            change_type: change_type.to_string(),
        }),
        Change::WifiAdded(wifi) => proto::delta_update::Change::WifiAdded(wifi_to_proto(wifi)),
        Change::WifiRemoved { bssid } => {
            proto::delta_update::Change::WifiRemoved(WifiNetwork {
                bssid: bssid.clone(),
                ..Default::default()
            })
        }
        Change::WifiUpdated(wifi) => proto::delta_update::Change::WifiUpdated(wifi_to_proto(wifi)),
        Change::InterfaceChanged(iface) => {
            proto::delta_update::Change::InterfaceChanged(iface_to_proto(iface))
        }
    };

    DeltaUpdate {
        sequence: event.sequence,
        timestamp: Some(to_timestamp(event.timestamp)),
        change: Some(change),
    }
}

fn to_timestamp(dt: chrono::DateTime<Utc>) -> Timestamp {
    Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    }
}
