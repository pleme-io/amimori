pub mod entity;
pub mod migration;

use std::net::IpAddr;
use std::path::Path;

use chrono::Utc;
use sea_orm::ActiveValue::Set;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectOptions, Database as SeaDatabase, DatabaseConnection,
    EntityTrait, QueryFilter,
};
use sea_orm_migration::MigratorTrait;

use crate::model::{HostInfo, InterfaceInfo, InterfaceKind, ServiceInfo, WifiInfo};

/// Persistent storage backed by SQLite via SeaORM.
pub struct Database {
    conn: DatabaseConnection,
}

impl Database {
    /// Open (or create) the SQLite database and run migrations.
    pub async fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let url = format!("sqlite://{}?mode=rwc", path.display());
        let opts = ConnectOptions::new(&url);
        let conn = SeaDatabase::connect(opts).await?;

        // Run migrations
        migration::Migrator::up(&conn, None).await?;

        // Enable WAL mode for concurrent reads
        sea_orm::ConnectionTrait::execute_unprepared(
            &conn,
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;",
        )
        .await?;

        tracing::info!("database opened at {}", path.display());
        Ok(Self { conn })
    }

    // ── Host operations ────────────────────────────────────────────────

    pub async fn upsert_host(&self, host: &HostInfo) -> anyhow::Result<()> {
        let ipv4: Vec<String> = host
            .addresses
            .iter()
            .filter(|a| a.is_ipv4())
            .map(ToString::to_string)
            .collect();
        let ipv6: Vec<String> = host
            .addresses
            .iter()
            .filter(|a| a.is_ipv6())
            .map(ToString::to_string)
            .collect();

        let existing = entity::host::Entity::find_by_id(&host.mac)
            .one(&self.conn)
            .await?;

        if existing.is_some() {
            let active = entity::host::ActiveModel {
                mac: Set(host.mac.clone()),
                vendor: Set(host.vendor.clone()),
                ipv4_json: Set(serde_json::to_string(&ipv4)?),
                ipv6_json: Set(serde_json::to_string(&ipv6)?),
                hostname: Set(host.hostname.clone()),
                os_hint: Set(host.os_hint.clone()),
                interface: Set(host.interface.clone()),
                first_seen: sea_orm::ActiveValue::NotSet,
                last_seen: Set(host.last_seen),
            };
            active.update(&self.conn).await?;
        } else {
            let active = entity::host::ActiveModel {
                mac: Set(host.mac.clone()),
                vendor: Set(host.vendor.clone()),
                ipv4_json: Set(serde_json::to_string(&ipv4)?),
                ipv6_json: Set(serde_json::to_string(&ipv6)?),
                hostname: Set(host.hostname.clone()),
                os_hint: Set(host.os_hint.clone()),
                interface: Set(host.interface.clone()),
                first_seen: Set(host.first_seen),
                last_seen: Set(host.last_seen),
            };
            active.insert(&self.conn).await?;
        }

        // Sync services
        self.sync_services(&host.mac, &host.services).await?;

        Ok(())
    }

    async fn sync_services(&self, mac: &str, services: &[ServiceInfo]) -> anyhow::Result<()> {
        // Delete existing services for this host
        entity::service::Entity::delete_many()
            .filter(entity::service::Column::HostMac.eq(mac))
            .exec(&self.conn)
            .await?;

        // Insert current services
        for svc in services {
            let active = entity::service::ActiveModel {
                id: sea_orm::ActiveValue::NotSet,
                host_mac: Set(mac.to_string()),
                port: Set(i32::from(svc.port)),
                protocol: Set(svc.protocol.clone()),
                name: Set(svc.name.clone()),
                version: Set(svc.version.clone()),
                state: Set(svc.state.clone()),
            };
            active.insert(&self.conn).await?;
        }
        Ok(())
    }

    pub async fn remove_host(&self, mac: &str) -> anyhow::Result<()> {
        entity::host::Entity::delete_by_id(mac)
            .exec(&self.conn)
            .await?;
        Ok(())
    }

    pub async fn get_host(&self, mac: &str) -> anyhow::Result<Option<HostInfo>> {
        let row = entity::host::Entity::find_by_id(mac)
            .one(&self.conn)
            .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let services = entity::service::Entity::find()
            .filter(entity::service::Column::HostMac.eq(mac))
            .all(&self.conn)
            .await?;

        Ok(Some(row_to_host_info(&row, &services)))
    }

    pub async fn all_hosts(&self) -> anyhow::Result<Vec<HostInfo>> {
        let hosts = entity::host::Entity::find().all(&self.conn).await?;
        let mut result = Vec::with_capacity(hosts.len());

        for host in &hosts {
            let services = entity::service::Entity::find()
                .filter(entity::service::Column::HostMac.eq(&host.mac))
                .all(&self.conn)
                .await?;
            result.push(row_to_host_info(host, &services));
        }

        Ok(result)
    }

    // ── Interface operations ───────────────────────────────────────────

    pub async fn upsert_interface(&self, iface: &InterfaceInfo) -> anyhow::Result<()> {
        let ipv4: Vec<String> = iface
            .ipv4
            .iter()
            .map(ToString::to_string)
            .collect();
        let ipv6: Vec<String> = iface
            .ipv6
            .iter()
            .map(ToString::to_string)
            .collect();

        let existing = entity::interface::Entity::find_by_id(&iface.name)
            .one(&self.conn)
            .await?;

        let active = entity::interface::ActiveModel {
            name: Set(iface.name.clone()),
            mac: Set(iface.mac.clone()),
            ipv4_json: Set(serde_json::to_string(&ipv4)?),
            ipv6_json: Set(serde_json::to_string(&ipv6)?),
            gateway: Set(iface.gateway.clone()),
            subnet: Set(iface.subnet.clone()),
            is_up: Set(iface.is_up),
            kind: Set(iface.kind.to_string()),
            dns_json: Set(serde_json::to_string(&iface.dns)?),
        };

        if existing.is_some() {
            active.update(&self.conn).await?;
        } else {
            active.insert(&self.conn).await?;
        }

        Ok(())
    }

    pub async fn all_interfaces(&self) -> anyhow::Result<Vec<InterfaceInfo>> {
        let rows = entity::interface::Entity::find().all(&self.conn).await?;
        Ok(rows.into_iter().map(row_to_interface_info).collect())
    }

    // ── WiFi operations ────────────────────────────────────────────────

    pub async fn upsert_wifi(&self, wifi: &WifiInfo) -> anyhow::Result<()> {
        let existing = entity::wifi_network::Entity::find_by_id(&wifi.bssid)
            .one(&self.conn)
            .await?;

        let active = entity::wifi_network::ActiveModel {
            bssid: Set(wifi.bssid.clone()),
            ssid: Set(wifi.ssid.clone()),
            rssi: Set(wifi.rssi),
            noise: Set(wifi.noise),
            channel: Set(wifi.channel as i32),
            band: Set(wifi.band.clone()),
            security: Set(wifi.security.clone()),
            interface: Set(wifi.interface.clone()),
        };

        if existing.is_some() {
            active.update(&self.conn).await?;
        } else {
            active.insert(&self.conn).await?;
        }

        Ok(())
    }

    pub async fn remove_wifi(&self, bssid: &str) -> anyhow::Result<()> {
        entity::wifi_network::Entity::delete_by_id(bssid)
            .exec(&self.conn)
            .await?;
        Ok(())
    }

    pub async fn all_wifi(&self) -> anyhow::Result<Vec<WifiInfo>> {
        let rows = entity::wifi_network::Entity::find().all(&self.conn).await?;
        Ok(rows.into_iter().map(row_to_wifi_info).collect())
    }

    // ── Restore full state from DB ─────────────────────────────────────

    /// Load all persisted state. Called once at daemon startup.
    pub async fn load_all(
        &self,
    ) -> anyhow::Result<(Vec<InterfaceInfo>, Vec<HostInfo>, Vec<WifiInfo>)> {
        let interfaces = self.all_interfaces().await?;
        let hosts = self.all_hosts().await?;
        let wifi = self.all_wifi().await?;
        Ok((interfaces, hosts, wifi))
    }
}

// ── Conversion helpers ─────────────────────────────────────────────────────

fn row_to_host_info(
    row: &entity::host::Model,
    services: &[entity::service::Model],
) -> HostInfo {
    let ipv4: Vec<String> = serde_json::from_str(&row.ipv4_json).unwrap_or_default();
    let ipv6: Vec<String> = serde_json::from_str(&row.ipv6_json).unwrap_or_default();

    let mut addresses: Vec<IpAddr> = Vec::new();
    for s in &ipv4 {
        if let Ok(ip) = s.parse() {
            addresses.push(ip);
        }
    }
    for s in &ipv6 {
        if let Ok(ip) = s.parse() {
            addresses.push(ip);
        }
    }

    let svcs = services
        .iter()
        .map(|s| ServiceInfo {
            port: s.port as u16,
            protocol: s.protocol.clone(),
            name: s.name.clone(),
            version: s.version.clone(),
            state: s.state.clone(),
        })
        .collect();

    HostInfo {
        mac: row.mac.clone(),
        vendor: row.vendor.clone(),
        addresses,
        hostname: row.hostname.clone(),
        os_hint: row.os_hint.clone(),
        services: svcs,
        interface: row.interface.clone(),
        first_seen: row.first_seen.with_timezone(&Utc),
        last_seen: row.last_seen.with_timezone(&Utc),
    }
}

fn row_to_interface_info(row: entity::interface::Model) -> InterfaceInfo {
    let ipv4: Vec<String> = serde_json::from_str(&row.ipv4_json).unwrap_or_default();
    let ipv6: Vec<String> = serde_json::from_str(&row.ipv6_json).unwrap_or_default();
    let dns: Vec<String> = serde_json::from_str(&row.dns_json).unwrap_or_default();

    let ipv4_addrs = ipv4.iter().filter_map(|s| s.parse().ok()).collect();
    let ipv6_addrs = ipv6.iter().filter_map(|s| s.parse().ok()).collect();

    let kind = match row.kind.as_str() {
        "wifi" => InterfaceKind::Wifi,
        "ethernet" => InterfaceKind::Ethernet,
        "tunnel" => InterfaceKind::Tunnel,
        "loopback" => InterfaceKind::Loopback,
        _ => InterfaceKind::Other,
    };

    InterfaceInfo {
        name: row.name,
        mac: row.mac,
        ipv4: ipv4_addrs,
        ipv6: ipv6_addrs,
        gateway: row.gateway,
        subnet: row.subnet,
        is_up: row.is_up,
        kind,
        dns,
    }
}

fn row_to_wifi_info(row: entity::wifi_network::Model) -> WifiInfo {
    WifiInfo {
        ssid: row.ssid,
        bssid: row.bssid,
        rssi: row.rssi,
        noise: row.noise,
        channel: row.channel as u32,
        band: row.band,
        security: row.security,
        interface: row.interface,
    }
}
