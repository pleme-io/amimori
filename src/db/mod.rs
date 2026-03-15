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

use crate::model::{Change, DeltaEvent, HostInfo, InterfaceInfo, InterfaceKind, NetworkInfo, ServiceInfo, WifiInfo};
use crate::traits::StorageBackend;

/// Persistent storage backed by SQLite via SeaORM.
pub struct Database {
    conn: DatabaseConnection,
}

impl Database {
    /// Open (or create) the SQLite database, run migrations, and configure for production.
    ///
    /// Creates parent directories if needed. Applies all pending migrations.
    /// Enables WAL journal mode for concurrent read/write.
    pub async fn open(path: &Path) -> anyhow::Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                anyhow::anyhow!(
                    "cannot create database directory {}: {e}",
                    parent.display()
                )
            })?;
        }

        let url = format!("sqlite://{}?mode=rwc", path.display());
        let mut opts = ConnectOptions::new(&url);
        opts.sqlx_logging(false);

        // Connection pool: pre-heat connections for concurrent collector writes.
        // SQLite WAL mode supports concurrent readers + single writer, but having
        // a small pool avoids contention on the writer lock.
        opts.min_connections(2);
        opts.max_connections(8);
        opts.connect_timeout(std::time::Duration::from_secs(5));
        opts.idle_timeout(std::time::Duration::from_secs(300));

        tracing::debug!(path = %path.display(), "connecting to database (pool: 2-8 connections)");

        let conn = SeaDatabase::connect(opts).await.map_err(|e| {
            anyhow::anyhow!("cannot open database at {}: {e}", path.display())
        })?;

        // Run pending migrations
        tracing::debug!("running database migrations");
        migration::Migrator::up(&conn, None).await.map_err(|e| {
            anyhow::anyhow!("database migration failed: {e}")
        })?;

        // Configure SQLite for concurrent access and durability
        let pragmas = [
            "PRAGMA journal_mode=WAL",
            "PRAGMA synchronous=NORMAL",
            "PRAGMA foreign_keys=ON",
            "PRAGMA busy_timeout=5000",
        ];
        for pragma in &pragmas {
            sea_orm::ConnectionTrait::execute_unprepared(&conn, pragma)
                .await
                .map_err(|e| anyhow::anyhow!("{pragma} failed: {e}"))?;
        }

        // Quick integrity check
        let integrity: Vec<sea_orm::JsonValue> =
            sea_orm::ConnectionTrait::query_all(
                &conn,
                sea_orm::Statement::from_string(
                    sea_orm::DatabaseBackend::Sqlite,
                    "PRAGMA quick_check".to_string(),
                ),
            )
            .await
            .map_err(|e| anyhow::anyhow!("integrity check failed: {e}"))?
            .iter()
            .map(|row| {
                row.try_get_by_index::<String>(0)
                    .unwrap_or_else(|_| "unknown".to_string())
            })
            .map(serde_json::Value::String)
            .collect();

        let is_ok = integrity.first().and_then(|v| v.as_str()) == Some("ok");
        if !is_ok {
            tracing::error!(?integrity, "database integrity check failed");
            anyhow::bail!("database integrity check failed at {}", path.display());
        }

        tracing::info!(path = %path.display(), "database ready");
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

        // Serialize the full HostInfo as the SSOT document
        let document = serde_json::to_string(host)?;

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
                network_id: Set(host.network_id.clone()),
                first_seen: sea_orm::ActiveValue::NotSet,
                last_seen: Set(host.last_seen),
                document_json: Set(Some(document)),
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
                network_id: Set(host.network_id.clone()),
                first_seen: Set(host.first_seen),
                last_seen: Set(host.last_seen),
                document_json: Set(Some(document)),
            };
            active.insert(&self.conn).await?;
        }

        self.sync_services(&host.mac, &host.services).await?;
        Ok(())
    }

    async fn sync_services(&self, mac: &str, services: &[ServiceInfo]) -> anyhow::Result<()> {
        entity::service::Entity::delete_many()
            .filter(entity::service::Column::HostMac.eq(mac))
            .exec(&self.conn)
            .await?;

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
        // CASCADE will also remove services
        entity::host::Entity::delete_by_id(mac)
            .exec(&self.conn)
            .await?;
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn get_host(&self, mac: &str) -> anyhow::Result<Option<HostInfo>> {
        let Some(row) = entity::host::Entity::find_by_id(mac)
            .one(&self.conn)
            .await?
        else {
            return Ok(None);
        };

        let services = entity::service::Entity::find()
            .filter(entity::service::Column::HostMac.eq(mac))
            .all(&self.conn)
            .await?;

        Ok(Some(row_to_host_info(&row, &services)))
    }

    pub async fn all_hosts(&self) -> anyhow::Result<Vec<HostInfo>> {
        // Batch: two queries total (hosts + all services) instead of N+1.
        let (hosts, all_services) = tokio::try_join!(
            entity::host::Entity::find().all(&self.conn),
            entity::service::Entity::find().all(&self.conn),
        )?;

        // Group services by host MAC for O(1) lookup per host.
        let mut services_by_mac: std::collections::HashMap<String, Vec<entity::service::Model>> =
            std::collections::HashMap::with_capacity(hosts.len());
        for svc in all_services {
            services_by_mac
                .entry(svc.host_mac.clone())
                .or_default()
                .push(svc);
        }

        Ok(hosts
            .iter()
            .map(|host| {
                let services = services_by_mac
                    .get(&host.mac)
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]);
                row_to_host_info(host, services)
            })
            .collect())
    }

    // ── Interface operations ───────────────────────────────────────────

    pub async fn upsert_interface(&self, iface: &InterfaceInfo) -> anyhow::Result<()> {
        let ipv4: Vec<String> = iface.ipv4.iter().map(ToString::to_string).collect();
        let ipv6: Vec<String> = iface.ipv6.iter().map(ToString::to_string).collect();
        let document = serde_json::to_string(iface)?;

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
            document_json: Set(Some(document)),
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
        let document = serde_json::to_string(wifi)?;

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
            document_json: Set(Some(document)),
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

    // ── Network operations ──────────────────────────────────────────────

    pub async fn upsert_network(&self, network: &NetworkInfo) -> anyhow::Result<()> {
        let document = serde_json::to_string(network)?;

        let existing = entity::network::Entity::find_by_id(&network.id)
            .one(&self.conn)
            .await?;

        if let Some(row) = existing {
            let active = entity::network::ActiveModel {
                id: Set(network.id.clone()),
                ssid: Set(network.ssid.clone()),
                gateway_mac: Set(network.gateway_mac.clone()),
                gateway_ip: Set(network.gateway_ip.clone()),
                subnet_cidr: Set(network.subnet_cidr.clone()),
                subnet_mask: Set(network.subnet_mask.clone()),
                interface: Set(network.interface.clone()),
                times_connected: Set(row.times_connected),
                first_seen: sea_orm::ActiveValue::NotSet,
                last_seen: Set(network.last_seen),
                document_json: Set(Some(document)),
            };
            active.update(&self.conn).await?;
        } else {
            let active = entity::network::ActiveModel {
                id: Set(network.id.clone()),
                ssid: Set(network.ssid.clone()),
                gateway_mac: Set(network.gateway_mac.clone()),
                gateway_ip: Set(network.gateway_ip.clone()),
                subnet_cidr: Set(network.subnet_cidr.clone()),
                subnet_mask: Set(network.subnet_mask.clone()),
                interface: Set(network.interface.clone()),
                times_connected: Set(1),
                first_seen: Set(network.first_seen),
                last_seen: Set(network.last_seen),
                document_json: Set(Some(document)),
            };
            active.insert(&self.conn).await?;
        }
        Ok(())
    }

    /// Increment the connection counter for a known network.
    pub async fn bump_network_connection(&self, network_id: &str) -> anyhow::Result<()> {
        let Some(row) = entity::network::Entity::find_by_id(network_id)
            .one(&self.conn)
            .await?
        else {
            return Ok(());
        };
        let active = entity::network::ActiveModel {
            id: Set(row.id),
            times_connected: Set(row.times_connected + 1),
            last_seen: Set(Utc::now()),
            ..Default::default()
        };
        active.update(&self.conn).await?;
        Ok(())
    }

    /// Bulk-update all hosts from one network_id to another.
    pub async fn migrate_hosts_network_id(&self, old_id: &str, new_id: &str) -> anyhow::Result<u64> {
        let result = sea_orm::ConnectionTrait::execute(
            &self.conn,
            sea_orm::Statement::from_sql_and_values(
                sea_orm::DatabaseBackend::Sqlite,
                "UPDATE hosts SET network_id = $1 WHERE network_id = $2",
                [new_id.into(), old_id.into()],
            ),
        )
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn all_networks(&self) -> anyhow::Result<Vec<NetworkInfo>> {
        let rows = entity::network::Entity::find().all(&self.conn).await?;
        Ok(rows.into_iter().map(row_to_network_info).collect())
    }

    pub async fn get_network(&self, id: &str) -> anyhow::Result<Option<NetworkInfo>> {
        let row = entity::network::Entity::find_by_id(id)
            .one(&self.conn)
            .await?;
        Ok(row.map(row_to_network_info))
    }

    /// Load hosts scoped to a specific network.
    pub async fn hosts_for_network(&self, network_id: &str) -> anyhow::Result<Vec<HostInfo>> {
        let hosts = entity::host::Entity::find()
            .filter(entity::host::Column::NetworkId.eq(network_id))
            .all(&self.conn)
            .await?;

        let macs: Vec<String> = hosts.iter().map(|h| h.mac.clone()).collect();
        let all_services = if macs.is_empty() {
            vec![]
        } else {
            entity::service::Entity::find()
                .filter(entity::service::Column::HostMac.is_in(macs))
                .all(&self.conn)
                .await?
        };

        let mut services_by_mac: std::collections::HashMap<String, Vec<entity::service::Model>> =
            std::collections::HashMap::with_capacity(hosts.len());
        for svc in all_services {
            services_by_mac
                .entry(svc.host_mac.clone())
                .or_default()
                .push(svc);
        }

        Ok(hosts
            .iter()
            .map(|host| {
                let services = services_by_mac
                    .get(&host.mac)
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]);
                row_to_host_info(host, services)
            })
            .collect())
    }

    // ── Bulk restore ───────────────────────────────────────────────────

    /// Load all persisted state. Called once at daemon startup.
    pub async fn load_all(
        &self,
    ) -> anyhow::Result<(Vec<InterfaceInfo>, Vec<HostInfo>, Vec<WifiInfo>)> {
        let interfaces = self.all_interfaces().await?;
        let hosts = self.all_hosts().await?;
        let wifi = self.all_wifi().await?;
        Ok((interfaces, hosts, wifi))
    }

    // ── Event timeline ─────────────────────────────────────────────

    /// Persist a delta event to the durable timeline.
    pub async fn append_event(&self, event: &DeltaEvent) -> anyhow::Result<()> {
        let (event_type, subject_mac, subject_name) = classify_change(&event.change);

        let active = entity::event::ActiveModel {
            id: sea_orm::ActiveValue::NotSet,
            sequence: Set(event.sequence as i64),
            timestamp: Set(event.timestamp),
            event_type: Set(event_type.to_string()),
            subject_mac: Set(subject_mac),
            subject_name: Set(subject_name),
            change_json: Set(serde_json::to_string(&event.change)?),
        };
        active.insert(&self.conn).await?;
        Ok(())
    }

    /// Prune events older than `ttl_secs`. Returns count of deleted rows.
    pub async fn prune_events(&self, ttl_secs: u64) -> anyhow::Result<u64> {
        if ttl_secs == 0 {
            return Ok(0);
        }
        let cutoff = Utc::now() - chrono::Duration::seconds(ttl_secs as i64);
        let result = entity::event::Entity::delete_many()
            .filter(entity::event::Column::Timestamp.lt(cutoff))
            .exec(&self.conn)
            .await?;
        Ok(result.rows_affected)
    }
}

/// Extract event classification from a Change for indexed querying.
fn classify_change(change: &Change) -> (&'static str, String, String) {
    match change {
        Change::HostAdded(h) => (
            "host_added",
            h.mac.clone(),
            h.hostname.clone().unwrap_or_default(),
        ),
        Change::HostRemoved { mac } => ("host_removed", mac.clone(), String::new()),
        Change::HostUpdated(h) => (
            "host_updated",
            h.mac.clone(),
            h.hostname.clone().unwrap_or_default(),
        ),
        Change::ServiceChanged {
            mac,
            service,
            change_type,
        } => (
            match change_type {
                crate::model::ChangeType::Added => "service_added",
                crate::model::ChangeType::Removed => "service_removed",
                crate::model::ChangeType::Updated => "service_updated",
            },
            mac.clone(),
            format!("{}/{}", service.port, service.protocol),
        ),
        Change::WifiAdded(w) => ("wifi_added", w.bssid.clone(), w.ssid.clone()),
        Change::WifiRemoved { bssid } => ("wifi_removed", bssid.clone(), String::new()),
        Change::WifiUpdated(w) => ("wifi_updated", w.bssid.clone(), w.ssid.clone()),
        Change::InterfaceChanged(i) => ("interface_changed", String::new(), i.name.clone()),
        Change::NetworkChanged { interface, .. } => {
            ("network_changed", String::new(), interface.clone())
        }
    }
}

// ── Conversion helpers ─────────────────────────────────────────────────────

fn row_to_host_info(
    row: &entity::host::Model,
    services: &[entity::service::Model],
) -> HostInfo {
    // Prefer the SSOT document when available — it includes fingerprints,
    // banners, and all enrichment data that relational columns don't capture.
    if let Some(ref doc) = row.document_json {
        if let Ok(host) = serde_json::from_str::<HostInfo>(doc) {
            return host;
        }
        tracing::warn!(mac = %row.mac, "corrupt document_json, falling back to columns");
    }

    // Fallback: assemble from relational columns (pre-migration data)
    let ipv4: Vec<String> = serde_json::from_str(&row.ipv4_json).unwrap_or_else(|e| {
        tracing::warn!(mac = %row.mac, error = %e, "corrupt ipv4_json in database");
        Vec::new()
    });
    let ipv6: Vec<String> = serde_json::from_str(&row.ipv6_json).unwrap_or_else(|e| {
        tracing::warn!(mac = %row.mac, error = %e, "corrupt ipv6_json in database");
        Vec::new()
    });

    let addresses: Vec<IpAddr> = ipv4
        .iter()
        .chain(ipv6.iter())
        .filter_map(|s| s.parse().ok())
        .collect();

    let svcs = services
        .iter()
        .map(|s| ServiceInfo {
            port: s.port as u16,
            protocol: s.protocol.clone(),
            name: s.name.clone(),
            version: s.version.clone(),
            state: s.state.clone(),
            banner: String::new(),
        })
        .collect();

    HostInfo {
        mac: row.mac.clone(),
        vendor: row.vendor.clone(),
        addresses,
        hostname: row.hostname.clone(),
        os_hint: row.os_hint.clone(),
        services: svcs,
        fingerprints: Vec::new(),
        interface: row.interface.clone(),
        network_id: row.network_id.clone(),
        status: crate::model::HostStatus::default(),
        first_seen: row.first_seen.with_timezone(&Utc),
        last_seen: row.last_seen.with_timezone(&Utc),
    }
}

fn row_to_interface_info(row: entity::interface::Model) -> InterfaceInfo {
    // Prefer SSOT document when available
    if let Some(ref doc) = row.document_json {
        if let Ok(iface) = serde_json::from_str::<InterfaceInfo>(doc) {
            return iface;
        }
    }

    // Fallback: assemble from relational columns
    let ipv4: Vec<String> = serde_json::from_str(&row.ipv4_json).unwrap_or_default();
    let ipv6: Vec<String> = serde_json::from_str(&row.ipv6_json).unwrap_or_default();
    let dns: Vec<String> = serde_json::from_str(&row.dns_json).unwrap_or_default();

    InterfaceInfo {
        name: row.name,
        mac: row.mac,
        ipv4: ipv4.iter().filter_map(|s| s.parse().ok()).collect(),
        ipv6: ipv6.iter().filter_map(|s| s.parse().ok()).collect(),
        gateway: row.gateway,
        subnet: row.subnet,
        is_up: row.is_up,
        kind: match row.kind.as_str() {
            "wifi" => InterfaceKind::Wifi,
            "ethernet" => InterfaceKind::Ethernet,
            "tunnel" => InterfaceKind::Tunnel,
            "loopback" => InterfaceKind::Loopback,
            _ => InterfaceKind::Other,
        },
        dns,
    }
}

fn row_to_wifi_info(row: entity::wifi_network::Model) -> WifiInfo {
    // Prefer SSOT document when available
    if let Some(ref doc) = row.document_json {
        if let Ok(wifi) = serde_json::from_str::<WifiInfo>(doc) {
            return wifi;
        }
    }

    // Fallback: assemble from relational columns
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

fn row_to_network_info(row: entity::network::Model) -> NetworkInfo {
    if let Some(ref doc) = row.document_json {
        if let Ok(net) = serde_json::from_str::<NetworkInfo>(doc) {
            return net;
        }
    }
    NetworkInfo {
        id: row.id,
        ssid: row.ssid,
        gateway_mac: row.gateway_mac,
        gateway_ip: row.gateway_ip,
        subnet_cidr: row.subnet_cidr,
        subnet_mask: row.subnet_mask,
        interface: row.interface,
        times_connected: row.times_connected as u32,
        first_seen: row.first_seen.with_timezone(&Utc),
        last_seen: row.last_seen.with_timezone(&Utc),
    }
}

// ── StorageBackend trait implementation ─────────────────────────────────────

#[async_trait::async_trait]
impl StorageBackend for Database {
    async fn upsert_host(&self, host: &HostInfo) -> anyhow::Result<()> {
        self.upsert_host(host).await
    }

    async fn remove_host(&self, mac: &str) -> anyhow::Result<()> {
        self.remove_host(mac).await
    }

    async fn upsert_interface(&self, iface: &InterfaceInfo) -> anyhow::Result<()> {
        self.upsert_interface(iface).await
    }

    async fn upsert_wifi(&self, wifi: &WifiInfo) -> anyhow::Result<()> {
        self.upsert_wifi(wifi).await
    }

    async fn remove_wifi(&self, bssid: &str) -> anyhow::Result<()> {
        self.remove_wifi(bssid).await
    }

    async fn load_all(&self) -> anyhow::Result<(Vec<InterfaceInfo>, Vec<HostInfo>, Vec<WifiInfo>)> {
        self.load_all().await
    }

    async fn append_event(&self, event: &DeltaEvent) -> anyhow::Result<()> {
        self.append_event(event).await
    }

    async fn prune_events(&self, ttl_secs: u64) -> anyhow::Result<u64> {
        self.prune_events(ttl_secs).await
    }

    async fn upsert_network(&self, network: &NetworkInfo) -> anyhow::Result<()> {
        self.upsert_network(network).await
    }

    async fn hosts_for_network(&self, network_id: &str) -> anyhow::Result<Vec<HostInfo>> {
        self.hosts_for_network(network_id).await
    }

    async fn migrate_hosts_network_id(&self, old_id: &str, new_id: &str) -> anyhow::Result<u64> {
        self.migrate_hosts_network_id(old_id, new_id).await
    }

    async fn bump_network_connection(&self, network_id: &str) -> anyhow::Result<()> {
        self.bump_network_connection(network_id).await
    }

    async fn get_network(&self, id: &str) -> anyhow::Result<Option<NetworkInfo>> {
        self.get_network(id).await
    }

    async fn all_networks(&self) -> anyhow::Result<Vec<NetworkInfo>> {
        self.all_networks().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    // ── row_to_host_info ───────────────────────────────────────────────

    fn make_host_model(ipv4: &str, ipv6: &str) -> entity::host::Model {
        entity::host::Model {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            vendor: "Apple".into(),
            ipv4_json: ipv4.into(),
            ipv6_json: ipv6.into(),
            hostname: Some("test".into()),
            os_hint: None,
            interface: "en0".into(),
            network_id: "10.0.0.1|255.255.255.0".into(),
            first_seen: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            last_seen: Utc.with_ymd_and_hms(2025, 1, 2, 0, 0, 0).unwrap(),
            document_json: None, // test uses relational fallback
        }
    }

    #[test]
    fn row_to_host_info_basic() {
        let row = make_host_model(r#"["10.0.0.1"]"#, r#"["fe80::1"]"#);
        let host = row_to_host_info(&row, &[]);
        assert_eq!(host.mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(host.vendor, "Apple");
        assert_eq!(host.addresses.len(), 2);
        assert_eq!(host.hostname.as_deref(), Some("test"));
        assert_eq!(host.network_id, "10.0.0.1|255.255.255.0");
    }

    #[test]
    fn row_to_host_info_with_services() {
        let row = make_host_model(r#"["10.0.0.1"]"#, "[]");
        let services = vec![entity::service::Model {
            id: 1,
            host_mac: "aa:bb:cc:dd:ee:ff".into(),
            port: 443,
            protocol: "tcp".into(),
            name: "https".into(),
            version: "".into(),
            state: "open".into(),
        }];
        let host = row_to_host_info(&row, &services);
        assert_eq!(host.services.len(), 1);
        assert_eq!(host.services[0].port, 443);
        assert_eq!(host.services[0].name, "https");
    }

    #[test]
    fn row_to_host_info_corrupt_json_returns_empty() {
        let row = make_host_model("not valid json", "also bad");
        let host = row_to_host_info(&row, &[]);
        assert!(host.addresses.is_empty(), "corrupt JSON should produce empty addresses");
    }

    #[test]
    fn row_to_host_info_empty_json_arrays() {
        let row = make_host_model("[]", "[]");
        let host = row_to_host_info(&row, &[]);
        assert!(host.addresses.is_empty());
    }

    // ── row_to_interface_info ──────────────────────────────────────────

    #[test]
    fn row_to_interface_info_basic() {
        let row = entity::interface::Model {
            name: "en0".into(),
            mac: "aa:bb:cc:dd:ee:ff".into(),
            ipv4_json: r#"["10.0.0.5"]"#.into(),
            ipv6_json: "[]".into(),
            gateway: "10.0.0.1".into(),
            subnet: "255.255.255.0".into(),
            is_up: true,
            kind: "wifi".into(),
            dns_json: r#"["8.8.8.8"]"#.into(),
            document_json: None,
        };
        let iface = row_to_interface_info(row);
        assert_eq!(iface.name, "en0");
        assert_eq!(iface.kind, InterfaceKind::Wifi);
        assert!(iface.is_up);
        assert_eq!(iface.ipv4.len(), 1);
        assert_eq!(iface.dns, vec!["8.8.8.8"]);
    }

    #[test]
    fn row_to_interface_info_unknown_kind_defaults_to_other() {
        let row = entity::interface::Model {
            name: "bridge0".into(),
            mac: "".into(),
            ipv4_json: "[]".into(),
            ipv6_json: "[]".into(),
            gateway: "".into(),
            subnet: "".into(),
            is_up: false,
            kind: "bridge".into(),
            dns_json: "[]".into(),
            document_json: None,
        };
        let iface = row_to_interface_info(row);
        assert_eq!(iface.kind, InterfaceKind::Other);
    }

    #[test]
    fn row_to_interface_info_corrupt_json() {
        let row = entity::interface::Model {
            name: "en0".into(),
            mac: "".into(),
            ipv4_json: "bad".into(),
            ipv6_json: "bad".into(),
            gateway: "".into(),
            subnet: "".into(),
            is_up: true,
            kind: "wifi".into(),
            dns_json: "bad".into(),
            document_json: None,
        };
        let iface = row_to_interface_info(row);
        assert!(iface.ipv4.is_empty());
        assert!(iface.ipv6.is_empty());
        assert!(iface.dns.is_empty());
    }

    // ── row_to_wifi_info ───────────────────────────────────────────────

    #[test]
    #[test]
    fn row_to_host_info_prefers_document() {
        use crate::model::{Fingerprint, FingerprintSource};

        // Create a HostInfo with fingerprints
        let original = HostInfo {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            vendor: "Apple".into(),
            addresses: vec!["10.0.0.1".parse().unwrap()],
            hostname: Some("macbook.local".into()),
            os_hint: Some("macOS".into()),
            services: vec![],
            fingerprints: vec![Fingerprint {
                source: FingerprintSource::Mdns,
                category: "hw".into(),
                key: "model".into(),
                value: "MacBook Pro".into(),
                confidence: 0.95,
                observed_at: Utc::now(),
            }],
            interface: "en0".into(),
            network_id: "10.0.0.1|255.255.255.0".into(),
            status: crate::model::HostStatus::default(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        };

        // Serialize to document_json
        let doc = serde_json::to_string(&original).unwrap();

        let row = entity::host::Model {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            vendor: "Apple".into(),
            ipv4_json: r#"["10.0.0.1"]"#.into(),
            ipv6_json: "[]".into(),
            hostname: Some("macbook.local".into()),
            os_hint: Some("macOS".into()),
            interface: "en0".into(),
            network_id: "10.0.0.1|255.255.255.0".into(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            document_json: Some(doc),
        };

        let restored = row_to_host_info(&row, &[]);
        // Should use document, preserving fingerprints
        assert_eq!(restored.fingerprints.len(), 1);
        assert_eq!(restored.fingerprints[0].value, "MacBook Pro");
        assert_eq!(restored.hostname.as_deref(), Some("macbook.local"));
        assert_eq!(restored.os_hint.as_deref(), Some("macOS"));
    }

    #[test]
    fn row_to_host_info_falls_back_without_document() {
        let row = make_host_model(r#"["10.0.0.1"]"#, r#"["fe80::1"]"#);
        // document_json is None — should use relational columns
        let host = row_to_host_info(&row, &[]);
        assert_eq!(host.mac, "aa:bb:cc:dd:ee:ff");
        assert!(host.fingerprints.is_empty()); // no fingerprints from columns
    }

    #[test]
    fn row_to_host_info_corrupt_document_falls_back() {
        let mut row = make_host_model(r#"["10.0.0.1"]"#, "[]");
        row.document_json = Some("not valid json".into());
        let host = row_to_host_info(&row, &[]);
        // Should fall back to relational columns
        assert_eq!(host.mac, "aa:bb:cc:dd:ee:ff");
        assert!(host.fingerprints.is_empty());
    }

    #[test]
    fn row_to_wifi_info_basic() {
        let row = entity::wifi_network::Model {
            bssid: "11:22:33:44:55:66".into(),
            ssid: "TestNet".into(),
            rssi: -60,
            noise: -90,
            channel: 6,
            band: "2.4GHz".into(),
            security: "WPA2".into(),
            interface: "en0".into(),
            document_json: None,
        };
        let wifi = row_to_wifi_info(row);
        assert_eq!(wifi.ssid, "TestNet");
        assert_eq!(wifi.channel, 6);
        assert_eq!(wifi.rssi, -60);
    }
}
