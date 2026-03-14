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
                first_seen: sea_orm::ActiveValue::NotSet, // never overwrite creation time
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
                network_id: Set(host.network_id.clone()),
                first_seen: Set(host.first_seen),
                last_seen: Set(host.last_seen),
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
}

// ── Conversion helpers ─────────────────────────────────────────────────────

fn row_to_host_info(
    row: &entity::host::Model,
    services: &[entity::service::Model],
) -> HostInfo {
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
        network_id: row.network_id.clone(),
        first_seen: row.first_seen.with_timezone(&Utc),
        last_seen: row.last_seen.with_timezone(&Utc),
    }
}

fn row_to_interface_info(row: entity::interface::Model) -> InterfaceInfo {
    let ipv4: Vec<String> = serde_json::from_str(&row.ipv4_json).unwrap_or_else(|e| {
        tracing::warn!(name = %row.name, error = %e, "corrupt ipv4_json in database");
        Vec::new()
    });
    let ipv6: Vec<String> = serde_json::from_str(&row.ipv6_json).unwrap_or_else(|e| {
        tracing::warn!(name = %row.name, error = %e, "corrupt ipv6_json in database");
        Vec::new()
    });
    let dns: Vec<String> = serde_json::from_str(&row.dns_json).unwrap_or_else(|e| {
        tracing::warn!(name = %row.name, error = %e, "corrupt dns_json in database");
        Vec::new()
    });

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
}
