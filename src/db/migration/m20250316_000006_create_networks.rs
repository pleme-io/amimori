use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// ADR-015: Networks as first-class entities.
///
/// Each network the device connects to gets a row. Hosts are scoped to a
/// network via `hosts.network_id` (already exists — this migration adds the
/// parent table and upgrades the identity to a richer composite fingerprint).
///
/// Network identity = `gateway_mac|subnet_cidr` when gateway MAC is known,
/// falling back to `gateway_ip|subnet_mask` for compatibility.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Networks::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Networks::Id).string().not_null().primary_key())
                    .col(ColumnDef::new(Networks::Ssid).string().not_null().default(""))
                    .col(ColumnDef::new(Networks::GatewayMac).string().not_null().default(""))
                    .col(ColumnDef::new(Networks::GatewayIp).string().not_null().default(""))
                    .col(ColumnDef::new(Networks::SubnetCidr).string().not_null().default(""))
                    .col(ColumnDef::new(Networks::SubnetMask).string().not_null().default(""))
                    .col(ColumnDef::new(Networks::Interface).string().not_null().default(""))
                    .col(ColumnDef::new(Networks::TimesConnected).integer().not_null().default(1))
                    .col(ColumnDef::new(Networks::FirstSeen).timestamp_with_time_zone().not_null())
                    .col(ColumnDef::new(Networks::LastSeen).timestamp_with_time_zone().not_null())
                    .col(ColumnDef::new(Networks::DocumentJson).text().null())
                    .to_owned(),
            )
            .await?;

        // Index for quick lookup by SSID (human queries like "show my home network")
        manager
            .create_index(
                Index::create()
                    .name("idx_networks_ssid")
                    .table(Networks::Table)
                    .col(Networks::Ssid)
                    .to_owned(),
            )
            .await?;

        // Index for lookup by gateway MAC (network identity matching)
        manager
            .create_index(
                Index::create()
                    .name("idx_networks_gateway_mac")
                    .table(Networks::Table)
                    .col(Networks::GatewayMac)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Networks::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Networks {
    Table,
    Id,
    Ssid,
    GatewayMac,
    GatewayIp,
    SubnetCidr,
    SubnetMask,
    Interface,
    TimesConnected,
    FirstSeen,
    LastSeen,
    DocumentJson,
}
