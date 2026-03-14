use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Hosts::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Hosts::Mac).string().not_null().primary_key())
                    .col(ColumnDef::new(Hosts::Vendor).string().not_null().default(""))
                    .col(ColumnDef::new(Hosts::Ipv4Json).string().not_null().default("[]"))
                    .col(ColumnDef::new(Hosts::Ipv6Json).string().not_null().default("[]"))
                    .col(ColumnDef::new(Hosts::Hostname).string().null())
                    .col(ColumnDef::new(Hosts::OsHint).string().null())
                    .col(ColumnDef::new(Hosts::Interface).string().not_null().default(""))
                    .col(
                        ColumnDef::new(Hosts::FirstSeen)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Hosts::LastSeen)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Services::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Services::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Services::HostMac).string().not_null())
                    .col(ColumnDef::new(Services::Port).integer().not_null())
                    .col(ColumnDef::new(Services::Protocol).string().not_null().default("tcp"))
                    .col(ColumnDef::new(Services::Name).string().not_null().default(""))
                    .col(ColumnDef::new(Services::Version).string().not_null().default(""))
                    .col(ColumnDef::new(Services::State).string().not_null().default("open"))
                    .foreign_key(
                        ForeignKey::create()
                            .from(Services::Table, Services::HostMac)
                            .to(Hosts::Table, Hosts::Mac)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Interfaces::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Interfaces::Name)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Interfaces::Mac).string().not_null().default(""))
                    .col(ColumnDef::new(Interfaces::Ipv4Json).string().not_null().default("[]"))
                    .col(ColumnDef::new(Interfaces::Ipv6Json).string().not_null().default("[]"))
                    .col(ColumnDef::new(Interfaces::Gateway).string().not_null().default(""))
                    .col(ColumnDef::new(Interfaces::Subnet).string().not_null().default(""))
                    .col(ColumnDef::new(Interfaces::IsUp).boolean().not_null().default(false))
                    .col(ColumnDef::new(Interfaces::Kind).string().not_null().default("other"))
                    .col(ColumnDef::new(Interfaces::DnsJson).string().not_null().default("[]"))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(WifiNetworks::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(WifiNetworks::Bssid)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(WifiNetworks::Ssid).string().not_null().default(""))
                    .col(ColumnDef::new(WifiNetworks::Rssi).integer().not_null().default(0))
                    .col(ColumnDef::new(WifiNetworks::Noise).integer().not_null().default(0))
                    .col(ColumnDef::new(WifiNetworks::Channel).integer().not_null().default(0))
                    .col(ColumnDef::new(WifiNetworks::Band).string().not_null().default(""))
                    .col(ColumnDef::new(WifiNetworks::Security).string().not_null().default(""))
                    .col(ColumnDef::new(WifiNetworks::Interface).string().not_null().default(""))
                    .to_owned(),
            )
            .await?;

        // Index on services.host_mac for join performance
        manager
            .create_index(
                Index::create()
                    .name("idx_services_host_mac")
                    .table(Services::Table)
                    .col(Services::HostMac)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Services::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Hosts::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Interfaces::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(WifiNetworks::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum Hosts {
    Table,
    Mac,
    Vendor,
    Ipv4Json,
    Ipv6Json,
    Hostname,
    OsHint,
    Interface,
    FirstSeen,
    LastSeen,
}

#[derive(DeriveIden)]
enum Services {
    Table,
    Id,
    HostMac,
    Port,
    Protocol,
    Name,
    Version,
    State,
}

#[derive(DeriveIden)]
enum Interfaces {
    Table,
    Name,
    Mac,
    Ipv4Json,
    Ipv6Json,
    Gateway,
    Subnet,
    IsUp,
    Kind,
    DnsJson,
}

#[derive(DeriveIden)]
enum WifiNetworks {
    Table,
    Bssid,
    Ssid,
    Rssi,
    Noise,
    Channel,
    Band,
    Security,
    Interface,
}
