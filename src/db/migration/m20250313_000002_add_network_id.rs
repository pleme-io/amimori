use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add network_id column to hosts table
        manager
            .alter_table(
                Table::alter()
                    .table(Hosts::Table)
                    .add_column(
                        ColumnDef::new(Hosts::NetworkId)
                            .string()
                            .not_null()
                            .default(""),
                    )
                    .to_owned(),
            )
            .await?;

        // Index for querying hosts by network
        manager
            .create_index(
                Index::create()
                    .name("idx_hosts_network_id")
                    .table(Hosts::Table)
                    .col(Hosts::NetworkId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Hosts::Table)
                    .drop_column(Hosts::NetworkId)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum Hosts {
    Table,
    NetworkId,
}
