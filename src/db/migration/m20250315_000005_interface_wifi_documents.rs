use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Add document_json columns to interfaces and wifi_networks tables.
/// Same pattern as hosts — the full domain type is the SSOT,
/// relational columns are indexes for queryability.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Interfaces::Table)
                    .add_column(ColumnDef::new(Interfaces::DocumentJson).text().null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(WifiNetworks::Table)
                    .add_column(ColumnDef::new(WifiNetworks::DocumentJson).text().null())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(Table::alter().table(Interfaces::Table).drop_column(Interfaces::DocumentJson).to_owned())
            .await?;
        manager
            .alter_table(Table::alter().table(WifiNetworks::Table).drop_column(WifiNetworks::DocumentJson).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum Interfaces {
    Table,
    DocumentJson,
}

#[derive(DeriveIden)]
enum WifiNetworks {
    Table,
    DocumentJson,
}
