use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Add a `document_json` column to hosts table that stores the full
/// HostInfo as JSON. This is the SSOT — all other columns are derived
/// indexes for queryability. On read, we deserialize the document
/// instead of assembling from relational columns.
///
/// This eliminates the entity↔model conversion layer and makes
/// HostInfo the single canonical representation.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add document_json column to hosts
        manager
            .alter_table(
                Table::alter()
                    .table(Hosts::Table)
                    .add_column(
                        ColumnDef::new(Hosts::DocumentJson)
                            .text()
                            .null() // nullable during migration, populated on next write
                    )
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
                    .drop_column(Hosts::DocumentJson)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Hosts {
    Table,
    DocumentJson,
}
