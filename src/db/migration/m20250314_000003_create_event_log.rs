use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// Persistent event timeline — append-only log of all network state transitions.
///
/// Architecture: The in-memory ring buffer (`StateEngine::event_log`) provides
/// low-latency streaming to gRPC subscribers. This table provides durable history
/// that survives daemon restarts, enabling:
///   - "When did host X first appear / disappear?"
///   - "What changed on the network in the last 24h?"
///   - "How often does this device go offline?"
///
/// Events are stored as JSON blobs (change_json) for schema flexibility —
/// new Change variants don't require migrations. The event_type column enables
/// indexed filtering without deserializing the blob.
///
/// Retention: old events are pruned by the same pruner that handles stale hosts,
/// configurable via storage.retention.event_ttl.
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Events::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Events::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Events::Sequence)
                            .big_unsigned()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Events::Timestamp)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Events::EventType)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Events::SubjectMac)
                            .string()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(Events::SubjectName)
                            .string()
                            .not_null()
                            .default(""),
                    )
                    .col(
                        ColumnDef::new(Events::ChangeJson)
                            .text()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Indexes for common queries
        manager
            .create_index(
                Index::create()
                    .name("idx_events_timestamp")
                    .table(Events::Table)
                    .col(Events::Timestamp)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_events_sequence")
                    .table(Events::Table)
                    .col(Events::Sequence)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_events_subject_mac")
                    .table(Events::Table)
                    .col(Events::SubjectMac)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_events_event_type")
                    .table(Events::Table)
                    .col(Events::EventType)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Events::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum Events {
    Table,
    Id,
    Sequence,
    Timestamp,
    /// Discriminant for filtering: host_added, host_removed, host_updated,
    /// service_added, service_removed, wifi_added, wifi_removed, wifi_updated,
    /// interface_changed, network_changed
    EventType,
    /// MAC or BSSID of the subject (empty for interface/network events)
    SubjectMac,
    /// Human-readable subject (hostname, SSID, interface name)
    SubjectName,
    /// Full Change enum serialized as JSON
    ChangeJson,
}
