use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "events")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub sequence: i64,
    pub timestamp: ChronoDateTimeUtc,
    /// Discriminant: host_added, host_removed, service_added, etc.
    pub event_type: String,
    /// MAC or BSSID of the subject (empty for interface/network events)
    pub subject_mac: String,
    /// Human-readable: hostname, SSID, interface name
    pub subject_name: String,
    /// Full Change enum serialized as JSON
    pub change_json: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
