use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "networks")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub ssid: String,
    pub gateway_mac: String,
    pub gateway_ip: String,
    pub subnet_cidr: String,
    pub subnet_mask: String,
    pub interface: String,
    pub times_connected: i32,
    pub first_seen: ChronoDateTimeUtc,
    pub last_seen: ChronoDateTimeUtc,
    /// Full NetworkInfo serialized as JSON — the SSOT document.
    pub document_json: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
