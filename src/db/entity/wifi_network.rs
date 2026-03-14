use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "wifi_networks")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub bssid: String,
    pub ssid: String,
    pub rssi: i32,
    pub noise: i32,
    pub channel: i32,
    pub band: String,
    pub security: String,
    pub interface: String,
    pub document_json: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
