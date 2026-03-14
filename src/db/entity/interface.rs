use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "interfaces")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub name: String,
    pub mac: String,
    pub ipv4_json: String, // JSON array
    pub ipv6_json: String, // JSON array
    pub gateway: String,
    pub subnet: String,
    pub is_up: bool,
    pub kind: String,
    pub dns_json: String, // JSON array
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
