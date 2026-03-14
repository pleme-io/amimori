use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "hosts")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub mac: String,
    pub vendor: String,
    pub ipv4_json: String, // JSON array of IPv4 addresses
    pub ipv6_json: String, // JSON array of IPv6 addresses
    pub hostname: Option<String>,
    pub os_hint: Option<String>,
    pub interface: String,
    pub network_id: String,
    pub first_seen: ChronoDateTimeUtc,
    pub last_seen: ChronoDateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::service::Entity")]
    Services,
}

impl Related<super::service::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Services.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
