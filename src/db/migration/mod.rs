use sea_orm_migration::prelude::*;

mod m20250101_000001_create_tables;
mod m20250313_000002_add_network_id;
mod m20250314_000003_create_event_log;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20250101_000001_create_tables::Migration),
            Box::new(m20250313_000002_add_network_id::Migration),
            Box::new(m20250314_000003_create_event_log::Migration),
        ]
    }
}
