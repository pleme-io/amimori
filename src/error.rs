use thiserror::Error;

/// Top-level error type for amimori operations.
#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum AmimoriError {
    #[error("config error: {0}")]
    Config(String),

    #[error("database error: {0}")]
    Database(#[from] sea_orm::DbErr),

    #[error("gRPC error: {0}")]
    Grpc(#[from] tonic::transport::Error),

    #[error("collector error: {source}")]
    Collector {
        collector: String,
        #[source]
        source: anyhow::Error,
    },

    #[error("network interface error: {0}")]
    NetworkInterface(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(#[from] anyhow::Error),
}
