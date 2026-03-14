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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_error_display() {
        let e = AmimoriError::Config("bad port".into());
        assert_eq!(e.to_string(), "config error: bad port");
    }

    #[test]
    fn network_interface_error_display() {
        let e = AmimoriError::NetworkInterface("en0 not found".into());
        assert_eq!(e.to_string(), "network interface error: en0 not found");
    }

    #[test]
    fn io_error_from_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let e: AmimoriError = io_err.into();
        assert!(e.to_string().contains("file missing"));
    }

    #[test]
    fn collector_error_display() {
        let e = AmimoriError::Collector {
            collector: "nmap".into(),
            source: anyhow::anyhow!("timed out"),
        };
        assert!(e.to_string().contains("timed out"));
    }

    #[test]
    fn other_error_from_anyhow() {
        let e: AmimoriError = anyhow::anyhow!("something broke").into();
        assert_eq!(e.to_string(), "something broke");
    }
}
