//! Transport for Limen components: TLS configuration, HTTP/2 serving with
//! per-connection peer information, connectors, and the worker reverse
//! tunnel (ADR-0003, ADR-0005).

pub mod connect;
pub mod framing;
pub mod serve;
pub mod tls;
pub mod tunnel;

pub use serve::PeerInfo;

/// ALPN protocol IDs the proxy's single TLS listener routes on.
pub mod alpn {
    /// Worker → proxy reverse tunnel. The worker acts as the HTTP/2 server.
    pub const TUNNEL: &[u8] = b"limen-tunnel/1";
    /// Proxy → proxy peering, used to reach a worker tunnel held by another proxy.
    pub const PEER: &[u8] = b"limen-peer/1";
    /// CLI local listener → proxy, for database sessions.
    pub const DB: &[u8] = b"limen-db/1";
    /// CLI local listener → proxy, for Redis sessions.
    pub const REDIS: &[u8] = b"limen-redis/1";
    /// CLI local listener → proxy, for `RabbitMQ` (AMQP 0-9-1) sessions.
    pub const MQ: &[u8] = b"limen-mq/1";
    /// CLI local listener → proxy, for Kafka sessions.
    pub const KAFKA: &[u8] = b"limen-kafka/1";
    /// CLI → proxy, for SSH sessions.
    pub const SSH: &[u8] = b"limen-ssh/1";
    /// CLI API (relayed to the control plane) and the Kubernetes API, routed by path.
    pub const H2: &[u8] = b"h2";
    /// Browsers that don't speak HTTP/2. Only the web console is served this way.
    pub const HTTP1: &[u8] = b"http/1.1";
    pub const HTTP11: &[u8] = b"http/1.1";

    pub const ALL: [&[u8]; 9] = [TUNNEL, PEER, DB, REDIS, MQ, KAFKA, SSH, H2, HTTP11];
}

/// Refusals a worker makes before it reads anything from a session stream,
/// marked in the status metadata so the proxy can act on them without
/// parsing the message.
pub mod refusal {
    /// Metadata key on a marked refusal; the value says why.
    pub const KEY: &str = "limen-refusal";
    /// The worker is shutting down.
    pub const DRAINING: &str = "draining";

    /// The worker is draining. It read nothing (the grant is unused), so the
    /// session can be tried on another worker.
    #[must_use]
    pub fn draining() -> tonic::Status {
        let mut status = tonic::Status::unavailable(
            "worker is draining: it is shutting down and takes no new sessions",
        );
        status
            .metadata_mut()
            .insert(KEY, tonic::metadata::MetadataValue::from_static(DRAINING));
        status
    }

    /// Whether `status` is a [`draining`] refusal.
    #[must_use]
    pub fn is_draining(status: &tonic::Status) -> bool {
        status.code() == tonic::Code::Unavailable
            && status.metadata().get(KEY).is_some_and(|v| v == DRAINING)
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn only_a_marked_unavailable_is_a_drain_refusal() {
            assert!(super::is_draining(&super::draining()));
            assert!(!super::is_draining(&tonic::Status::unavailable(
                "worker is draining"
            )));
            let mut other = tonic::Status::permission_denied("no");
            other.metadata_mut().insert(
                super::KEY,
                tonic::metadata::MetadataValue::from_static(super::DRAINING),
            );
            assert!(!super::is_draining(&other));
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("TLS configuration: {0}")]
    Tls(String),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("HTTP/2: {0}")]
    Http(#[from] hyper::Error),
}

#[cfg(test)]
mod tests {
    use super::alpn;

    #[test]
    fn alpn_ids_are_unique_and_within_tls_limit() {
        let mut seen = std::collections::HashSet::new();
        for id in alpn::ALL {
            assert!(
                !id.is_empty() && id.len() <= 255,
                "ALPN IDs must be 1..=255 bytes"
            );
            assert!(seen.insert(id), "duplicate ALPN ID {id:?}");
        }
    }
}
