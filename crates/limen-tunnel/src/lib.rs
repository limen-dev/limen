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
    /// CLI → proxy, for SSH sessions.
    pub const SSH: &[u8] = b"limen-ssh/1";
    /// CLI API (relayed to the control plane) and the Kubernetes API, routed by path.
    pub const H2: &[u8] = b"h2";
    /// Browsers that don't speak HTTP/2. Only the web console is served this way.
    pub const HTTP1: &[u8] = b"http/1.1";
    pub const HTTP11: &[u8] = b"http/1.1";

    pub const ALL: [&[u8]; 7] = [TUNNEL, PEER, DB, REDIS, SSH, H2, HTTP11];
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
