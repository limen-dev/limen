//! Proxy configuration. Every flag also reads from a `LIMEN_*` environment variable.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Args;
use limen_core::secret::Secret;

#[derive(Debug, Clone, Args)]
pub struct Config {
    /// Public listener: one TLS port for everything, routed by ALPN (ADR-0005).
    #[arg(long, env = "LIMEN_LISTEN", default_value = "0.0.0.0:3443")]
    pub listen: SocketAddr,

    /// Health, readiness, and debug listener (plain HTTP, keep it private).
    #[arg(long, env = "LIMEN_ADMIN_LISTEN", default_value = "0.0.0.0:3444")]
    pub admin_listen: SocketAddr,

    /// Control plane gRPC address, `host:port`.
    #[arg(long, env = "LIMEN_CONTROL_PLANE_ADDR")]
    pub control_plane_addr: String,

    /// Name in the control plane's certificate.
    #[arg(long, env = "LIMEN_CONTROL_PLANE_NAME", default_value = "localhost")]
    pub control_plane_name: String,

    /// Internal CA certificate to trust when contacting the control plane
    /// before enrollment. After enrollment, the CA bundle it returned is used.
    #[arg(long, env = "LIMEN_CA_FILE")]
    pub ca_file: Option<PathBuf>,

    /// Join token for first enrollment. Ignored once enrolled.
    #[arg(long, env = "LIMEN_JOIN_TOKEN", value_parser = parse_secret)]
    pub join_token: Option<Secret<String>>,

    /// DNS names for the public certificate. Must be allowed by the join token.
    #[arg(
        long = "dns-name",
        env = "LIMEN_DNS_NAMES",
        value_delimiter = ',',
        default_value = "localhost"
    )]
    pub dns_names: Vec<String>,

    /// Address other proxies use to reach this one for peering (ADR-0004).
    #[arg(long, env = "LIMEN_PEER_ADDRESS")]
    pub peer_address: Option<String>,

    #[arg(long, env = "LIMEN_DATA_DIR", default_value = "/var/lib/limen/proxy")]
    pub data_dir: PathBuf,

    /// On shutdown, how long to wait for API connections to finish. Worker
    /// tunnels are closed right away so workers move to another proxy.
    #[arg(long, env = "LIMEN_DRAIN_TIMEOUT_SECS", default_value_t = 20)]
    pub drain_timeout_secs: u64,
}

#[allow(clippy::unnecessary_wraps)] // clap value parsers must return Result
fn parse_secret(s: &str) -> Result<Secret<String>, String> {
    Ok(Secret::new(s.to_owned()))
}
