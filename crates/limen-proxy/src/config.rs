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

    /// How old the policy snapshot may get while the control plane is
    /// unreachable before new sessions fail closed (ADR-0011).
    #[arg(long, env = "LIMEN_POLICY_GRACE_SECS", default_value_t = 300)]
    pub policy_grace_secs: u64,

    /// How often to fetch a fresh policy snapshot.
    #[arg(long, env = "LIMEN_POLICY_REFRESH_SECS", default_value_t = 10)]
    pub policy_refresh_secs: u64,

    /// How often to ping each worker tunnel. The answer also carries the
    /// worker's load (sessions and cap) used to choose workers. 1 to 3600.
    #[arg(long, env = "LIMEN_PING_INTERVAL_SECS", default_value_t = 15,
          value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub ping_interval_secs: u64,

    /// How often to report this proxy's tunnels, with each worker's load,
    /// to the control plane's registry (also on every tunnel change), where
    /// peer proxies read them. 1 to 3600.
    #[arg(long, env = "LIMEN_REPORT_INTERVAL_SECS", default_value_t = 15,
          value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub report_interval_secs: u64,

    /// Refuse new audit events (and, by default, the actions they audit)
    /// once the local spool holds this many bytes, e.g. during a long
    /// control plane outage.
    #[arg(long, env = "LIMEN_AUDIT_SPOOL_MAX_BYTES", default_value_t = 512 * 1024 * 1024)]
    pub audit_spool_max_bytes: u64,

    #[arg(long, env = "LIMEN_AUDIT_FAILURE_MODE", default_value = "fail_closed")]
    pub audit_failure_mode: limen_audit::FailureMode,
}

#[allow(clippy::unnecessary_wraps)] // clap value parsers must return Result
fn parse_secret(s: &str) -> Result<Secret<String>, String> {
    Ok(Secret::new(s.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(clap::Parser)]
    struct Cli {
        #[command(flatten)]
        config: Config,
    }

    fn parse_with(extra: &[&str]) -> Result<Config, clap::Error> {
        use clap::Parser as _;
        let mut argv = vec!["limen-proxy", "--control-plane-addr=cp:3080"];
        argv.extend_from_slice(extra);
        Cli::try_parse_from(argv).map(|c| c.config)
    }

    #[test]
    fn ping_and_report_intervals_are_bounded() {
        let c = parse_with(&[]).expect("defaults");
        assert_eq!((c.ping_interval_secs, c.report_interval_secs), (15, 15));
        let c = parse_with(&["--ping-interval-secs=3600", "--report-interval-secs=1"])
            .expect("in range");
        assert_eq!((c.ping_interval_secs, c.report_interval_secs), (3600, 1));
        for bad in [
            "--ping-interval-secs=0",
            "--ping-interval-secs=3601",
            "--report-interval-secs=0",
            "--report-interval-secs=3601",
        ] {
            assert!(parse_with(&[bad]).is_err(), "{bad}");
        }
    }
}
