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

    /// Public origin of the console, used to start browser SSO for web apps.
    #[arg(long, env = "LIMEN_CONSOLE_PUBLIC_URL")]
    pub console_public_url: Option<String>,

    /// Internal CA certificate to trust when contacting the control plane
    /// before enrollment. After enrollment, the CA bundle it returned is used.
    #[arg(long, env = "LIMEN_CA_FILE")]
    pub ca_file: Option<PathBuf>,

    /// Join token for first enrollment. Ignored once enrolled.
    #[arg(long, env = "LIMEN_JOIN_TOKEN", value_parser = parse_secret)]
    pub join_token: Option<Secret<String>>,

    /// Display name, such as `prod-a-proxy-1`: 1 to 63 characters of a-z,
    /// 0-9 and -. Sent only at first enrollment, and must be approved by the
    /// join token; fixed after that (a different value is ignored with a
    /// warning). Shown next to the ID in the console, audit data, and logs.
    #[arg(long, env = "LIMEN_NAME")]
    pub name: Option<String>,

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

    /// New connections per second from one client IP, before any
    /// authentication (an abuse guard; the rest are dropped). Raise it, with
    /// the burst, for a site where many users share one egress address.
    /// 1 to 100000.
    #[arg(long, env = "LIMEN_ACCEPT_RATE_PER_SECOND", default_value_t = 50,
          value_parser = clap::value_parser!(u32).range(1..=100_000))]
    pub accept_rate_per_second: u32,

    /// The burst allowed on top of the rate, per client IP. 1 to 100000.
    #[arg(long, env = "LIMEN_ACCEPT_BURST", default_value_t = 200,
          value_parser = clap::value_parser!(u32).range(1..=100_000))]
    pub accept_burst: u32,

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
    /// peer proxies read them. 1 to 15: at most a third of the registry's
    /// 45 s tunnel lease, so peers never lose this proxy's tunnels between
    /// reports.
    #[arg(long, env = "LIMEN_REPORT_INTERVAL_SECS", default_value_t = 15,
          value_parser = parse_report_interval)]
    pub report_interval_secs: u64,

    /// Refuse new audit events (and, by default, the actions they audit)
    /// once the local spool holds this many bytes, e.g. during a long
    /// control plane outage.
    #[arg(long, env = "LIMEN_AUDIT_SPOOL_MAX_BYTES", default_value_t = 512 * 1024 * 1024)]
    pub audit_spool_max_bytes: u64,

    #[arg(long, env = "LIMEN_AUDIT_FAILURE_MODE", default_value = "fail_closed")]
    pub audit_failure_mode: limen_audit::FailureMode,
}

/// 1 to [`MAX_REPORT_INTERVAL_SECS`](limen_core::registry::MAX_REPORT_INTERVAL_SECS).
/// Builds with the `test-hooks` feature (tests only) accept up to 3600, for
/// tests that need load figures to stay stale; such tests must finish well
/// within the lease.
fn parse_report_interval(s: &str) -> Result<u64, String> {
    use limen_core::registry::{MAX_REPORT_INTERVAL_SECS, TUNNEL_LEASE_SECS};
    let secs: u64 = s
        .parse()
        .map_err(|_| format!("not a number of seconds: {s}"))?;
    let max = if cfg!(feature = "test-hooks") {
        3600
    } else {
        MAX_REPORT_INTERVAL_SECS
    };
    if (1..=max).contains(&secs) {
        Ok(secs)
    } else {
        Err(format!(
            "must be 1 to {max} seconds: at most a third of the {TUNNEL_LEASE_SECS} s registry lease, so peers keep seeing this proxy's tunnels"
        ))
    }
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
    fn accept_limit_keeps_the_old_defaults_and_is_bounded() {
        let c = parse_with(&[]).expect("defaults");
        assert_eq!((c.accept_rate_per_second, c.accept_burst), (50, 200));
        assert!(parse_with(&["--accept-rate-per-second=0"]).is_err());
        assert!(parse_with(&["--accept-burst=0"]).is_err());
        assert!(parse_with(&["--accept-rate-per-second=100001"]).is_err());
        assert!(parse_with(&["--accept-rate-per-second=1000", "--accept-burst=5000"]).is_ok());
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

    #[test]
    fn reports_come_well_within_the_registry_lease() {
        // limen_core::registry also checks cap * 3 <= lease at compile time.
        assert_eq!(limen_core::registry::MAX_REPORT_INTERVAL_SECS, 15);
        assert_eq!(limen_core::registry::TUNNEL_LEASE_SECS, 45);
    }

    /// Release builds: a report interval past a third of the lease would
    /// let peers lose this proxy's tunnels between reports.
    #[cfg(not(feature = "test-hooks"))]
    #[test]
    fn release_builds_cap_the_report_interval_at_a_third_of_the_lease() {
        for ok in 1..=15 {
            let c = parse_with(&[&format!("--report-interval-secs={ok}")]).expect("in range");
            assert_eq!(c.report_interval_secs, ok);
        }
        for bad in ["16", "60", "3600"] {
            let err =
                parse_with(&[&format!("--report-interval-secs={bad}")]).expect_err("past the cap");
            assert!(err.to_string().contains("lease"), "{err}");
        }
    }

    /// Test builds may report rarely, for tests that keep figures stale.
    #[cfg(feature = "test-hooks")]
    #[test]
    fn test_hooks_builds_allow_long_report_intervals() {
        let c = parse_with(&["--report-interval-secs=3600"]).expect("test-hooks");
        assert_eq!(c.report_interval_secs, 3600);
    }
}
