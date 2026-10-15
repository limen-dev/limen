//! Control plane configuration. Every flag also reads from a `LIMEN_*`
//! environment variable, which is how the containers are configured.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, ValueEnum};
use limen_audit::FailureMode;
use limen_core::secret::Secret;

use crate::replicas::SpoolMode;

#[derive(Debug, Clone, Args)]
pub struct Config {
    /// Stable identifier of this replica. Appears in audit events and its
    /// certificate, and is the audit manifest writer. Defaults to the
    /// hostname. Two live replicas with the same id refuse to start.
    #[arg(long, env = "LIMEN_ID", default_value_t = default_id())]
    pub id: String,

    /// Whether the audit spool directory survives this replica.
    #[arg(long, env = "LIMEN_SPOOL_MODE", value_enum, default_value = "durable")]
    pub spool_mode: SpoolMode,

    /// URL peers use to reach this replica's ingest service. Defaults to
    /// `https://<first --dns-name>:<--listen port>`.
    #[arg(long, env = "LIMEN_ADVERTISE_URL")]
    pub advertise_url: Option<String>,

    /// gRPC listener (mTLS). Proxies connect here.
    #[arg(long, env = "LIMEN_LISTEN", default_value = "0.0.0.0:3080")]
    pub listen: SocketAddr,

    /// Health and readiness listener (plain HTTP, keep it private).
    #[arg(long, env = "LIMEN_ADMIN_LISTEN", default_value = "0.0.0.0:3081")]
    pub admin_listen: SocketAddr,

    /// DNS names and IPs for this replica's server certificate.
    #[arg(
        long = "dns-name",
        env = "LIMEN_DNS_NAMES",
        value_delimiter = ',',
        default_value = "localhost"
    )]
    pub dns_names: Vec<String>,

    /// PostgreSQL connection URL.
    #[arg(long, env = "LIMEN_DATABASE_URL", value_parser = parse_secret)]
    pub database_url: Secret<String>,

    #[arg(long, env = "LIMEN_CA_BACKEND", value_enum, default_value = "file")]
    pub ca_backend: CaBackend,

    /// Directory for CA keys when the file backend is used. Development only.
    #[arg(long, env = "LIMEN_CA_DIR", default_value = "/var/lib/limen/ca")]
    pub ca_dir: PathBuf,

    /// KMS key ID or ARN for the internal CA (kms backend).
    #[arg(long, env = "LIMEN_KMS_INTERNAL_CA_KEY")]
    pub kms_internal_ca_key: Option<String>,

    /// KMS key ID or ARN for the user CA (kms backend).
    #[arg(long, env = "LIMEN_KMS_USER_CA_KEY")]
    pub kms_user_ca_key: Option<String>,

    /// KMS key ID or ARN for the SSH user CA, which targets trust (kms backend).
    #[arg(long, env = "LIMEN_KMS_SSH_USER_CA_KEY")]
    pub kms_ssh_user_ca_key: Option<String>,

    /// KMS key ID or ARN for the SSH host CA, which the CLI trusts (kms backend).
    #[arg(long, env = "LIMEN_KMS_SSH_HOST_CA_KEY")]
    pub kms_ssh_host_ca_key: Option<String>,

    /// Write the CA certificates (public) to this directory on startup, so
    /// components and the CLI can pin them. Used by the dev stack.
    #[arg(long, env = "LIMEN_CA_EXPORT_DIR")]
    pub ca_export_dir: Option<PathBuf>,

    /// OIDC issuer URL, exactly as it appears in ID tokens and as the CLI reaches it.
    #[arg(long, env = "LIMEN_OIDC_ISSUER")]
    pub oidc_issuer: String,

    /// Where the control plane itself reaches the issuer, if different from
    /// `oidc_issuer` (for example inside a container network).
    #[arg(long, env = "LIMEN_OIDC_INTERNAL_URL")]
    pub oidc_internal_url: Option<String>,

    #[arg(long, env = "LIMEN_OIDC_CLIENT_ID")]
    pub oidc_client_id: String,

    #[arg(
        long,
        env = "LIMEN_OIDC_SCOPES",
        value_delimiter = ',',
        default_value = "openid,email,profile,groups"
    )]
    pub oidc_scopes: Vec<String>,

    /// Public URL users reach the proxy at, such as `https://limen.example.com`.
    /// Setting it turns on the web console under `/console/` (ADR-0017).
    #[arg(long, env = "LIMEN_CONSOLE_PUBLIC_URL")]
    pub console_public_url: Option<String>,

    /// The `aud` bots' workload identity tokens must carry (ADR-0019). The CLI
    /// asks the CI platform for a token with this audience.
    #[arg(long, env = "LIMEN_BOT_AUDIENCE", default_value = "limen")]
    pub bot_audience: String,

    /// How old a bot's token may be (by its `iat`) when it logs in.
    #[arg(long, env = "LIMEN_BOT_MAX_TOKEN_AGE", value_parser = parse_duration, default_value = "15m")]
    pub bot_max_token_age: Duration,

    /// Accept bot token issuers that use plain `http://`. Development only:
    /// real issuers are https, and the tokens' keys travel over that channel.
    #[arg(long, env = "LIMEN_BOT_ALLOW_INSECURE_ISSUERS")]
    pub bot_allow_insecure_issuers: bool,

    /// The console's own OIDC client. Its redirect URI is
    /// `<console public URL>/console/callback`.
    #[arg(
        long,
        env = "LIMEN_CONSOLE_OIDC_CLIENT_ID",
        default_value = "limen-console"
    )]
    pub console_oidc_client_id: String,

    /// Secret of the console's OIDC client. Required with the console.
    #[arg(long, env = "LIMEN_CONSOLE_OIDC_CLIENT_SECRET", value_parser = parse_secret)]
    pub console_oidc_client_secret: Option<Secret<String>>,

    /// ID token claim used as the Limen username.
    #[arg(
        long,
        env = "LIMEN_OIDC_USERNAME_CLAIM",
        value_enum,
        default_value = "email"
    )]
    pub oidc_username_claim: UsernameClaim,

    /// IdP groups whose members get `limen:admin` regardless of policy, so
    /// the first admin can log in and apply policy.
    #[arg(
        long = "bootstrap-admin-group",
        env = "LIMEN_BOOTSTRAP_ADMIN_GROUPS",
        value_delimiter = ','
    )]
    pub bootstrap_admin_groups: Vec<String>,

    /// Multi-use join tokens as `kind:token` (kind is proxy or worker). Meant
    /// for bootstrapping and autoscaled tasks until the AWS IAM join method
    /// exists (ADR-0016). Prefer single-use tokens from `limen admin token create`.
    #[arg(long = "static-join-token", env = "LIMEN_STATIC_JOIN_TOKENS", value_delimiter = ',', value_parser = parse_static_token)]
    pub static_join_tokens: Vec<StaticJoinToken>,

    /// DNS names a proxy enrolled with a static token may put in its certificate.
    #[arg(
        long = "proxy-dns-name",
        env = "LIMEN_PROXY_DNS_NAMES",
        value_delimiter = ','
    )]
    pub proxy_dns_names: Vec<String>,

    /// Upper bound on user credential lifetime, whatever roles say.
    #[arg(long, env = "LIMEN_MAX_CERT_TTL", value_parser = parse_duration, default_value = "12h")]
    pub max_cert_ttl: Duration,

    /// How long a browser sign-in to the console lasts, capped by
    /// `--max-cert-ttl`. Locks and session kills still take effect at once.
    #[arg(long, env = "LIMEN_CONSOLE_SESSION_TTL", value_parser = parse_duration, default_value = "8h")]
    pub console_session_ttl: Duration,

    /// Lifetime of proxy and worker certificates. They renew at half-life.
    #[arg(long, env = "LIMEN_COMPONENT_CERT_TTL", value_parser = parse_duration, default_value = "24h")]
    pub component_cert_ttl: Duration,

    /// Local spool for audit events, from this replica and ingested from
    /// proxies and workers, until every sink has shipped them (ADR-0009).
    #[arg(
        long,
        env = "LIMEN_AUDIT_SPOOL_DIR",
        default_value = "/var/lib/limen/spool"
    )]
    pub audit_spool_dir: PathBuf,

    /// Refuse new audit events (and so, by default, the actions they audit)
    /// once the spool holds this many bytes.
    #[arg(long, env = "LIMEN_AUDIT_SPOOL_MAX_BYTES", default_value_t = 2 * 1024 * 1024 * 1024)]
    pub audit_spool_max_bytes: u64,

    /// Optional sink: append every event to this local JSONL file (development).
    #[arg(long, env = "LIMEN_AUDIT_FILE")]
    pub audit_file: Option<PathBuf>,

    /// S3 bucket for audit batches and session recordings (ADR-0009).
    #[arg(long, env = "LIMEN_AUDIT_S3_BUCKET")]
    pub audit_s3_bucket: Option<String>,

    /// Key prefix inside the bucket, for example `limen/`.
    #[arg(long, env = "LIMEN_AUDIT_S3_PREFIX", default_value = "")]
    pub audit_s3_prefix: String,

    /// S3 endpoint override, for S3-compatible stores in development.
    #[arg(long, env = "LIMEN_AUDIT_S3_ENDPOINT")]
    pub audit_s3_endpoint: Option<String>,

    /// Use path-style S3 addressing (S3-compatible stores).
    #[arg(long, env = "LIMEN_AUDIT_S3_PATH_STYLE")]
    pub audit_s3_path_style: bool,

    /// Encrypt objects with this KMS key (SSE-KMS). Without it, the bucket's
    /// default encryption applies.
    #[arg(long, env = "LIMEN_AUDIT_S3_KMS_KEY")]
    pub audit_s3_kms_key: Option<String>,

    /// Create the bucket if it doesn't exist (development only; in AWS the
    /// bucket comes from Terraform with encryption, versioning, and Object Lock).
    #[arg(long, env = "LIMEN_AUDIT_S3_CREATE_BUCKET")]
    pub audit_s3_create_bucket: bool,

    /// Close an S3 batch after this long, even if it isn't full.
    #[arg(long, env = "LIMEN_AUDIT_S3_FLUSH", value_parser = parse_duration, default_value = "60s")]
    pub audit_s3_flush: Duration,

    /// Datadog Logs intake URL, for example
    /// `https://http-intake.logs.datadoghq.eu/api/v2/logs`. Enables the Datadog sink.
    #[arg(long, env = "LIMEN_DATADOG_LOGS_URL")]
    pub datadog_logs_url: Option<String>,

    #[arg(long, env = "DD_API_KEY", value_parser = parse_secret)]
    pub datadog_api_key: Option<Secret<String>>,

    /// Deployment environment, used in Datadog tags (`env:`).
    #[arg(long, env = "LIMEN_ENVIRONMENT", default_value = "dev")]
    pub environment: String,

    /// Where session recordings go when no S3 bucket is configured (development).
    #[arg(
        long,
        env = "LIMEN_RECORDINGS_DIR",
        default_value = "/var/lib/limen/recordings"
    )]
    pub recordings_dir: PathBuf,

    #[arg(long, env = "LIMEN_AUDIT_FAILURE_MODE", default_value = "fail_closed")]
    pub audit_failure_mode: FailureMode,

    /// On shutdown, how long in-flight connections may finish before they're cut.
    #[arg(long, env = "LIMEN_DRAIN_TIMEOUT", value_parser = parse_duration_or_zero, default_value = "20s")]
    pub drain_timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CaBackend {
    File,
    Kms,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum UsernameClaim {
    Email,
    PreferredUsername,
    Sub,
}

#[derive(Debug, Clone)]
pub struct StaticJoinToken {
    pub kind: String,
    pub token: Secret<String>,
    /// Labels for components enrolled with this token.
    pub labels: limen_core::labels::Labels,
}

#[allow(clippy::unnecessary_wraps)] // clap value parsers must return Result
fn parse_secret(s: &str) -> Result<Secret<String>, String> {
    Ok(Secret::new(s.to_owned()))
}

/// `kind:token` or `kind:token:key=value;key=value`.
fn parse_static_token(s: &str) -> Result<StaticJoinToken, String> {
    let mut parts = s.splitn(3, ':');
    let kind = parts.next().unwrap_or_default();
    let token = parts.next().ok_or("expected kind:token[:key=value;...]")?;
    if !matches!(kind, "proxy" | "worker") {
        return Err(format!("unknown component kind {kind:?}"));
    }
    if token.len() < 32 {
        return Err("static join tokens must be at least 32 characters".into());
    }
    let mut labels = limen_core::labels::Labels::default();
    for pair in parts
        .next()
        .unwrap_or_default()
        .split(';')
        .filter(|p| !p.is_empty())
    {
        let (k, v) = pair
            .split_once('=')
            .ok_or_else(|| format!("label {pair:?} must be key=value"))?;
        labels.insert(k, v).map_err(|e| e.to_string())?;
    }
    Ok(StaticJoinToken {
        kind: kind.to_owned(),
        token: Secret::new(token.to_owned()),
        labels,
    })
}

/// Like [`parse_duration`], but `0s` is allowed.
pub fn parse_duration_or_zero(s: &str) -> Result<Duration, String> {
    let digits = s.trim_end_matches(|c: char| c.is_ascii_alphabetic());
    if !digits.is_empty() && digits.bytes().all(|b| b == b'0') {
        return Ok(Duration::ZERO);
    }
    parse_duration(s)
}

/// Parse `90s`, `10m`, `8h`, or `1d`.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    limen_policy::duration::DurationStr::parse(s).map(|d| d.0)
}

/// The hostname: `HOSTNAME`, then `/etc/hostname`, else `control-plane`.
fn default_id() -> String {
    let from_env = std::env::var("HOSTNAME").ok();
    let from_file = || std::fs::read_to_string("/etc/hostname").ok();
    pick_hostname(from_env, from_file)
}

fn pick_hostname(env: Option<String>, file: impl FnOnce() -> Option<String>) -> String {
    [env, file()]
        .into_iter()
        .flatten()
        .map(|s| s.trim().to_owned())
        .find(|s| !s.is_empty())
        .unwrap_or_else(|| "control-plane".to_owned())
}

impl Config {
    /// Where peers reach this replica's ingest service.
    #[must_use]
    pub fn ingest_url(&self) -> String {
        self.advertise_url.clone().unwrap_or_else(|| {
            let host = self.dns_names.first().map_or("localhost", String::as_str);
            format!("https://{host}:{}", self.listen.port())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_default_prefers_env_then_file_then_fallback() {
        assert_eq!(
            pick_hostname(Some(" cp-0\n".into()), || Some("x".into())),
            "cp-0"
        );
        assert_eq!(pick_hostname(None, || Some("box\n".into())), "box");
        assert_eq!(pick_hostname(Some(String::new()), || None), "control-plane");
    }

    #[test]
    fn static_tokens_with_labels() {
        let t = parse_static_token("worker:0123456789abcdef0123456789abcdef:pool=dev;az=a")
            .expect("valid");
        assert_eq!(t.kind, "worker");
        assert_eq!(t.labels.get("pool"), Some("dev"));
        assert_eq!(t.labels.get("az"), Some("a"));
        assert!(
            parse_static_token("worker:0123456789abcdef0123456789abcdef")
                .expect("no labels")
                .labels
                .get("pool")
                .is_none()
        );
        assert!(parse_static_token("worker:short").is_err());
        assert!(parse_static_token("admin:0123456789abcdef0123456789abcdef").is_err());
        assert!(parse_static_token("worker:0123456789abcdef0123456789abcdef:BAD=x").is_err());
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration_or_zero("0s"), Ok(Duration::ZERO));
        assert_eq!(parse_duration_or_zero("00m"), Ok(Duration::ZERO));
        assert_eq!(parse_duration_or_zero("20s"), Ok(Duration::from_secs(20)));
        assert!(parse_duration_or_zero("s").is_err());
        assert!(parse_duration("0s").is_err(), "TTLs must stay positive");
    }
}
