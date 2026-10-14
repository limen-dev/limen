//! Control plane configuration. Every flag also reads from a `LIMEN_*`
//! environment variable, which is how the containers are configured.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, ValueEnum};
use limen_audit::FailureMode;
use limen_core::secret::Secret;

#[derive(Debug, Clone, Args)]
pub struct Config {
    /// Stable identifier of this replica. Appears in audit events and its certificate.
    #[arg(long, env = "LIMEN_ID", default_value = "control-plane")]
    pub id: String,

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

    /// Lifetime of proxy and worker certificates. They renew at half-life.
    #[arg(long, env = "LIMEN_COMPONENT_CERT_TTL", value_parser = parse_duration, default_value = "24h")]
    pub component_cert_ttl: Duration,

    /// Stub audit sink (Phase 1): a local JSONL file.
    #[arg(
        long,
        env = "LIMEN_AUDIT_FILE",
        default_value = "/var/lib/limen/audit/control-plane.jsonl"
    )]
    pub audit_file: PathBuf,

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
}

#[allow(clippy::unnecessary_wraps)] // clap value parsers must return Result
fn parse_secret(s: &str) -> Result<Secret<String>, String> {
    Ok(Secret::new(s.to_owned()))
}

fn parse_static_token(s: &str) -> Result<StaticJoinToken, String> {
    let (kind, token) = s.split_once(':').ok_or("expected kind:token")?;
    if !matches!(kind, "proxy" | "worker") {
        return Err(format!("unknown component kind {kind:?}"));
    }
    if token.len() < 32 {
        return Err("static join tokens must be at least 32 characters".into());
    }
    Ok(StaticJoinToken {
        kind: kind.to_owned(),
        token: Secret::new(token.to_owned()),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration_or_zero("0s"), Ok(Duration::ZERO));
        assert_eq!(parse_duration_or_zero("00m"), Ok(Duration::ZERO));
        assert_eq!(parse_duration_or_zero("20s"), Ok(Duration::from_secs(20)));
        assert!(parse_duration_or_zero("s").is_err());
        assert!(parse_duration("0s").is_err(), "TTLs must stay positive");
    }
}
