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
// A command line: its switches are the bools.
#[allow(clippy::struct_excessive_bools)]
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

    /// Accept an ID token that has no `email_verified` claim when the
    /// username is the email. By default a missing claim is refused (an
    /// explicit `false` always is). Set it for an IdP that never sends the
    /// claim and verifies addresses itself.
    #[arg(
        long,
        env = "LIMEN_OIDC_ALLOW_UNVERIFIED_EMAIL",
        default_value_t = false
    )]
    pub oidc_allow_unverified_email: bool,

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
    /// Labels follow as `kind:token:key=value;key=value`. The pseudo-label
    /// `limen.io/name=<pattern>` approves component names instead: a pattern
    /// with one `*` (such as `worker-*`), since a reusable token can't give
    /// one exact name to many components. A component then picks its name
    /// with `--name`; without one it gets none.
    #[arg(long = "static-join-token", env = "LIMEN_STATIC_JOIN_TOKENS", value_delimiter = ',', value_parser = parse_static_token)]
    pub static_join_tokens: Vec<StaticJoinToken>,

    /// DNS names a proxy enrolled with a static token may put in its certificate.
    #[arg(
        long = "proxy-dns-name",
        env = "LIMEN_PROXY_DNS_NAMES",
        value_delimiter = ','
    )]
    pub proxy_dns_names: Vec<String>,

    /// User credential lifetime when none of the user's roles sets
    /// `cert_ttl`. At most `--max-cert-ttl`.
    #[arg(long, env = "LIMEN_DEFAULT_CERT_TTL", value_parser = parse_duration, default_value = "1h")]
    pub default_cert_ttl: Duration,

    /// Key that seals the IdP refresh tokens kept for offboarding checks
    /// (ADR-0047): 32 random bytes, base64. Without it the control plane
    /// stores no refresh token and does not check logins against the IdP.
    #[arg(long, env = "LIMEN_IDP_TOKEN_KEY", value_parser = parse_secret)]
    pub idp_token_key: Option<Secret<String>>,

    /// How often a login is checked against the IdP (ADR-0047). `0s` turns
    /// the check off.
    #[arg(long, env = "LIMEN_IDP_CHECK_INTERVAL", value_parser = parse_duration, default_value = "5m")]
    pub idp_check_interval: Duration,

    /// Delete the record of a person the IdP check disabled once they have
    /// stayed disabled this long (ADR-0047). Their sessions, recordings and
    /// audit history stay. An admin's lock never purges. `0s` turns it off.
    /// Runs with the IdP check, so it needs `--idp-token-key` too.
    #[arg(long, env = "LIMEN_IDP_PURGE_AFTER", value_parser = parse_duration_or_zero, default_value = "90d")]
    pub idp_purge_after: Duration,

    /// Bearer token the IdP's SCIM client presents to `/scim/v2` (ADR-0048).
    /// At least 32 characters. Without it the SCIM endpoint is off.
    #[arg(long, env = "LIMEN_SCIM_TOKEN", value_parser = parse_secret)]
    pub scim_token: Option<Secret<String>>,

    /// Do not end logins when a refreshed ID token no longer grants a role.
    /// For an IdP that leaves groups out of refreshed tokens. A token with no
    /// groups claim at all is never read as "no groups" either way: the login
    /// is kept and an alert raised (ADR-0047).
    #[arg(long, env = "LIMEN_IDP_IGNORE_GROUPS")]
    pub idp_ignore_groups: bool,

    /// What to do when the IdP cannot be asked: `open` keeps sessions and
    /// alerts, `closed` ends logins not confirmed within `--idp-check-grace`.
    #[arg(
        long,
        env = "LIMEN_IDP_CHECK_FAILURE",
        value_enum,
        default_value = "open"
    )]
    pub idp_check_failure: IdpCheckFailure,

    /// With `--idp-check-failure closed`: how long a login may go without a
    /// successful check before it ends.
    #[arg(long, env = "LIMEN_IDP_CHECK_GRACE", value_parser = parse_duration, default_value = "1h")]
    pub idp_check_grace: Duration,

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

    /// IAM role that `limen audit verify` may use to read the audit bucket
    /// (the `verifier_policy_json` permissions). The control plane assumes it
    /// and hands the caller short-lived credentials. Needs `sts:AssumeRole`.
    #[arg(long, env = "LIMEN_AUDIT_VERIFIER_ROLE_ARN")]
    pub audit_verifier_role_arn: Option<String>,

    /// The S3 endpoint verifiers should use, if it differs from the control
    /// plane's own (a VPC endpoint for the control plane, a public one for
    /// people). Defaults to `--audit-s3-endpoint`.
    #[arg(long, env = "LIMEN_AUDIT_VERIFIER_S3_ENDPOINT")]
    pub audit_verifier_s3_endpoint: Option<String>,

    /// How long verifier credentials last (AWS allows 15 minutes to 12 hours).
    #[arg(long, env = "LIMEN_AUDIT_VERIFIER_TTL", value_parser = parse_duration, default_value = "15m")]
    pub audit_verifier_ttl: Duration,

    /// For an S3-compatible store without STS (development): a fixed
    /// read-only key to hand to verifiers instead of a role. It does not expire.
    #[arg(long, env = "LIMEN_AUDIT_VERIFIER_ACCESS_KEY_ID")]
    pub audit_verifier_access_key_id: Option<String>,

    #[arg(long, env = "LIMEN_AUDIT_VERIFIER_SECRET_ACCESS_KEY", value_parser = parse_secret)]
    pub audit_verifier_secret_access_key: Option<Secret<String>>,

    /// Close an S3 batch after this long, even if it isn't full.
    #[arg(long, env = "LIMEN_AUDIT_S3_FLUSH", value_parser = parse_duration, default_value = "60s")]
    pub audit_s3_flush: Duration,

    /// Write an OCSF projection of the audit trail (ADR-0049) to this bucket
    /// for SIEMs. It must not be the audit bucket: a SIEM reader gets this
    /// bucket and nothing of the audit bucket, which holds recordings. Uses
    /// the audit bucket's path-style setting.
    #[arg(long, env = "LIMEN_AUDIT_OCSF_S3_BUCKET")]
    pub audit_ocsf_s3_bucket: Option<String>,

    /// S3 endpoint for the OCSF bucket, if it differs from `--audit-s3-endpoint`
    /// (another account or region, or an S3-compatible store in development).
    #[arg(long, env = "LIMEN_AUDIT_OCSF_S3_ENDPOINT")]
    pub audit_ocsf_s3_endpoint: Option<String>,

    /// Key prefix in the OCSF bucket. Empty, or ending in `/`.
    #[arg(long, env = "LIMEN_AUDIT_OCSF_S3_PREFIX", default_value = "")]
    pub audit_ocsf_s3_prefix: String,

    /// Encrypt OCSF objects with this KMS key. Must differ from
    /// `--audit-s3-kms-key`: the audit key protects recordings.
    #[arg(long, env = "LIMEN_AUDIT_OCSF_S3_KMS_KEY")]
    pub audit_ocsf_s3_kms_key: Option<String>,

    /// Close an OCSF batch after this long, even if it isn't full.
    #[arg(long, env = "LIMEN_AUDIT_OCSF_S3_FLUSH", value_parser = parse_duration, default_value = "60s")]
    pub audit_ocsf_s3_flush: Duration,

    /// If the OCSF sink fails while the spool holds more than this many bytes
    /// and the OCSF sink is the slowest consumer, it skips the batch (counted
    /// in `limen_audit_ocsf_skipped_total`) instead of holding the spool
    /// until it is full and audit fails closed. The events stay in the S3
    /// trail. Must be below `--audit-spool-max-bytes`.
    #[arg(long, env = "LIMEN_AUDIT_OCSF_MAX_LAG_BYTES", default_value_t = 256 * 1024 * 1024,
          value_parser = clap::value_parser!(u64).range(1..))]
    pub audit_ocsf_max_lag_bytes: u64,

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

    /// Close each API connection gracefully (HTTP/2 GOAWAY) after about this
    /// many seconds, ±10 % per connection, so clients reconnect, re-resolve
    /// the control plane's name, and spread over replicas, including new
    /// ones. 0 keeps connections for life. At most 604800 (7 days).
    #[arg(long, env = "LIMEN_MAX_CONNECTION_AGE_SECS", default_value_t = 300,
          value_parser = clap::value_parser!(u64).range(0..=604_800))]
    pub max_connection_age_secs: u64,

    /// After the maximum age, how long in-flight calls on that connection
    /// may finish before it is cut. 1 to 3600: 0 would cut every busy
    /// connection the moment it reaches its age.
    #[arg(long, env = "LIMEN_CONNECTION_AGE_GRACE_SECS", default_value_t = 30,
          value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub connection_age_grace_secs: u64,

    /// The most connections this replica's pool opens to PostgreSQL. The
    /// database sees up to this times the number of replicas: keep the
    /// total under its `max_connections` (Aurora: by instance class), or
    /// put RDS Proxy in front. 1 to 500.
    #[arg(long, env = "LIMEN_DATABASE_MAX_CONNECTIONS", default_value_t = 16,
          value_parser = clap::value_parser!(u32).range(1..=500))]
    pub database_max_connections: u32,

    /// Requests per minute from one client IP to the unauthenticated entry
    /// points (logins, enrollment, bot logins). Counted per replica, so the
    /// limit across a fleet is this times the number of replicas that the
    /// load balancer spreads one IP over. Raise it for sites where many
    /// users share one egress IP (browser sign-ins get twice as much).
    #[arg(long, env = "LIMEN_UNAUTHENTICATED_RATE_PER_MINUTE", default_value_t = 30,
          value_parser = clap::value_parser!(u32).range(1..=100_000))]
    pub unauthenticated_rate_per_minute: u32,

    /// The burst allowed on top of the rate, per client IP. Browser sign-ins
    /// get twice as much.
    #[arg(long, env = "LIMEN_UNAUTHENTICATED_BURST", default_value_t = 10,
          value_parser = clap::value_parser!(u32).range(1..=100_000))]
    pub unauthenticated_burst: u32,

    /// Tell this URL when an access request needs approval, is decided, or a
    /// break-glass grant is made (ADR-0025): a JSON POST signed with
    /// `--notify-webhook-secret`. It carries a request id and a console
    /// link, never the approval: approving happens only in Limen. `https`
    /// (or `http` to localhost, for development).
    #[arg(long, env = "LIMEN_NOTIFY_WEBHOOK_URL", value_parser = parse_secret)]
    pub notify_webhook_url: Option<Secret<String>>,

    /// Key for the `X-Limen-Signature` of the webhook:
    /// `HMAC-SHA256(secret, timestamp "." body)`.
    #[arg(long, env = "LIMEN_NOTIFY_WEBHOOK_SECRET", value_parser = parse_secret)]
    pub notify_webhook_secret: Option<Secret<String>>,

    /// A Slack incoming-webhook URL for the same notices. The URL is the
    /// credential.
    #[arg(long, env = "LIMEN_NOTIFY_SLACK_URL", value_parser = parse_secret)]
    pub notify_slack_url: Option<Secret<String>>,

    /// Also send break-glass grants here (a Slack incoming-webhook URL, for
    /// a channel people actually watch).
    #[arg(long, env = "LIMEN_BREAK_GLASS_SLACK_URL", value_parser = parse_secret)]
    pub break_glass_slack_url: Option<Secret<String>>,

    /// Also send break-glass grants to this webhook (signed like the other).
    #[arg(long, env = "LIMEN_BREAK_GLASS_WEBHOOK_URL", value_parser = parse_secret)]
    pub break_glass_webhook_url: Option<Secret<String>>,

    /// How long the console and `limen audit search` keep events and
    /// recording text searchable (ADR-0026). Older history stays in the sinks.
    #[arg(long, env = "LIMEN_SEARCH_RETENTION", value_parser = parse_duration, default_value = "30d")]
    pub search_retention: Duration,

    /// Also index the text of session recordings so an auditor can search
    /// what was on screen (ADR-0026). Off by default: terminals echo whatever
    /// is displayed, secrets included. Common secret shapes are masked, which
    /// is best effort and not a guarantee.
    #[arg(long, env = "LIMEN_SEARCH_RECORDINGS")]
    pub search_recordings: bool,

    /// A link to the same search in the full-history store, shown next to
    /// results. Placeholders: {query} {user} {resource} {kind} {after} {before}.
    #[arg(long, env = "LIMEN_SEARCH_HISTORY_URL")]
    pub search_history_url: Option<String>,

    /// How often an access review starts by itself (ADR-0029). 0 turns the
    /// schedule off; admins can still start one.
    #[arg(long, env = "LIMEN_REVIEW_INTERVAL", value_parser = parse_duration_or_zero, default_value = "90d")]
    pub review_interval: Duration,

    /// Let `limen:auditor` watch live sessions too (ADR-0030). Off by
    /// default: watching is a separate power from reading the record.
    #[arg(long, env = "LIMEN_AUDITORS_MAY_WATCH")]
    pub auditors_may_watch: bool,

    /// Put the requester, role, resource, and reason in notices. Off by
    /// default so resource names don't leave Limen.
    #[arg(long, env = "LIMEN_NOTIFY_INCLUDE_DETAILS")]
    pub notify_include_details: bool,

    /// Whether failing `policy_test` documents refuse a write (`required`)
    /// or are only reported (`advisory`), on every channel (ADR-0042 §6).
    #[arg(
        long,
        env = "LIMEN_POLICY_TESTS",
        value_enum,
        default_value = "advisory"
    )]
    pub policy_tests: PolicyTests,

    /// Whose writes that widen standing access wait for a person's approval:
    /// bot writers' only (`writers`), or people's too (`all`, a second
    /// admin approves).
    #[arg(
        long,
        env = "LIMEN_WIDENING_APPROVAL",
        value_enum,
        default_value = "writers"
    )]
    pub widening_approval: WideningApproval,

    /// How long a change held for approval waits before it expires.
    #[arg(long, env = "LIMEN_POLICY_CHANGE_TTL", value_parser = parse_duration, default_value = "7d")]
    pub policy_change_ttl: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PolicyTests {
    Advisory,
    Required,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum WideningApproval {
    Writers,
    All,
}

/// The rule when the IdP cannot be reached (ADR-0047).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum IdpCheckFailure {
    Open,
    Closed,
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
    /// Names components enrolled with this token may ask for. Always a pattern.
    pub name: Option<limen_core::names::NamePattern>,
}

#[allow(clippy::unnecessary_wraps)] // clap value parsers must return Result
fn parse_secret(s: &str) -> Result<Secret<String>, String> {
    Ok(Secret::new(s.to_owned()))
}

/// `kind:token` or `kind:token:key=value;key=value`, where the key
/// `limen.io/name` gives the name pattern rather than a label.
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
    let mut name = None;
    for pair in parts
        .next()
        .unwrap_or_default()
        .split(';')
        .filter(|p| !p.is_empty())
    {
        let (k, v) = pair
            .split_once('=')
            .ok_or_else(|| format!("label {pair:?} must be key=value"))?;
        if k == limen_core::names::NAME_LABEL {
            let pattern = limen_core::names::NamePattern::parse(v).map_err(|e| e.to_string())?;
            if pattern.exact().is_some() {
                return Err(format!(
                    "{k}={v}: a static token is reusable, so it can only approve a pattern with * (such as {v}-*), not one exact name"
                ));
            }
            if name.replace(pattern).is_some() {
                return Err(format!("{k} given twice"));
            }
            continue;
        }
        labels.insert(k, v).map_err(|e| e.to_string())?;
    }
    Ok(StaticJoinToken {
        kind: kind.to_owned(),
        token: Secret::new(token.to_owned()),
        labels,
        name,
    })
}

/// Like [`parse_duration`], but `0s` is allowed.
pub fn parse_duration_or_zero(s: &str) -> Result<Duration, String> {
    // Zero turns a feature off (no drain wait, no scheduled reviews), so only
    // a zero with a real unit counts: `0hours` or `0x` must be an error, not
    // a silent off switch.
    let s = s.trim();
    // A bare `0` stays valid: the docs say "0 off".
    let digits = s.strip_suffix(['s', 'm', 'h', 'd']).unwrap_or(s);
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
    /// Refuses a `--default-cert-ttl` above `--max-cert-ttl`, which would
    /// otherwise be cut silently.
    pub fn check_cert_ttls(&self) -> Result<(), String> {
        if self.default_cert_ttl > self.max_cert_ttl {
            return Err(format!(
                "--default-cert-ttl ({}s) is longer than --max-cert-ttl ({}s)",
                self.default_cert_ttl.as_secs(),
                self.max_cert_ttl.as_secs()
            ));
        }
        Ok(())
    }

    /// Refuses OCSF settings that would weaken the audit bucket's protection
    /// or could never take effect (ADR-0049).
    pub fn check_ocsf(&self) -> Result<(), String> {
        let Some(bucket) = &self.audit_ocsf_s3_bucket else {
            if self.audit_ocsf_s3_kms_key.is_some()
                || self.audit_ocsf_s3_endpoint.is_some()
                || !self.audit_ocsf_s3_prefix.is_empty()
            {
                return Err("the other --audit-ocsf-s3-* flags need --audit-ocsf-s3-bucket".into());
            }
            return Ok(());
        };
        if bucket.trim().is_empty() {
            return Err("--audit-ocsf-s3-bucket is empty".into());
        }
        // Names are compared the way S3 reads them (no padding, no case). A
        // different spelling of the same bucket (an access point, another
        // account's alias) can't be seen from here: the IAM separation in the
        // `audit` Terraform module (`ocsf.enabled`) is the control, this is a guard against
        // mistakes.
        let same_bucket = self
            .audit_s3_bucket
            .as_deref()
            .is_some_and(|a| a.trim().eq_ignore_ascii_case(bucket.trim()));
        // The same name on another endpoint is another store; on the same one it is not.
        // S3 bucket names are global on AWS, so every AWS endpoint (any region,
        // or none at all) is the same store.
        let norm = |e: &str| e.trim().trim_end_matches('/').to_ascii_lowercase();
        let aws = |e: &str| e.contains("amazonaws.com");
        let other_endpoint = self.audit_ocsf_s3_endpoint.as_deref().is_some_and(|e| {
            let e = norm(e);
            match self.audit_s3_endpoint.as_deref().map(norm) {
                Some(a) => e != a && !(aws(&e) && aws(&a)),
                // The audit bucket is on AWS (no endpoint): an AWS endpoint is the same store.
                None => !aws(&e),
            }
        });
        if same_bucket && !other_endpoint {
            return Err(
                "--audit-ocsf-s3-bucket must not be the audit bucket: whoever reads the SIEM feed would be able to read recordings"
                    .into(),
            );
        }
        // A key id, `alias/name` and a full ARN can name one key. Compare the
        // last path segment, which catches an alias or key id written two ways;
        // an alias and the key id it points to can't be told apart offline.
        let kms_name = |k: &str| k.trim().rsplit('/').next().unwrap_or_default().to_owned();
        if let Some(key) = &self.audit_ocsf_s3_kms_key
            && self
                .audit_s3_kms_key
                .as_deref()
                .is_some_and(|a| kms_name(a) == kms_name(key))
        {
            return Err(
                "--audit-ocsf-s3-kms-key must not be the audit KMS key: it also protects recordings"
                    .into(),
            );
        }
        let prefix = &self.audit_ocsf_s3_prefix;
        if prefix.starts_with('/') || (!prefix.is_empty() && !prefix.ends_with('/')) {
            return Err(
                "--audit-ocsf-s3-prefix must be empty, or end in `/` and not start with one".into(),
            );
        }
        if self.audit_ocsf_max_lag_bytes >= self.audit_spool_max_bytes {
            return Err(format!(
                "--audit-ocsf-max-lag-bytes ({}) must be below --audit-spool-max-bytes ({}), or the OCSF sink could still fill the spool",
                self.audit_ocsf_max_lag_bytes, self.audit_spool_max_bytes
            ));
        }
        Ok(())
    }

    /// Refuses a SCIM token too short to be unguessable.
    pub fn check_scim_token(&self) -> Result<(), String> {
        match &self.scim_token {
            Some(t) if t.expose().trim().len() < 32 => {
                Err("--scim-token must be at least 32 characters".to_owned())
            }
            _ => Ok(()),
        }
    }

    /// The key for sealed refresh tokens, if configured. Refuses one that is
    /// not 32 bytes of base64, and a check interval without a key.
    pub fn idp_token_key(&self) -> Result<Option<[u8; 32]>, String> {
        use base64::Engine as _;
        let Some(key) = &self.idp_token_key else {
            return Ok(None);
        };
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(key.expose().trim())
            .map_err(|_| "--idp-token-key must be base64".to_owned())?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "--idp-token-key must be 32 bytes (44 base64 characters)".to_owned())?;
        Ok(Some(key))
    }

    /// The notifiers these flags configure. Refuses a URL that is not
    /// `https` (or loopback `http`).
    pub fn notify_config(&self) -> Result<crate::access::notify::NotifyConfig, String> {
        use crate::access::notify::{Target, validate_url};
        let check = |name: &str, url: &Secret<String>| {
            validate_url(url.expose()).map_err(|e| format!("{name}: {e}"))
        };
        let mut cfg = crate::access::notify::NotifyConfig {
            include_details: self.notify_include_details,
            ..Default::default()
        };
        if let Some(url) = &self.notify_webhook_url {
            check("--notify-webhook-url", url)?;
            cfg.targets.push(Target::Webhook {
                url: url.clone(),
                secret: self.notify_webhook_secret.clone(),
            });
        } else if self.notify_webhook_secret.is_some() {
            return Err("--notify-webhook-secret needs --notify-webhook-url".into());
        }
        if let Some(url) = &self.notify_slack_url {
            check("--notify-slack-url", url)?;
            cfg.targets.push(Target::Slack { url: url.clone() });
        }
        if let Some(url) = &self.break_glass_slack_url {
            check("--break-glass-slack-url", url)?;
            cfg.break_glass_targets
                .push(Target::Slack { url: url.clone() });
        }
        if let Some(url) = &self.break_glass_webhook_url {
            check("--break-glass-webhook-url", url)?;
            cfg.break_glass_targets.push(Target::Webhook {
                url: url.clone(),
                secret: self.notify_webhook_secret.clone(),
            });
        }
        Ok(cfg)
    }

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
    fn static_tokens_with_name_patterns() {
        let t = parse_static_token(
            "worker:0123456789abcdef0123456789abcdef:pool=dev;limen.io/name=prod-a-*",
        )
        .expect("valid");
        assert_eq!(
            t.name.as_ref().map(limen_core::names::NamePattern::as_str),
            Some("prod-a-*")
        );
        // The pattern is not a label.
        assert_eq!(t.labels.get("limen.io/name"), None);
        assert_eq!(t.labels.get("pool"), Some("dev"));
        let t = parse_static_token("proxy:0123456789abcdef0123456789abcdef:limen.io/name=*")
            .expect("any name");
        assert!(t.name.is_some());
        assert!(
            parse_static_token("worker:0123456789abcdef0123456789abcdef")
                .expect("plain")
                .name
                .is_none()
        );
        let exact =
            parse_static_token("worker:0123456789abcdef0123456789abcdef:limen.io/name=worker-1")
                .expect_err("exact names are refused for reusable tokens");
        assert!(exact.contains("pattern"), "{exact}");
        for bad in ["Prod-*", "a*b*", "-*", ""] {
            assert!(
                parse_static_token(&format!(
                    "worker:0123456789abcdef0123456789abcdef:limen.io/name={bad}"
                ))
                .is_err(),
                "{bad:?}"
            );
        }
    }

    #[derive(clap::Parser)]
    struct Cli {
        #[command(flatten)]
        config: Config,
    }

    fn parse_with(extra: &[&str]) -> Result<Config, clap::Error> {
        use clap::Parser as _;
        let mut argv = vec![
            "limen-control-plane",
            "--database-url=postgres://x",
            "--oidc-issuer=https://idp.example",
            "--oidc-client-id=limen",
        ];
        argv.extend_from_slice(extra);
        Cli::try_parse_from(argv).map(|c| c.config)
    }

    #[test]
    fn default_cert_ttl_is_an_hour_and_at_most_the_max() {
        let ok = parse_with(&[]).expect("defaults");
        assert_eq!(ok.default_cert_ttl, Duration::from_hours(1));
        assert_eq!(ok.max_cert_ttl, Duration::from_hours(12));
        assert!(ok.check_cert_ttls().is_ok());
        let short = parse_with(&["--default-cert-ttl=10m"]).expect("10m");
        assert_eq!(short.default_cert_ttl, Duration::from_mins(10));
        assert!(short.check_cert_ttls().is_ok());
        let over = parse_with(&["--default-cert-ttl=2h", "--max-cert-ttl=1h"]).expect("parses");
        let err = over.check_cert_ttls().expect_err("above the max");
        assert!(err.contains("--default-cert-ttl"), "{err}");
    }

    #[test]
    fn ocsf_settings_cannot_share_the_audit_bucket_or_key_or_outgrow_the_spool() {
        let ok = |extra: &[&str]| parse_with(extra).expect("parses").check_ocsf();
        // Off by default, and nothing else may be set without the bucket.
        assert!(ok(&[]).is_ok());
        assert!(ok(&["--audit-ocsf-s3-kms-key=k"]).is_err());
        assert!(ok(&["--audit-ocsf-s3-prefix=x/"]).is_err());
        assert!(ok(&["--audit-ocsf-s3-bucket=siem"]).is_ok());
        // The audit bucket holds recordings.
        let same = ok(&["--audit-s3-bucket=audit", "--audit-ocsf-s3-bucket=audit"])
            .expect_err("same bucket");
        assert!(same.contains("must not be the audit bucket"), "{same}");
        assert!(ok(&["--audit-s3-bucket=audit", "--audit-ocsf-s3-bucket=siem"]).is_ok());
        // A different spelling of the same name is the same bucket.
        assert!(ok(&["--audit-s3-bucket=audit", "--audit-ocsf-s3-bucket=AUDIT "]).is_err());
        // The same name on another endpoint is a different store.
        assert!(
            ok(&[
                "--audit-s3-bucket=audit",
                "--audit-ocsf-s3-bucket=audit",
                "--audit-ocsf-s3-endpoint=https://other.example"
            ])
            .is_ok()
        );
        // On AWS (no audit endpoint), spelling out an AWS endpoint is the same store.
        assert!(
            ok(&[
                "--audit-s3-bucket=audit",
                "--audit-ocsf-s3-bucket=audit",
                "--audit-ocsf-s3-endpoint=https://s3.eu-west-1.amazonaws.com"
            ])
            .is_err()
        );
        // Two AWS regions are still one global bucket namespace.
        for ocsf in [
            "https://s3.eu-west-1.amazonaws.com",
            "https://s3.amazonaws.com",
        ] {
            assert!(
                ok(&[
                    "--audit-s3-bucket=audit",
                    "--audit-s3-endpoint=https://s3.us-east-1.amazonaws.com",
                    "--audit-ocsf-s3-bucket=audit",
                    &format!("--audit-ocsf-s3-endpoint={ocsf}"),
                ])
                .is_err(),
                "{ocsf}"
            );
        }
        // An S3-compatible store and AWS are different stores.
        assert!(
            ok(&[
                "--audit-s3-bucket=audit",
                "--audit-s3-endpoint=http://s3:8333",
                "--audit-ocsf-s3-bucket=audit",
                "--audit-ocsf-s3-endpoint=https://s3.eu-west-1.amazonaws.com",
            ])
            .is_ok()
        );
        // Spelling out the audit endpoint again does not make it another store.
        for same in ["http://s3:8333", "http://s3:8333/"] {
            assert!(
                ok(&[
                    "--audit-s3-bucket=audit",
                    "--audit-s3-endpoint=http://s3:8333",
                    "--audit-ocsf-s3-bucket=audit",
                    &format!("--audit-ocsf-s3-endpoint={same}"),
                ])
                .is_err(),
                "{same}"
            );
        }
        // And so does its key.
        let key = ok(&[
            "--audit-s3-kms-key=k1",
            "--audit-ocsf-s3-bucket=siem",
            "--audit-ocsf-s3-kms-key=k1",
        ])
        .expect_err("same key");
        assert!(key.contains("KMS key"), "{key}");
        assert!(
            ok(&[
                "--audit-s3-kms-key=k1",
                "--audit-ocsf-s3-bucket=siem",
                "--audit-ocsf-s3-kms-key=k2"
            ])
            .is_ok()
        );
        // An alias and its ARN, or a key id and its ARN, are the same key.
        for (audit, ocsf) in [
            (
                "alias/limen",
                "arn:aws:kms:eu-west-1:111122223333:alias/limen",
            ),
            ("arn:aws:kms:eu-west-1:111122223333:key/abc-123", "abc-123"),
        ] {
            let both = ok(&[
                &format!("--audit-s3-kms-key={audit}"),
                "--audit-ocsf-s3-bucket=siem",
                &format!("--audit-ocsf-s3-kms-key={ocsf}"),
            ]);
            assert!(both.is_err(), "{audit} vs {ocsf}");
        }
        // Prefix shape.
        assert!(ok(&["--audit-ocsf-s3-bucket=siem", "--audit-ocsf-s3-prefix=ocsf"]).is_err());
        assert!(
            ok(&[
                "--audit-ocsf-s3-bucket=siem",
                "--audit-ocsf-s3-prefix=/ocsf/"
            ])
            .is_err()
        );
        assert!(
            ok(&[
                "--audit-ocsf-s3-bucket=siem",
                "--audit-ocsf-s3-prefix=ocsf/"
            ])
            .is_ok()
        );
        assert!(ok(&["--audit-ocsf-s3-bucket= "]).is_err());
        // The lag bound must be reachable before the spool is full.
        let lag = ok(&[
            "--audit-ocsf-s3-bucket=siem",
            "--audit-spool-max-bytes=1000",
            "--audit-ocsf-max-lag-bytes=1000",
        ])
        .expect_err("not below the spool size");
        assert!(lag.contains("must be below"), "{lag}");
        assert!(parse_with(&["--audit-ocsf-max-lag-bytes=0"]).is_err());
    }

    #[test]
    fn login_rate_limit_flags_keep_the_old_defaults_and_are_bounded() {
        let ok = parse_with(&[]).expect("defaults");
        assert_eq!(ok.unauthenticated_rate_per_minute, 30);
        assert_eq!(ok.unauthenticated_burst, 10);
        assert!(parse_with(&["--unauthenticated-rate-per-minute=0"]).is_err());
        assert!(parse_with(&["--unauthenticated-burst=0"]).is_err());
        assert_eq!(ok.database_max_connections, 16);
        assert!(parse_with(&["--database-max-connections=0"]).is_err());
        assert!(parse_with(&["--database-max-connections=501"]).is_err());
        assert!(parse_with(&["--database-max-connections=40"]).is_ok());
        assert!(parse_with(&["--unauthenticated-rate-per-minute=100001"]).is_err());
        assert!(
            parse_with(&[
                "--unauthenticated-rate-per-minute=600",
                "--unauthenticated-burst=100"
            ])
            .is_ok()
        );
    }

    #[test]
    fn connection_age_flags_are_bounded() {
        let ok = parse_with(&[]).expect("defaults");
        assert_eq!(ok.max_connection_age_secs, 300);
        assert_eq!(ok.connection_age_grace_secs, 30);
        assert!(
            parse_with(&["--max-connection-age-secs=0"]).is_ok(),
            "0 disables it"
        );
        assert!(parse_with(&["--max-connection-age-secs=604800"]).is_ok());
        // Absurd ages fail at startup with a clear message, never later in
        // the accept loop.
        let err =
            parse_with(&["--max-connection-age-secs=18446744073709551615"]).expect_err("too large");
        assert!(err.to_string().contains("max-connection-age-secs"), "{err}");
        assert!(parse_with(&["--max-connection-age-secs=604801"]).is_err());
        // A grace of 0 would cut every busy connection at its age.
        let err = parse_with(&["--connection-age-grace-secs=0"]).expect_err("zero grace");
        assert!(
            err.to_string().contains("connection-age-grace-secs"),
            "{err}"
        );
        assert!(parse_with(&["--connection-age-grace-secs=3601"]).is_err());
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration_or_zero("0s"), Ok(Duration::ZERO));
        assert_eq!(parse_duration_or_zero("00m"), Ok(Duration::ZERO));
        assert_eq!(parse_duration_or_zero("20s"), Ok(Duration::from_secs(20)));
        assert_eq!(parse_duration_or_zero("0"), Ok(Duration::ZERO));
        assert!(parse_duration_or_zero("s").is_err());
        for typo in ["0x", "0hours", "0 days", "0w"] {
            assert!(parse_duration_or_zero(typo).is_err(), "{typo:?}");
        }
        assert!(parse_duration("0s").is_err(), "TTLs must stay positive");
    }
}
