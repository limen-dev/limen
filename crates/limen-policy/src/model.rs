//! YAML document model. Parsing is strict: unknown fields are errors.

use std::collections::BTreeMap;

use limen_core::labels::Labels;
use limen_core::resource::ResourceKind;
use serde::{Deserialize, Serialize};

use crate::duration::DurationStr;

/// One YAML document. The `kind` field selects the variant.
// Documents are parsed rarely and held in maps, so variant size doesn't matter.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Document {
    Role(RoleDoc),
    RoleMapping(RoleMappingDoc),
    Resource(ResourceDoc),
    Bot(crate::bot::BotDoc),
}

impl Document {
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Document::Role(_) => "role",
            Document::RoleMapping(_) => "role_mapping",
            Document::Resource(_) => "resource",
            Document::Bot(_) => "bot",
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Document::Role(d) => &d.metadata.name,
            Document::RoleMapping(d) => &d.metadata.name,
            Document::Resource(d) => &d.metadata.name,
            Document::Bot(d) => &d.metadata.name,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Version {
    #[serde(rename = "v1")]
    V1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub labels: Labels,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleDoc {
    pub version: Version,
    pub metadata: Metadata,
    pub spec: RoleSpec,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleSpec {
    /// Lifetime of credentials issued at login. The shortest across a user's roles wins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_ttl: Option<DurationStr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_session_ttl: Option<DurationStr>,
    #[serde(default)]
    pub allow: Vec<Rule>,
    #[serde(default)]
    pub deny: Vec<Rule>,
}

/// Selects resources and, optionally, the principals that may be used on them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub resources: Selector,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh: Option<SshGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db: Option<DbGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kube: Option<KubeGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redis: Option<RedisGrant>,
    // Planned integrations (ADR-0018, ADR-0022): the policy accepts them so
    // resources and roles can be written and reviewed now; no worker serves
    // them yet. Redshift uses `db`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mongo: Option<MongoGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search: Option<SearchGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mq: Option<UserGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kafka: Option<UserGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web: Option<OpenGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp: Option<OpenGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selector {
    pub kind: Vec<ResourceKind>,
    /// Every key must match. Any value within a key may match. `"*"` as the only
    /// value means "the key is present with any value". The key `"*"` with
    /// value `["*"]` matches every resource.
    #[serde(default)]
    pub labels: BTreeMap<String, Vec<String>>,
    /// Optional explicit resource names. Both the names and the labels must match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshGrant {
    pub logins: Vec<String>,
    #[serde(default)]
    pub port_forwarding: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DbGrant {
    pub roles: Vec<String>,
    #[serde(default = "all")]
    pub databases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubeGrant {
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisGrant {
    pub users: Vec<String>,
    /// Commands refused for this grant on top of the built-in deny list
    /// (ADR-0034). `NAME` or `NAME SUBCOMMAND`, case-insensitive.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_commands: Vec<String>,
    /// Commands from the built-in deny list this grant opens up again.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_commands: Vec<String>,
    /// Key patterns (`*` and `?`) the session may touch. Empty means any key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<String>,
    /// Logical databases the session may `SELECT`. Empty means only 0.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub databases: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MongoGrant {
    /// Names the worker has a credential for (`credentials_dir` on the
    /// resource). With `x509` or `aws` they are labels for the identity the
    /// worker holds (ADR-0035).
    pub roles: Vec<String>,
    #[serde(default = "all")]
    pub databases: Vec<String>,
    /// Command names (case-insensitive) a session on this grant may not run,
    /// for example `drop`, `dropDatabase`, `createIndexes`. A session may do
    /// whatever any one grant that covers its database permits.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_commands: Vec<String>,
}

/// `OpenSearch` or `Elasticsearch` roles the session may act as.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchGrant {
    pub roles: Vec<String>,
}

/// Broker users (`RabbitMQ`, `Kafka`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserGrant {
    pub users: Vec<String>,
}

/// Web apps and TCP services have no upstream identity to choose: the grant is
/// access itself, written `web: {}` or `tcp: {}`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenGrant {}

fn all() -> Vec<String> {
    vec!["*".to_owned()]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleMappingDoc {
    pub version: Version,
    pub metadata: Metadata,
    pub spec: Vec<GroupMapping>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupMapping {
    pub idp_group: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceDoc {
    pub version: Version,
    pub metadata: Metadata,
    pub spec: ResourceSpec,
}

/// Exactly one of the protocol sections must be set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh: Option<SshTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postgres: Option<DbTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mysql: Option<DbTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redis: Option<RedisTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes: Option<KubeTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redshift: Option<DbTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mongodb: Option<MongoTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opensearch: Option<SearchTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elasticsearch: Option<SearchTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rabbitmq: Option<BrokerTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kafka: Option<BrokerTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web: Option<WebTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp: Option<TcpTarget>,
    /// Labels a worker must carry to serve this resource.
    #[serde(default)]
    pub worker_selector: Labels,
}

impl ResourceSpec {
    /// Where the resource points, for admins: an address, or a cluster name.
    #[must_use]
    pub fn target(&self) -> Option<String> {
        if let Some(t) = &self.ssh {
            return Some(t.address.clone());
        }
        if let Some(t) = self
            .postgres
            .as_ref()
            .or(self.mysql.as_ref())
            .or(self.redshift.as_ref())
        {
            return Some(t.endpoint.clone());
        }
        if let Some(t) = &self.redis {
            return Some(t.endpoint.clone());
        }
        if let Some(t) = &self.kubernetes {
            return Some(t.cluster_name.clone());
        }
        if let Some(t) = &self.mongodb {
            return Some(match t.flavor {
                MongoFlavor::Standard => t.endpoint.clone(),
                MongoFlavor::Atlas => format!("{} (Atlas)", t.endpoint),
                MongoFlavor::Documentdb => format!("{} (DocumentDB)", t.endpoint),
            });
        }
        if let Some(t) = self.opensearch.as_ref().or(self.elasticsearch.as_ref()) {
            return Some(t.endpoint.clone());
        }
        if let Some(t) = self.rabbitmq.as_ref().or(self.kafka.as_ref()) {
            return Some(t.endpoint.clone());
        }
        if let Some(t) = &self.web {
            return Some(format!("{} → {}", t.host, t.address));
        }
        self.tcp.as_ref().map(|t| t.address.clone())
    }

    #[must_use]
    pub fn kinds(&self) -> Vec<ResourceKind> {
        let mut kinds = Vec::new();
        if self.ssh.is_some() {
            kinds.push(ResourceKind::Ssh);
        }
        if self.postgres.is_some() {
            kinds.push(ResourceKind::Postgres);
        }
        if self.mysql.is_some() {
            kinds.push(ResourceKind::Mysql);
        }
        if self.redis.is_some() {
            kinds.push(ResourceKind::Redis);
        }
        if self.kubernetes.is_some() {
            kinds.push(ResourceKind::Kubernetes);
        }
        let planned = [
            (self.redshift.is_some(), ResourceKind::Redshift),
            (self.mongodb.is_some(), ResourceKind::Mongodb),
            (self.opensearch.is_some(), ResourceKind::Opensearch),
            (self.elasticsearch.is_some(), ResourceKind::Elasticsearch),
            (self.rabbitmq.is_some(), ResourceKind::Rabbitmq),
            (self.kafka.is_some(), ResourceKind::Kafka),
            (self.web.is_some(), ResourceKind::Web),
            (self.tcp.is_some(), ResourceKind::Tcp),
        ];
        kinds.extend(planned.into_iter().filter(|(set, _)| *set).map(|(_, k)| k));
        kinds
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshTarget {
    /// `host:port`.
    pub address: String,
    /// Pinned host public key in OpenSSH format, if the target has no host certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DbTarget {
    /// `host:port`.
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default = "yes")]
    pub iam_auth: bool,
    /// Secrets Manager ARN holding the admin credentials used for role bootstrap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_secret_arn: Option<String>,
    /// Redshift (provisioned): the cluster to ask for temporary credentials
    /// (`GetClusterCredentials`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_identifier: Option<String>,
    /// Redshift Serverless: the workgroup to ask for credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workgroup: Option<String>,
    /// The database to use when the user doesn't name one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_database: Option<String>,
    /// Secret mode (ADR-0033): a directory on the worker with one file per DB
    /// role, named for the role, holding its password. Used when `iam_auth` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_dir: Option<String>,
    /// PEM bundle on the worker that signs the target's certificate (for
    /// example the RDS bundle). Without it the system roots are used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_ca_file: Option<String>,
    /// The name the target's certificate must carry, when it differs from the
    /// host in `endpoint` (an IP address, a `PrivateLink` name, a tunnel).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_server_name: Option<String>,
    /// Talk to the target without TLS. Refused unless the worker was started
    /// with `--allow-insecure-db-targets` (the local compose profile).
    #[serde(default)]
    pub insecure_dev: bool,
    /// Replace literals in logged statement text with `?` (`audit.normalize_literals`).
    #[serde(default)]
    pub normalize_literals: bool,
    /// Role bootstrap (ADR-0015, ADR-0033): a dedicated admin login and the
    /// file on the worker that holds its password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_password_file: Option<String>,
    /// Roles to create and the grants they get (bootstrap).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bootstrap: Vec<DbRoleSpec>,
}

/// A database login role Limen creates and maintains (ADR-0015).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DbRoleSpec {
    /// Must start with `limen_`.
    pub role: String,
    /// Each entry is a database and the privileges the role gets in it.
    #[serde(default)]
    pub grants: Vec<DbGrantSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DbGrantSpec {
    pub database: String,
    /// `read` (SELECT) or `write` (SELECT, INSERT, UPDATE, DELETE), on every
    /// table in the listed schemas (default `public` for PostgreSQL).
    pub access: DbAccess,
    #[serde(default)]
    pub schemas: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DbAccess {
    Read,
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisTarget {
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default = "yes")]
    pub iam_auth: bool,
    /// The `ElastiCache` replication group ID, which names the IAM token's host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_name: Option<String>,
    /// TLS toward the target. On by default; `false` is for local servers only.
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub tls: bool,
    /// Left out of the snapshot when default, so components from before
    /// Phase 7 (which reject unknown fields) still read it during an upgrade.
    #[serde(default, skip_serializing_if = "RedisAudit::is_default")]
    pub audit: RedisAudit,
}

impl RedisAudit {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if passes a reference
fn is_true(b: &bool) -> bool {
    *b
}

/// What a `redis.command` event may contain (ADR-0034). Values are never
/// logged unless `log_values` is set, and credential commands never are.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisAudit {
    #[serde(default)]
    pub log_values: bool,
    /// Replace key names with a hash, so the trail holds no ids or emails.
    #[serde(default)]
    pub redact_keys: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubeTarget {
    pub cluster_name: String,
}

/// Where a MongoDB-compatible server runs, which decides how the worker will
/// authenticate (ADR-0018).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MongoFlavor {
    #[default]
    Standard,
    Atlas,
    Documentdb,
}

/// How the worker logs in to a MongoDB-compatible server (ADR-0035).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MongoAuth {
    /// `SCRAM-SHA-256` with the role's password from `credentials_dir`.
    #[default]
    Scram,
    /// `SCRAM-SHA-1`, for servers without SHA-256 (`DocumentDB` 4.0).
    ScramSha1,
    /// `MONGODB-X509`: a client certificate and key per role in `credentials_dir`.
    X509,
    /// `MONGODB-AWS`: the worker's IAM identity (Atlas and `DocumentDB`).
    /// Unverified against the real services.
    Aws,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MongoTarget {
    /// `host:port`. A replica set member is enough: the worker follows the
    /// primary the member names (no `mongodb+srv` resolution yet).
    pub endpoint: String,
    #[serde(default)]
    pub flavor: MongoFlavor,
    #[serde(default)]
    pub auth: MongoAuth,
    /// The database to use when the user doesn't name one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_database: Option<String>,
    /// Where the users are defined (`authSource`). Default `admin`, or
    /// `$external` for `x509` and `aws`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_source: Option<String>,
    /// A directory on the worker: `<role>` holds that role's password
    /// (`scram`, `scram_sha1`) and `<role>.pem` its client certificate and
    /// key (`x509`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials_dir: Option<String>,
    /// PEM bundle that signs the server's certificate. Required: for Atlas
    /// use the system bundle, for `DocumentDB` the AWS global bundle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_ca_file: Option<String>,
    /// The name the server's certificate must carry, when it differs from
    /// the host in `endpoint`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_server_name: Option<String>,
    /// Talk to the server without TLS. Only for `standard` servers, and refused
    /// unless the worker runs with `--allow-insecure-db-targets`.
    #[serde(default)]
    pub insecure_dev: bool,
    /// Keep the values of commands in the audit trail (`audit.full_commands`).
    /// The default replaces every value in a filter, document, or pipeline
    /// with `?` and keeps the shape.
    #[serde(default)]
    pub full_commands: bool,
}

/// `OpenSearch` or `Elasticsearch` over HTTP(S).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchTarget {
    /// `host:port`.
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// An AWS-managed domain (`OpenSearch` Service), reached with `SigV4`.
    #[serde(default)]
    pub aws: bool,
}

/// `RabbitMQ` or `Kafka`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerTarget {
    /// `host:port` of one broker or bootstrap address.
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Amazon MQ or `MSK`.
    #[serde(default)]
    pub aws: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebTarget {
    /// `host:port` of the app, as the worker reaches it.
    pub address: String,
    /// The public host name users open, such as `grafana.apps.example.com`.
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpTarget {
    /// `host:port`.
    pub address: String,
}

fn yes() -> bool {
    true
}
