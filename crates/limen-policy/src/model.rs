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
}

impl Document {
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Document::Role(_) => "role",
            Document::RoleMapping(_) => "role_mapping",
            Document::Resource(_) => "resource",
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Document::Role(d) => &d.metadata.name,
            Document::RoleMapping(d) => &d.metadata.name,
            Document::Resource(d) => &d.metadata.name,
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
}

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
    /// Labels a worker must carry to serve this resource.
    #[serde(default)]
    pub worker_selector: Labels,
}

impl ResourceSpec {
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisTarget {
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default = "yes")]
    pub iam_auth: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubeTarget {
    pub cluster_name: String,
}

fn yes() -> bool {
    true
}
