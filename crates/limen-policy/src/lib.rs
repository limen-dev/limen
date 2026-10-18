//! Policy: YAML roles, role mappings, and resources, with a deny-by-default
//! evaluator (ADR-0008).

pub mod bot;
pub mod duration;
pub mod model;

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use limen_core::identity::ADMIN_ROLE;
use limen_core::labels::Labels;
use limen_core::resource::ResourceKind;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use model::Document;
pub use model::{
    KafkaClass, KafkaGrant, KafkaSasl, MqClass, MqGrant, RedisAudit, RedisGrant, RedisTarget,
};
use model::{ResourceDoc, RoleDoc, Rule, Selector};

/// Default lifetime of login credentials when no role sets `cert_ttl`.
pub const DEFAULT_CERT_TTL: Duration = Duration::from_mins(10);
/// Default cap on a single session's length.
pub const DEFAULT_MAX_SESSION_TTL: Duration = Duration::from_hours(8);
const MAX_NAME_LEN: usize = 128;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("{source_name}: YAML error: {message}")]
    Parse {
        source_name: String,
        message: String,
    },
    #[error("{kind} {name:?}: {message}")]
    Invalid {
        kind: &'static str,
        name: String,
        message: String,
    },
    #[error("duplicate {kind} {name:?}")]
    Duplicate { kind: &'static str, name: String },
}

fn invalid(kind: &'static str, name: &str, message: impl Into<String>) -> PolicyError {
    PolicyError::Invalid {
        kind,
        name: name.to_owned(),
        message: message.into(),
    }
}

/// Result of evaluating an access request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Decision {
    Allow {
        matched_roles: Vec<String>,
    },
    Deny {
        reason: DenyReason,
    },
    /// Reserved for just-in-time and approval workflows. Not produced in v1.
    /// Enforcement points must treat it as a denial.
    RequiresApproval {
        reason: String,
    },
}

impl Decision {
    /// True only for an explicit allow. Every other variant, including ones
    /// added later, denies access.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allow { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    NoMatchingRole,
    ExplicitDeny,
    UnknownResource,
    PolicySnapshotStale,
    InvalidRequest,
}

/// The upstream identity a session will use on the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    SshLogin(String),
    DbRole { role: String, database: String },
    KubeGroup(String),
    RedisUser(String),
    // Planned integrations: modelled so policy can be written and tested now.
    MongoRole { role: String, database: String },
    SearchRole(String),
    MqUser(String),
    KafkaUser(String),
    WebAccess,
    TcpAccess,
}

#[derive(Debug, Clone)]
pub struct AccessRequest<'a> {
    pub roles: &'a [String],
    pub resource: &'a str,
    pub principal: Principal,
}

/// A resource visible to a user, with the principals they may use on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessibleResource {
    pub name: String,
    pub kind: ResourceKind,
    pub labels: BTreeMap<String, String>,
    pub principals: Vec<String>,
}

/// A compiled, validated policy.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    roles: BTreeMap<String, RoleDoc>,
    /// IdP group → roles, merged across all `role_mapping` documents.
    group_roles: BTreeMap<String, BTreeSet<String>>,
    mapping_docs: BTreeMap<String, model::RoleMappingDoc>,
    resources: BTreeMap<String, ResourceDoc>,
    #[serde(default)]
    bots: BTreeMap<String, bot::BotDoc>,
}

/// Changes between two policies, by `kind/name`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDiff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
}

impl PolicyDiff {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

impl Policy {
    /// Parse one or more YAML sources, each possibly holding several `---`
    /// separated documents, and compile them into a single policy.
    pub fn parse_yaml<'a>(
        sources: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, PolicyError> {
        let mut docs = Vec::new();
        for (source_name, text) in sources {
            let parsed: Vec<Document> =
                serde_saphyr::from_multiple(text).map_err(|e| PolicyError::Parse {
                    source_name: source_name.to_owned(),
                    message: e.to_string(),
                })?;
            docs.extend(parsed);
        }
        Self::from_documents(docs)
    }

    pub fn from_documents(docs: impl IntoIterator<Item = Document>) -> Result<Self, PolicyError> {
        let mut policy = Policy::default();
        for doc in docs {
            match doc {
                Document::Role(role) => {
                    validate_role(&role)?;
                    let name = role.metadata.name.clone();
                    if policy.roles.insert(name.clone(), role).is_some() {
                        return Err(PolicyError::Duplicate { kind: "role", name });
                    }
                }
                Document::RoleMapping(mapping) => {
                    let name = mapping.metadata.name.clone();
                    validate_name("role_mapping", &name, &name)?;
                    if policy.mapping_docs.insert(name.clone(), mapping).is_some() {
                        return Err(PolicyError::Duplicate {
                            kind: "role_mapping",
                            name,
                        });
                    }
                }
                Document::Bot(bot) => {
                    bot::validate_bot(&bot)?;
                    let name = bot.metadata.name.clone();
                    if policy.bots.insert(name.clone(), bot).is_some() {
                        return Err(PolicyError::Duplicate { kind: "bot", name });
                    }
                }
                Document::Resource(resource) => {
                    validate_resource(&resource)?;
                    let name = resource.metadata.name.clone();
                    if policy.resources.insert(name.clone(), resource).is_some() {
                        return Err(PolicyError::Duplicate {
                            kind: "resource",
                            name,
                        });
                    }
                }
            }
        }
        for (doc_name, mapping) in &policy.mapping_docs {
            for m in &mapping.spec {
                if m.idp_group.is_empty() || m.idp_group.len() > 256 {
                    return Err(invalid(
                        "role_mapping",
                        doc_name,
                        "idp_group must be 1..=256 chars",
                    ));
                }
                for role in &m.roles {
                    if role != ADMIN_ROLE && !policy.roles.contains_key(role) {
                        return Err(invalid(
                            "role_mapping",
                            doc_name,
                            format!("unknown role {role:?}"),
                        ));
                    }
                    policy
                        .group_roles
                        .entry(m.idp_group.clone())
                        .or_default()
                        .insert(role.clone());
                }
            }
        }
        for (name, bot) in &policy.bots {
            for role in &bot.spec.roles {
                if !policy.roles.contains_key(role) {
                    return Err(invalid("bot", name, format!("unknown role {role:?}")));
                }
            }
        }
        Ok(policy)
    }

    /// SHA-256 over the canonical JSON form. Equal policies have equal digests.
    #[must_use]
    pub fn digest(&self) -> String {
        let json = serde_json::to_vec(&self.documents()).unwrap_or_default();
        Sha256::digest(json)
            .iter()
            .fold(String::with_capacity(64), |mut s, b| {
                use std::fmt::Write;
                let _ = write!(s, "{b:02x}");
                s
            })
    }

    /// Every document, sorted by kind and name.
    #[must_use]
    pub fn documents(&self) -> Vec<Document> {
        let mut out: Vec<Document> = self.roles.values().cloned().map(Document::Role).collect();
        out.extend(
            self.mapping_docs
                .values()
                .cloned()
                .map(Document::RoleMapping),
        );
        out.extend(self.resources.values().cloned().map(Document::Resource));
        out.extend(self.bots.values().cloned().map(Document::Bot));
        out
    }

    /// What changes when going from `self` to `next`.
    #[must_use]
    pub fn diff(&self, next: &Policy) -> PolicyDiff {
        let index = |p: &Policy| -> BTreeMap<String, serde_json::Value> {
            p.documents()
                .into_iter()
                .map(|d| {
                    (
                        format!("{}/{}", d.kind(), d.name()),
                        serde_json::to_value(&d).unwrap_or_default(),
                    )
                })
                .collect()
        };
        let (old, new) = (index(self), index(next));
        let mut diff = PolicyDiff::default();
        for (key, value) in &new {
            match old.get(key) {
                None => diff.added.push(key.clone()),
                Some(prev) if prev != value => diff.changed.push(key.clone()),
                Some(_) => {}
            }
        }
        diff.removed = old
            .keys()
            .filter(|k| !new.contains_key(*k))
            .cloned()
            .collect();
        diff
    }

    /// Roles for a user with the given IdP groups. `bootstrap_admin_groups`
    /// come from control plane config, so the first admin can log in before
    /// any policy exists.
    #[must_use]
    pub fn roles_for_groups<'a>(
        &self,
        groups: impl IntoIterator<Item = &'a str>,
        bootstrap_admin_groups: &[String],
    ) -> BTreeSet<String> {
        let mut roles = BTreeSet::new();
        for group in groups {
            if let Some(mapped) = self.group_roles.get(group) {
                roles.extend(mapped.iter().cloned());
            }
            if bootstrap_admin_groups.iter().any(|g| g == group) {
                roles.insert(ADMIN_ROLE.to_owned());
            }
        }
        roles
    }

    /// Credential lifetime for a set of roles: the shortest `cert_ttl`,
    /// otherwise [`DEFAULT_CERT_TTL`], always capped at `max`.
    #[must_use]
    pub fn cert_ttl(&self, roles: &[String], max: Duration) -> Duration {
        roles
            .iter()
            .filter_map(|r| self.roles.get(r)?.spec.cert_ttl.map(|d| d.0))
            .min()
            .unwrap_or(DEFAULT_CERT_TTL)
            .min(max)
    }

    /// How long a session may last: the shortest `max_session_ttl` across
    /// the roles, otherwise [`DEFAULT_MAX_SESSION_TTL`].
    #[must_use]
    pub fn max_session_ttl(&self, roles: &[String]) -> Duration {
        roles
            .iter()
            .filter_map(|r| self.roles.get(r)?.spec.max_session_ttl.map(|d| d.0))
            .min()
            .unwrap_or(DEFAULT_MAX_SESSION_TTL)
    }

    #[must_use]
    pub fn bot(&self, name: &str) -> Option<&bot::BotDoc> {
        self.bots.get(name)
    }

    pub fn bots(&self) -> impl Iterator<Item = &bot::BotDoc> {
        self.bots.values()
    }

    /// The issuers whose tokens can log a bot in with `method`, without a
    /// trailing slash. The control plane only fetches keys for these.
    #[must_use]
    pub fn bot_issuers(&self, method: bot::JoinMethod) -> BTreeSet<String> {
        self.bots
            .values()
            .filter(|b| b.spec.join.method == method)
            .filter_map(|b| b.spec.join.issuer())
            .collect()
    }

    /// Bots whose rule `claims` satisfy, for a token from `issuer` presented
    /// with `method`. `named` narrows it to one bot. More than one match is
    /// the caller's problem to refuse: an ambiguous token logs nobody in.
    #[must_use]
    pub fn match_bots(
        &self,
        method: bot::JoinMethod,
        issuer: &str,
        claims: &BTreeMap<String, String>,
        named: Option<&str>,
    ) -> Vec<&bot::BotDoc> {
        let issuer = issuer.trim_end_matches('/');
        self.bots
            .values()
            .filter(|b| named.is_none_or(|n| b.metadata.name == n))
            .filter(|b| b.spec.join.method == method)
            .filter(|b| b.spec.join.issuer().as_deref() == Some(issuer))
            .filter(|b| b.spec.join.matches(claims))
            .collect()
    }

    #[must_use]
    pub fn resource(&self, name: &str) -> Option<&ResourceDoc> {
        self.resources.get(name)
    }

    /// Whether a worker with `worker_labels` (from its certificate) may serve
    /// `resource`: every `worker_selector` label must match exactly. An empty
    /// selector matches any worker.
    #[must_use]
    pub fn worker_may_serve(
        &self,
        resource: &str,
        worker_labels: &BTreeMap<String, String>,
    ) -> bool {
        self.resources.get(resource).is_some_and(|r| {
            r.spec.worker_selector.iter().all(|(k, v)| {
                // A component's name is display only (a token holder picks
                // its value within the approved pattern), so no selector can
                // match it, whatever the policy says.
                k != limen_core::names::NAME_LABEL
                    && worker_labels.get(k).is_some_and(|actual| actual == v)
            })
        })
    }

    /// Every resource, in name order.
    pub fn resources(&self) -> impl Iterator<Item = &ResourceDoc> {
        self.resources.values()
    }

    #[must_use]
    pub fn resource_count(&self) -> usize {
        self.resources.len()
    }

    /// Deny by default. Any matching deny rule wins. Otherwise some allow rule
    /// must match the resource and list the requested principal.
    #[must_use]
    pub fn evaluate(&self, req: &AccessRequest<'_>) -> Decision {
        let Some(resource) = self.resources.get(req.resource) else {
            return Decision::Deny {
                reason: DenyReason::UnknownResource,
            };
        };
        let kind = resource_kind(resource);
        if !principal_fits_kind(&req.principal, kind) {
            return Decision::Deny {
                reason: DenyReason::InvalidRequest,
            };
        }
        let roles: Vec<&RoleDoc> = req.roles.iter().filter_map(|r| self.roles.get(r)).collect();

        let denied = roles.iter().flat_map(|r| &r.spec.deny).any(|rule| {
            selector_matches(&rule.resources, resource)
                && (rule_has_no_principals(rule) || rule_grants(rule, &req.principal))
        });
        if denied {
            return Decision::Deny {
                reason: DenyReason::ExplicitDeny,
            };
        }

        let matched_roles: Vec<String> = roles
            .iter()
            .filter(|r| {
                r.spec.allow.iter().any(|rule| {
                    selector_matches(&rule.resources, resource) && rule_grants(rule, &req.principal)
                })
            })
            .map(|r| r.metadata.name.clone())
            .collect();
        if matched_roles.is_empty() {
            Decision::Deny {
                reason: DenyReason::NoMatchingRole,
            }
        } else {
            Decision::Allow { matched_roles }
        }
    }

    /// The Redis grants that let `roles` act as `user` on `resource`. A session
    /// may do whatever any one of them permits (ADR-0034). Call it only after
    /// [`Policy::evaluate`] allowed the request, since deny rules aren't checked here.
    #[must_use]
    pub fn redis_grants(&self, roles: &[String], resource: &str, user: &str) -> Vec<RedisGrant> {
        let Some(resource) = self.resources.get(resource) else {
            return Vec::new();
        };
        roles
            .iter()
            .filter_map(|r| self.roles.get(r))
            .flat_map(|r| &r.spec.allow)
            .filter(|rule| selector_matches(&rule.resources, resource))
            .filter_map(|rule| rule.redis.as_ref())
            .filter(|g| g.users.iter().any(|u| u == user))
            .cloned()
            .collect()
    }

    /// The `RabbitMQ` grants that let `roles` act as `user` on `resource`
    /// (ADR-0037). Same contract as [`Policy::redis_grants`].
    #[must_use]
    pub fn mq_grants(&self, roles: &[String], resource: &str, user: &str) -> Vec<MqGrant> {
        self.rules_for(roles, resource)
            .filter_map(|rule| rule.mq.as_ref())
            .filter(|g| g.users.iter().any(|u| u == user))
            .cloned()
            .collect()
    }

    /// The `Kafka` grants that let `roles` act as `user` on `resource`
    /// (ADR-0037). Same contract as [`Policy::redis_grants`].
    #[must_use]
    pub fn kafka_grants(&self, roles: &[String], resource: &str, user: &str) -> Vec<KafkaGrant> {
        self.rules_for(roles, resource)
            .filter_map(|rule| rule.kafka.as_ref())
            .filter(|g| g.users.iter().any(|u| u == user))
            .cloned()
            .collect()
    }

    /// The allow rules of `roles` whose selector matches `resource`.
    fn rules_for<'a>(
        &'a self,
        roles: &'a [String],
        resource: &str,
    ) -> impl Iterator<Item = &'a Rule> {
        let resource = self.resources.get(resource);
        roles
            .iter()
            .filter_map(|r| self.roles.get(r))
            .flat_map(|r| &r.spec.allow)
            .filter(move |rule| resource.is_some_and(|res| selector_matches(&rule.resources, res)))
    }

    /// Resources the roles grant at least one principal on, with those
    /// principals (minus any explicitly denied). Sorted by name.
    #[must_use]
    pub fn accessible(&self, roles: &[String]) -> Vec<AccessibleResource> {
        let roles: Vec<&RoleDoc> = roles.iter().filter_map(|r| self.roles.get(r)).collect();
        let mut out = Vec::new();
        for (name, resource) in &self.resources {
            let mut principals = BTreeSet::new();
            for rule in roles.iter().flat_map(|r| &r.spec.allow) {
                if selector_matches(&rule.resources, resource) {
                    principals.extend(rule_principals(rule, resource_kind(resource)));
                }
            }
            for rule in roles.iter().flat_map(|r| &r.spec.deny) {
                if selector_matches(&rule.resources, resource) {
                    if rule_has_no_principals(rule) {
                        principals.clear();
                    } else {
                        for p in rule_principals(rule, resource_kind(resource)) {
                            principals.remove(&p);
                        }
                    }
                }
            }
            if !principals.is_empty() {
                out.push(AccessibleResource {
                    name: name.clone(),
                    kind: resource_kind(resource),
                    labels: resource
                        .metadata
                        .labels
                        .iter()
                        .map(|(k, v)| (k.to_owned(), v.to_owned()))
                        .collect(),
                    principals: principals.into_iter().collect(),
                });
            }
        }
        out
    }
}

/// The resource's single kind. Validation guarantees there is exactly one.
fn resource_kind(resource: &ResourceDoc) -> ResourceKind {
    resource.spec.kinds()[0]
}

fn principal_fits_kind(principal: &Principal, kind: ResourceKind) -> bool {
    matches!(
        (principal, kind),
        (Principal::SshLogin(_), ResourceKind::Ssh)
            | (
                Principal::DbRole { .. },
                ResourceKind::Postgres | ResourceKind::Mysql | ResourceKind::Redshift
            )
            | (Principal::KubeGroup(_), ResourceKind::Kubernetes)
            | (Principal::RedisUser(_), ResourceKind::Redis)
            | (Principal::MongoRole { .. }, ResourceKind::Mongodb)
            | (
                Principal::SearchRole(_),
                ResourceKind::Opensearch | ResourceKind::Elasticsearch
            )
            | (Principal::MqUser(_), ResourceKind::Rabbitmq)
            | (Principal::KafkaUser(_), ResourceKind::Kafka)
            | (Principal::WebAccess, ResourceKind::Web)
            | (Principal::TcpAccess, ResourceKind::Tcp)
    )
}

fn selector_matches(selector: &Selector, resource: &ResourceDoc) -> bool {
    if !selector.kind.contains(&resource_kind(resource)) {
        return false;
    }
    if let Some(names) = &selector.names
        && !names.iter().any(|n| n == &resource.metadata.name)
    {
        return false;
    }
    labels_match(&selector.labels, &resource.metadata.labels)
}

fn labels_match(selector: &BTreeMap<String, Vec<String>>, labels: &Labels) -> bool {
    selector.iter().all(|(key, values)| {
        if key == "*" {
            return values.iter().any(|v| v == "*");
        }
        match labels.get(key) {
            Some(actual) => values.iter().any(|v| v == "*" || v == actual),
            None => false,
        }
    })
}

fn rule_has_no_principals(rule: &Rule) -> bool {
    rule.ssh.is_none()
        && rule.db.is_none()
        && rule.kube.is_none()
        && rule.redis.is_none()
        && rule.mongo.is_none()
        && rule.search.is_none()
        && rule.mq.is_none()
        && rule.kafka.is_none()
        && rule.web.is_none()
        && rule.tcp.is_none()
}

fn rule_grants(rule: &Rule, principal: &Principal) -> bool {
    match principal {
        Principal::SshLogin(login) => rule.ssh.as_ref().is_some_and(|g| g.logins.contains(login)),
        Principal::DbRole { role, database } => rule.db.as_ref().is_some_and(|g| {
            g.roles.contains(role) && g.databases.iter().any(|d| d == "*" || d == database)
        }),
        Principal::KubeGroup(group) => rule.kube.as_ref().is_some_and(|g| g.groups.contains(group)),
        Principal::RedisUser(user) => rule.redis.as_ref().is_some_and(|g| g.users.contains(user)),
        Principal::MongoRole { role, database } => rule.mongo.as_ref().is_some_and(|g| {
            g.roles.contains(role) && g.databases.iter().any(|d| d == "*" || d == database)
        }),
        Principal::SearchRole(engine_role) => rule
            .search
            .as_ref()
            .is_some_and(|g| g.roles.contains(engine_role)),
        Principal::MqUser(user) => rule.mq.as_ref().is_some_and(|g| g.users.contains(user)),
        Principal::KafkaUser(user) => rule.kafka.as_ref().is_some_and(|g| g.users.contains(user)),
        Principal::WebAccess => rule.web.is_some(),
        Principal::TcpAccess => rule.tcp.is_some(),
    }
}

fn rule_principals(rule: &Rule, kind: ResourceKind) -> Vec<String> {
    match kind {
        ResourceKind::Ssh => rule.ssh.iter().flat_map(|g| g.logins.clone()).collect(),
        ResourceKind::Postgres | ResourceKind::Mysql | ResourceKind::Redshift => {
            rule.db.iter().flat_map(|g| g.roles.clone()).collect()
        }
        ResourceKind::Kubernetes => rule.kube.iter().flat_map(|g| g.groups.clone()).collect(),
        ResourceKind::Redis => rule.redis.iter().flat_map(|g| g.users.clone()).collect(),
        ResourceKind::Mongodb => rule.mongo.iter().flat_map(|g| g.roles.clone()).collect(),
        ResourceKind::Opensearch | ResourceKind::Elasticsearch => {
            rule.search.iter().flat_map(|g| g.roles.clone()).collect()
        }
        ResourceKind::Rabbitmq => rule.mq.iter().flat_map(|g| g.users.clone()).collect(),
        ResourceKind::Kafka => rule.kafka.iter().flat_map(|g| g.users.clone()).collect(),
        ResourceKind::Web => rule.web.iter().map(|_| "access".to_owned()).collect(),
        ResourceKind::Tcp => rule.tcp.iter().map(|_| "access".to_owned()).collect(),
    }
}

fn validate_name(kind: &'static str, doc: &str, name: &str) -> Result<(), PolicyError> {
    let ok = !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
        });
    if ok {
        Ok(())
    } else {
        Err(invalid(
            kind,
            doc,
            format!("name {name:?} must be 1..={MAX_NAME_LEN} chars of [a-z0-9._-]"),
        ))
    }
}

fn validate_role(role: &RoleDoc) -> Result<(), PolicyError> {
    let name = &role.metadata.name;
    validate_name("role", name, name)?;
    if role.spec.allow.is_empty() && role.spec.deny.is_empty() {
        return Err(invalid(
            "role",
            name,
            "role must have at least one allow or deny rule",
        ));
    }
    for rule in role.spec.allow.iter().chain(&role.spec.deny) {
        validate_selector(name, &rule.resources)?;
        let principal_lists: [(&str, Option<&Vec<String>>); 10] = [
            ("ssh.logins", rule.ssh.as_ref().map(|g| &g.logins)),
            ("db.roles", rule.db.as_ref().map(|g| &g.roles)),
            ("db.databases", rule.db.as_ref().map(|g| &g.databases)),
            ("kube.groups", rule.kube.as_ref().map(|g| &g.groups)),
            ("redis.users", rule.redis.as_ref().map(|g| &g.users)),
            ("mongo.roles", rule.mongo.as_ref().map(|g| &g.roles)),
            ("mongo.databases", rule.mongo.as_ref().map(|g| &g.databases)),
            ("search.roles", rule.search.as_ref().map(|g| &g.roles)),
            ("mq.users", rule.mq.as_ref().map(|g| &g.users)),
            ("kafka.users", rule.kafka.as_ref().map(|g| &g.users)),
        ];
        for (field, values) in principal_lists {
            let Some(values) = values else { continue };
            if values.is_empty() {
                return Err(invalid("role", name, format!("{field} must not be empty")));
            }
            for v in values {
                let wildcard_ok = field == "db.databases" || field == "mongo.databases";
                if v.is_empty()
                    || v.len() > MAX_NAME_LEN
                    || v.chars().any(char::is_control)
                    || (v.contains('*') && !(wildcard_ok && v == "*"))
                {
                    return Err(invalid(
                        "role",
                        name,
                        format!("invalid value {v:?} in {field}"),
                    ));
                }
            }
        }
        if let Some(redis) = &rule.redis {
            for (field, values) in [
                ("redis.deny_commands", &redis.deny_commands),
                ("redis.allow_commands", &redis.allow_commands),
            ] {
                if let Some(v) = values.iter().find(|v| {
                    v.trim().is_empty() || v.len() > MAX_NAME_LEN || v.chars().any(char::is_control)
                }) {
                    return Err(invalid(
                        "role",
                        name,
                        format!("invalid value {v:?} in {field}"),
                    ));
                }
            }
            if let Some(k) = redis
                .keys
                .iter()
                .find(|k| k.is_empty() || k.len() > MAX_NAME_LEN || k.chars().any(char::is_control))
            {
                return Err(invalid(
                    "role",
                    name,
                    format!("invalid value {k:?} in redis.keys"),
                ));
            }
        }
        if let Some(mq) = &rule.mq {
            validate_patterns(name, "mq.vhosts", &mq.vhosts)?;
            validate_patterns(name, "mq.names", &mq.names)?;
        }
        if let Some(kafka) = &rule.kafka {
            validate_patterns(name, "kafka.topics", &kafka.topics)?;
            validate_patterns(name, "kafka.groups", &kafka.groups)?;
        }
        if let Some(db) = &rule.db {
            // The prefix is reserved: bootstrap never touches other roles, and
            // the name goes into SQL (ADR-0015, ADR-0033).
            if let Some(bad) = db.roles.iter().find(|r| !valid_db_role(r)) {
                return Err(invalid(
                    "role",
                    name,
                    format!(
                        "db.roles entry {bad:?} must be limen_ followed by lowercase letters, digits, or underscores"
                    ),
                ));
            }
        }
        if let Some(kube) = &rule.kube
            && kube.groups.iter().any(|g| g.starts_with("system:"))
        {
            return Err(invalid(
                "role",
                name,
                "kube.groups must not include system: groups",
            ));
        }
    }
    for rule in &role.spec.allow {
        if rule_has_no_principals(rule) {
            return Err(invalid(
                "role",
                name,
                "allow rules must grant at least one principal (ssh, db, kube, redis, mongo, search, mq, kafka, web, or tcp)",
            ));
        }
    }
    Ok(())
}

/// `limen_` plus 1 to 40 of `[a-z0-9_]`.
#[must_use]
pub fn valid_db_role(role: &str) -> bool {
    role.strip_prefix("limen_").is_some_and(|rest| {
        (1..=40).contains(&rest.len())
            && rest
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    })
}

fn validate_selector(role: &str, selector: &Selector) -> Result<(), PolicyError> {
    if selector.kind.is_empty() {
        return Err(invalid("role", role, "resources.kind must not be empty"));
    }
    for (key, values) in &selector.labels {
        if values.is_empty() {
            return Err(invalid(
                "role",
                role,
                format!("label selector {key:?} has no values"),
            ));
        }
        if key == "*" && values != &["*"] {
            return Err(invalid(
                "role",
                role,
                "label key \"*\" only accepts the value \"*\"",
            ));
        }
    }
    Ok(())
}

/// Name patterns in a grant: `*` is the only wildcard, and nothing may be
/// blank or hold control characters.
fn validate_patterns(role: &str, field: &str, values: &[String]) -> Result<(), PolicyError> {
    match values
        .iter()
        .find(|v| v.is_empty() || v.len() > MAX_NAME_LEN || v.chars().any(char::is_control))
    {
        Some(v) => Err(invalid(
            "role",
            role,
            format!("invalid value {v:?} in {field}"),
        )),
        None => Ok(()),
    }
}

fn validate_resource(resource: &ResourceDoc) -> Result<(), PolicyError> {
    let name = &resource.metadata.name;
    validate_name("resource", name, name)?;
    if resource
        .spec
        .worker_selector
        .get(limen_core::names::NAME_LABEL)
        .is_some()
    {
        return Err(invalid(
            "resource",
            name,
            format!(
                "worker_selector can't use {:?}: a component's name is for people, not for access decisions; select workers by the labels on their join token",
                limen_core::names::NAME_LABEL
            ),
        ));
    }
    let kinds = resource.spec.kinds();
    if kinds.len() != 1 {
        return Err(invalid(
            "resource",
            name,
            "exactly one of ssh, postgres, mysql, redshift, redis, kubernetes, mongodb, opensearch, elasticsearch, rabbitmq, kafka, web, or tcp must be set",
        ));
    }
    let address = match kinds[0] {
        ResourceKind::Ssh => resource.spec.ssh.as_ref().map(|t| t.address.as_str()),
        ResourceKind::Postgres => resource.spec.postgres.as_ref().map(|t| t.endpoint.as_str()),
        ResourceKind::Mysql => resource.spec.mysql.as_ref().map(|t| t.endpoint.as_str()),
        ResourceKind::Redis => resource.spec.redis.as_ref().map(|t| t.endpoint.as_str()),
        ResourceKind::Kubernetes => None,
        ResourceKind::Redshift => resource.spec.redshift.as_ref().map(|t| t.endpoint.as_str()),
        ResourceKind::Mongodb => resource.spec.mongodb.as_ref().map(|t| t.endpoint.as_str()),
        ResourceKind::Opensearch => resource
            .spec
            .opensearch
            .as_ref()
            .map(|t| t.endpoint.as_str()),
        ResourceKind::Elasticsearch => resource
            .spec
            .elasticsearch
            .as_ref()
            .map(|t| t.endpoint.as_str()),
        ResourceKind::Rabbitmq => resource.spec.rabbitmq.as_ref().map(|t| t.endpoint.as_str()),
        ResourceKind::Kafka => resource.spec.kafka.as_ref().map(|t| t.endpoint.as_str()),
        ResourceKind::Web => resource.spec.web.as_ref().map(|t| t.address.as_str()),
        ResourceKind::Tcp => resource.spec.tcp.as_ref().map(|t| t.address.as_str()),
    };
    if resource
        .spec
        .rabbitmq
        .as_ref()
        .is_some_and(|t| t.sasl.is_some())
    {
        return Err(invalid(
            "resource",
            name,
            "sasl applies to Kafka resources only; a RabbitMQ broker user logs in with a password",
        ));
    }
    let db_target = resource
        .spec
        .postgres
        .as_ref()
        .or(resource.spec.mysql.as_ref())
        .or(resource.spec.redshift.as_ref());
    if let Some(target) = db_target {
        for spec in &target.bootstrap {
            if !valid_db_role(&spec.role) {
                return Err(invalid(
                    "resource",
                    name,
                    format!(
                        "bootstrap role {:?} must be limen_ followed by lowercase letters, digits, or underscores",
                        spec.role
                    ),
                ));
            }
        }
        if !target.iam_auth
            && let Some(dir) = &target.password_dir
            && dir.is_empty()
        {
            return Err(invalid("resource", name, "password_dir must not be empty"));
        }
    }
    if let Some(address) = address {
        let valid = address.rsplit_once(':').is_some_and(|(host, port)| {
            !host.is_empty() && port.parse::<u16>().is_ok_and(|p| p != 0)
        });
        if !valid {
            return Err(invalid(
                "resource",
                name,
                format!("address {address:?} must be host:port"),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
