//! Policy: YAML roles, role mappings, and resources, with a deny-by-default
//! evaluator (ADR-0008).

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
            r.spec
                .worker_selector
                .iter()
                .all(|(k, v)| worker_labels.get(k).is_some_and(|actual| actual == v))
        })
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
                ResourceKind::Postgres | ResourceKind::Mysql
            )
            | (Principal::KubeGroup(_), ResourceKind::Kubernetes)
            | (Principal::RedisUser(_), ResourceKind::Redis)
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
    rule.ssh.is_none() && rule.db.is_none() && rule.kube.is_none() && rule.redis.is_none()
}

fn rule_grants(rule: &Rule, principal: &Principal) -> bool {
    match principal {
        Principal::SshLogin(login) => rule.ssh.as_ref().is_some_and(|g| g.logins.contains(login)),
        Principal::DbRole { role, database } => rule.db.as_ref().is_some_and(|g| {
            g.roles.contains(role) && g.databases.iter().any(|d| d == "*" || d == database)
        }),
        Principal::KubeGroup(group) => rule.kube.as_ref().is_some_and(|g| g.groups.contains(group)),
        Principal::RedisUser(user) => rule.redis.as_ref().is_some_and(|g| g.users.contains(user)),
    }
}

fn rule_principals(rule: &Rule, kind: ResourceKind) -> Vec<String> {
    match kind {
        ResourceKind::Ssh => rule.ssh.iter().flat_map(|g| g.logins.clone()).collect(),
        ResourceKind::Postgres | ResourceKind::Mysql => {
            rule.db.iter().flat_map(|g| g.roles.clone()).collect()
        }
        ResourceKind::Kubernetes => rule.kube.iter().flat_map(|g| g.groups.clone()).collect(),
        ResourceKind::Redis => rule.redis.iter().flat_map(|g| g.users.clone()).collect(),
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
        let principal_lists: [(&str, Option<&Vec<String>>); 5] = [
            ("ssh.logins", rule.ssh.as_ref().map(|g| &g.logins)),
            ("db.roles", rule.db.as_ref().map(|g| &g.roles)),
            ("db.databases", rule.db.as_ref().map(|g| &g.databases)),
            ("kube.groups", rule.kube.as_ref().map(|g| &g.groups)),
            ("redis.users", rule.redis.as_ref().map(|g| &g.users)),
        ];
        for (field, values) in principal_lists {
            let Some(values) = values else { continue };
            if values.is_empty() {
                return Err(invalid("role", name, format!("{field} must not be empty")));
            }
            for v in values {
                let wildcard_ok = field == "db.databases";
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
                "allow rules must grant at least one principal (ssh, db, kube, or redis)",
            ));
        }
    }
    Ok(())
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

fn validate_resource(resource: &ResourceDoc) -> Result<(), PolicyError> {
    let name = &resource.metadata.name;
    validate_name("resource", name, name)?;
    let kinds = resource.spec.kinds();
    if kinds.len() != 1 {
        return Err(invalid(
            "resource",
            name,
            "exactly one of ssh, postgres, mysql, redis, kubernetes must be set",
        ));
    }
    let address = match kinds[0] {
        ResourceKind::Ssh => resource.spec.ssh.as_ref().map(|t| t.address.as_str()),
        ResourceKind::Postgres => resource.spec.postgres.as_ref().map(|t| t.endpoint.as_str()),
        ResourceKind::Mysql => resource.spec.mysql.as_ref().map(|t| t.endpoint.as_str()),
        ResourceKind::Redis => resource.spec.redis.as_ref().map(|t| t.endpoint.as_str()),
        ResourceKind::Kubernetes => None,
    };
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
