//! Policy: YAML roles, role mappings, and resources, with a deny-by-default
//! evaluator (ADR-0008).

pub mod bot;
pub mod delegation;
pub mod discovery;
pub mod duration;
pub mod model;
pub mod testing;
pub mod tooling;
pub mod trace;

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use limen_core::identity::ADMIN_ROLE;
use limen_core::labels::Labels;
use limen_core::resource::ResourceKind;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use model::Document;
use model::WebGrant;
pub use model::{
    BrokerTarget, KafkaClass, KafkaGrant, KafkaSasl, MongoGrant, MqClass, MqGrant, RedisAudit,
    RedisGrant, RedisTarget,
};
use model::{ResourceDoc, RoleDoc, Rule, Selector};
pub use model::{SearchAudit, SearchClass, SearchGrant, SearchTarget};

/// Default lifetime of login credentials when no role sets `cert_ttl`.
/// The control plane's `--default-cert-ttl` overrides it per deployment.
pub const DEFAULT_CERT_TTL: Duration = Duration::from_hours(1);
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
    /// Nothing the user holds grants it, but a role they may request would
    /// (ADR-0025). Enforcement points must treat it as a denial: a request
    /// is a row, not a session.
    RequiresApproval {
        reason: String,
        /// The requestable roles that would grant it.
        #[serde(default)]
        roles: Vec<String>,
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

impl Principal {
    /// Parse `kind=value` (`login=ubuntu`, `db_role=limen_read`, `kube_group=…`,
    /// `redis_user=…`, `mongo_role=…`, `search_role=…`, `mq_user=…`,
    /// `kafka_user=…`) or `web` / `tcp`. `database` goes with the database
    /// kinds.
    pub fn parse(spec: &str, database: &str) -> Result<Self, String> {
        let (kind, value) = spec.split_once('=').unwrap_or((spec, ""));
        let need = |what: &str| {
            if value.is_empty() {
                Err(format!("{what} needs a value, as {what}=NAME"))
            } else {
                Ok(value.to_owned())
            }
        };
        Ok(match kind {
            "login" => Principal::SshLogin(need("login")?),
            "db_role" => Principal::DbRole {
                role: need("db_role")?,
                database: database.to_owned(),
            },
            "mongo_role" => Principal::MongoRole {
                role: need("mongo_role")?,
                database: database.to_owned(),
            },
            "kube_group" => Principal::KubeGroup(need("kube_group")?),
            "redis_user" => Principal::RedisUser(need("redis_user")?),
            "search_role" => Principal::SearchRole(need("search_role")?),
            "mq_user" => Principal::MqUser(need("mq_user")?),
            "kafka_user" => Principal::KafkaUser(need("kafka_user")?),
            "web" if value.is_empty() => Principal::WebAccess,
            "tcp" if value.is_empty() => Principal::TcpAccess,
            other => {
                return Err(format!(
                    "unknown principal {other:?}; use login=, db_role=, mongo_role=, kube_group=, redis_user=, search_role=, mq_user=, kafka_user=, web, or tcp"
                ));
            }
        })
    }
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

/// A resource a user could reach by asking for a role (ADR-0025).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestableResource {
    pub name: String,
    pub kind: ResourceKind,
    pub labels: BTreeMap<String, String>,
    /// The requestable roles that grant it.
    pub roles: Vec<String>,
}

/// A compiled, validated policy.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct Policy {
    roles: BTreeMap<String, RoleDoc>,
    /// IdP group → roles, merged across all `role_mapping` documents.
    group_roles: BTreeMap<String, BTreeSet<String>>,
    mapping_docs: BTreeMap<String, model::RoleMappingDoc>,
    resources: BTreeMap<String, ResourceDoc>,
    #[serde(default)]
    bots: BTreeMap<String, bot::BotDoc>,
    #[serde(default)]
    discovery: BTreeMap<String, discovery::DiscoveryDoc>,
    #[serde(default)]
    policy_tests: BTreeMap<String, testing::PolicyTestDoc>,
    #[serde(default)]
    profiles: BTreeMap<String, delegation::ResourceProfileDoc>,
    #[serde(default)]
    writers: BTreeMap<String, delegation::PolicyWriterDoc>,
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
                Document::Discovery(doc) => {
                    discovery::validate_discovery(&doc)?;
                    let name = doc.metadata.name.clone();
                    if policy.discovery.insert(name.clone(), doc).is_some() {
                        return Err(PolicyError::Duplicate {
                            kind: "discovery",
                            name,
                        });
                    }
                }
                Document::PolicyTest(doc) => {
                    testing::validate_test(&doc)?;
                    let name = doc.metadata.name.clone();
                    if policy.policy_tests.insert(name.clone(), doc).is_some() {
                        return Err(PolicyError::Duplicate {
                            kind: "policy_test",
                            name,
                        });
                    }
                }
                Document::ResourceProfile(doc) => {
                    delegation::validate_profile(&doc)?;
                    let name = doc.metadata.name.clone();
                    if policy.profiles.insert(name.clone(), doc).is_some() {
                        return Err(PolicyError::Duplicate {
                            kind: "resource_profile",
                            name,
                        });
                    }
                }
                Document::PolicyWriter(doc) => {
                    delegation::validate_writer(&doc)?;
                    let name = doc.metadata.name.clone();
                    if policy.writers.insert(name.clone(), doc).is_some() {
                        return Err(PolicyError::Duplicate {
                            kind: "policy_writer",
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
                    if !limen_core::identity::is_builtin_role(role)
                        && !policy.roles.contains_key(role)
                    {
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
        check_writer_references(&policy)?;
        let mut web_hosts = BTreeMap::new();
        for (name, resource) in &policy.resources {
            if let Some(web) = &resource.spec.web
                && let Some(previous) = web_hosts.insert(&web.host, name)
            {
                return Err(invalid(
                    "resource",
                    name,
                    format!(
                        "web.host {:?} is already assigned to resource {previous:?}",
                        web.host
                    ),
                ));
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
        out.extend(self.discovery.values().cloned().map(Document::Discovery));
        out.extend(
            self.policy_tests
                .values()
                .cloned()
                .map(Document::PolicyTest),
        );
        out.extend(
            self.profiles
                .values()
                .cloned()
                .map(Document::ResourceProfile),
        );
        out.extend(self.writers.values().cloned().map(Document::PolicyWriter));
        out
    }

    /// What proxies and workers receive: every document except the control
    /// plane's own (resource profiles and writer grants). Leaving them out
    /// also keeps snapshots readable by components from before Phase 14.
    #[must_use]
    pub fn snapshot_documents(&self) -> Vec<Document> {
        self.documents()
            .into_iter()
            .filter(|d| !matches!(d, Document::ResourceProfile(_) | Document::PolicyWriter(_)))
            .collect()
    }

    #[must_use]
    pub fn profile(&self, name: &str) -> Option<&delegation::ResourceProfileDoc> {
        self.profiles.get(name)
    }

    /// The writer grant of `bot`, if it has one.
    #[must_use]
    pub fn writer_for_bot(&self, bot: &str) -> Option<&delegation::PolicyWriterDoc> {
        self.writers.values().find(|w| w.spec.bot == bot)
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
    /// otherwise `default` (the deployment's, [`DEFAULT_CERT_TTL`] unless
    /// set), always capped at `max`.
    #[must_use]
    pub fn cert_ttl(&self, roles: &[String], default: Duration, max: Duration) -> Duration {
        roles
            .iter()
            .filter_map(|r| self.roles.get(r)?.spec.cert_ttl.map(|d| d.0))
            .min()
            .unwrap_or(default)
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
                && (rule_has_no_principals(rule)
                    || (!matches!(req.principal, Principal::WebAccess)
                        && rule_grants(rule, &req.principal)))
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

    /// [`Policy::evaluate`], plus: when nothing the user holds reaches the
    /// resource but a role in `eligible` (roles they may ask for) would, the
    /// answer is [`Decision::RequiresApproval`] naming those roles. A deny rule
    /// in a requestable role stops it being offered. Enforcement points call
    /// [`Policy::evaluate`]: this is for telling people what to do next.
    #[must_use]
    pub fn evaluate_eligible(&self, req: &AccessRequest<'_>, eligible: &[String]) -> Decision {
        let base = self.evaluate(req);
        if !matches!(
            base,
            Decision::Deny {
                reason: DenyReason::NoMatchingRole
            }
        ) || eligible.is_empty()
        {
            return base;
        }
        let mut union: Vec<String> = req.roles.to_vec();
        union.extend(eligible.iter().filter(|r| !req.roles.contains(r)).cloned());
        match self.evaluate(&AccessRequest {
            roles: &union,
            resource: req.resource,
            principal: req.principal.clone(),
        }) {
            Decision::Allow { matched_roles } => {
                let roles: Vec<String> = matched_roles
                    .into_iter()
                    .filter(|r| eligible.contains(r))
                    .collect();
                if roles.is_empty() {
                    base
                } else {
                    Decision::RequiresApproval {
                        reason: format!("request one of: {}", roles.join(", ")),
                        roles,
                    }
                }
            }
            _ => base,
        }
    }

    #[must_use]
    pub fn role(&self, name: &str) -> Option<&RoleDoc> {
        self.roles.get(name)
    }

    /// Every role, in name order.
    pub fn roles(&self) -> impl Iterator<Item = &RoleDoc> {
        self.roles.values()
    }

    /// Roles that people can ask for, in name order.
    pub fn requestable_roles(&self) -> impl Iterator<Item = &RoleDoc> {
        self.roles.values().filter(|r| r.spec.request.is_some())
    }

    /// The requestable roles a member of any of `groups` may ask for.
    #[must_use]
    pub fn requestable_roles_for_groups<'a>(
        &self,
        groups: impl IntoIterator<Item = &'a str>,
    ) -> BTreeSet<String> {
        let groups: BTreeSet<&str> = groups.into_iter().collect();
        self.requestable_roles()
            .filter(|r| {
                r.spec
                    .request
                    .as_ref()
                    .is_some_and(|q| q.who.iter().any(|g| groups.contains(g.as_str())))
            })
            .map(|r| r.metadata.name.clone())
            .collect()
    }

    /// Whether the person takes part in access requests at all: they may ask
    /// for a role, or approve requests for one. Such people can sign in even
    /// when no role is mapped to their groups (ADR-0025).
    #[must_use]
    pub fn takes_part_in_requests<'a>(
        &self,
        username: &str,
        groups: impl IntoIterator<Item = &'a str>,
    ) -> bool {
        let groups: BTreeSet<&str> = groups.into_iter().collect();
        self.requestable_roles().any(|role| {
            role.spec.request.as_ref().is_some_and(|q| {
                q.who
                    .iter()
                    .chain(&q.approvers)
                    .any(|g| groups.contains(g.as_str()))
                    || q.approver_users.iter().any(|u| u == username)
            })
        })
    }

    /// Whether `username`, a member of `groups`, may approve requests for
    /// `role`. Checked again at approval time, never cached from the request.
    /// A break-glass role has no approvers, so nobody can.
    #[must_use]
    pub fn may_approve<'a>(
        &self,
        role: &str,
        username: &str,
        groups: impl IntoIterator<Item = &'a str>,
    ) -> bool {
        let Some(request) = self.roles.get(role).and_then(|r| r.spec.request.as_ref()) else {
            return false;
        };
        request.approver_users.iter().any(|u| u == username)
            || groups
                .into_iter()
                .any(|g| request.approvers.iter().any(|a| a == g))
    }

    /// The resources a user could get by asking, with the roles that would
    /// give them. A hint for `limen ls`: names and kinds, never an address.
    /// Resources the user already reaches are left out.
    #[must_use]
    pub fn requestable_resources(
        &self,
        held: &[String],
        eligible: &[String],
    ) -> Vec<RequestableResource> {
        let already: BTreeSet<String> = self.accessible(held).into_iter().map(|r| r.name).collect();
        let mut out: BTreeMap<String, RequestableResource> = BTreeMap::new();
        for role in eligible.iter().filter(|r| !held.contains(r)) {
            for res in self.accessible(std::slice::from_ref(role)) {
                if already.contains(&res.name) {
                    continue;
                }
                let entry = out
                    .entry(res.name.clone())
                    .or_insert_with(|| RequestableResource {
                        name: res.name.clone(),
                        kind: res.kind,
                        labels: res.labels.clone(),
                        roles: Vec::new(),
                    });
                entry.roles.push(role.clone());
            }
        }
        out.into_values().collect()
    }

    /// This policy plus accepted discovered resources (ADR-0027). Discovered
    /// resources look like static ones to roles, which select them by labels
    /// as before. A name already taken by a static resource is never
    /// replaced, and a resource that fails validation is skipped; both come
    /// back in the second value so the caller can say so.
    #[must_use]
    pub fn with_discovered(
        &self,
        discovered: impl IntoIterator<Item = ResourceDoc>,
    ) -> (Policy, Vec<(String, String)>) {
        let mut out = self.clone();
        let mut skipped = Vec::new();
        for resource in discovered {
            let name = resource.metadata.name.clone();
            if out.resources.contains_key(&name) {
                skipped.push((name, "a resource with that name already exists".to_owned()));
                continue;
            }
            if let Err(e) = validate_resource(&resource) {
                skipped.push((name, e.to_string()));
                continue;
            }
            if let Some(web) = &resource.spec.web
                && out
                    .resources
                    .values()
                    .any(|r| r.spec.web.as_ref().is_some_and(|w| w.host == web.host))
            {
                skipped.push((name, "web host already in use".to_owned()));
                continue;
            }
            out.resources.insert(name, resource);
        }
        (out, skipped)
    }

    /// Every discovery document, in name order.
    pub fn discovery(&self) -> impl Iterator<Item = &discovery::DiscoveryDoc> {
        self.discovery.values()
    }

    /// Every `policy_test` document, in name order.
    pub fn policy_tests(&self) -> impl Iterator<Item = &testing::PolicyTestDoc> {
        self.policy_tests.values()
    }

    /// Things that are valid but probably not what was meant. `apply` shows
    /// them and the console lists them; they never block a policy.
    #[must_use]
    pub fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        for role in self.roles.values() {
            let name = &role.metadata.name;
            if let Some(request) = &role.spec.request {
                if let Some(g) = request.who.iter().find(|g| request.approvers.contains(g)) {
                    out.push(format!(
                        "role {name}: group {g:?} may both request and approve; the requester can never approve their own request, but a group that can do both approves its own members' requests"
                    ));
                }
                let standing = self
                    .group_roles
                    .iter()
                    .any(|(g, roles)| roles.contains(name) && request.who.contains(g));
                if standing {
                    out.push(format!(
                        "role {name}: a group in request.who already holds it through a role mapping, so there is nothing to request"
                    ));
                }
            }
        }
        // A tag anyone with write access to the account can set must not be
        // what lets a resource into a role (ADR-0027).
        let tag_labels: BTreeSet<String> = self
            .discovery
            .values()
            .flat_map(|d| &d.spec.matchers)
            .flat_map(|m| m.labels_from_tags.iter().map(|t| t.to_lowercase()))
            .collect();
        if !tag_labels.is_empty() {
            for role in self.roles.values() {
                for rule in role.spec.allow.iter().chain(&role.spec.deny) {
                    for key in rule.resources.labels.keys() {
                        if tag_labels.contains(key) {
                            out.push(format!(
                                "role {}: selects on label {key:?}, which discovery copies from a cloud tag; anyone who can write that tag can steer a resource into this role (new resources and changed labels wait for an admin to accept them)",
                                role.metadata.name
                            ));
                        }
                    }
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// Whether a web request is allowed after the resource-level grant. Path
    /// prefixes match path segments, not arbitrary string fragments.
    #[must_use]
    pub fn web_request_allowed(
        &self,
        roles: &[String],
        resource_name: &str,
        method: &str,
        path: &str,
    ) -> bool {
        let Some(resource) = self.resources.get(resource_name) else {
            return false;
        };
        if resource_kind(resource) != ResourceKind::Web {
            return false;
        }
        let roles: Vec<&RoleDoc> = roles.iter().filter_map(|r| self.roles.get(r)).collect();
        let matches_request = |grant: &WebGrant| {
            (grant.methods.is_empty() || grant.methods.iter().any(|m| m == method))
                && (grant.path_prefixes.is_empty()
                    || grant.path_prefixes.iter().any(|prefix| {
                        path == prefix
                            || prefix == "/"
                            || path
                                .strip_prefix(prefix)
                                .is_some_and(|suffix| suffix.starts_with('/'))
                    }))
        };
        let denied = roles.iter().flat_map(|r| &r.spec.deny).any(|rule| {
            selector_matches(&rule.resources, resource)
                && (rule_has_no_principals(rule) || rule.web.as_ref().is_some_and(matches_request))
        });
        if denied {
            return false;
        }
        roles.iter().flat_map(|r| &r.spec.allow).any(|rule| {
            selector_matches(&rule.resources, resource)
                && rule.web.as_ref().is_some_and(matches_request)
        })
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

    /// The MongoDB grants that let `roles` act as `role` on `resource`. Call it
    /// only after [`Policy::evaluate`] allowed the request, since deny rules
    /// aren't checked here (ADR-0035).
    #[must_use]
    pub fn mongo_grants(&self, roles: &[String], resource: &str, role: &str) -> Vec<MongoGrant> {
        let Some(resource) = self.resources.get(resource) else {
            return Vec::new();
        };
        roles
            .iter()
            .filter_map(|r| self.roles.get(r))
            .flat_map(|r| &r.spec.allow)
            .filter(|rule| selector_matches(&rule.resources, resource))
            .filter_map(|rule| rule.mongo.as_ref())
            .filter(|g| g.roles.iter().any(|r| r == role))
            .cloned()
            .collect()
    }

    /// The search grants that let `roles` act as `engine_role` on `resource`.
    /// A session may do whatever any one of them permits (ADR-0036). Call it
    /// only after [`Policy::evaluate`] allowed the request, since deny rules
    /// aren't checked here.
    #[must_use]
    pub fn search_grants(
        &self,
        roles: &[String],
        resource: &str,
        engine_role: &str,
    ) -> Vec<SearchGrant> {
        let Some(resource) = self.resources.get(resource) else {
            return Vec::new();
        };
        roles
            .iter()
            .filter_map(|r| self.roles.get(r))
            .flat_map(|r| &r.spec.allow)
            .filter(|rule| selector_matches(&rule.resources, resource))
            .filter_map(|rule| rule.search.as_ref())
            .filter(|g| g.roles.iter().any(|r| r == engine_role))
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
            let principals = granted_principals(&roles, resource);
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

    /// The Kubernetes groups the roles let a user assume on the cluster
    /// resource `name`, minus any explicitly denied. Empty if the resource is
    /// unknown or not a cluster.
    #[must_use]
    pub fn kube_groups(&self, roles: &[String], name: &str) -> Vec<String> {
        let Some(resource) = self.resources.get(name) else {
            return Vec::new();
        };
        if resource_kind(resource) != ResourceKind::Kubernetes {
            return Vec::new();
        }
        let roles: Vec<&RoleDoc> = roles.iter().filter_map(|r| self.roles.get(r)).collect();
        granted_principals(&roles, resource).into_iter().collect()
    }
}

/// What `roles` grant on one resource: every allowed principal, less the ones
/// a deny rule names (or all of them, for a deny rule that names none).
fn granted_principals(roles: &[&RoleDoc], resource: &ResourceDoc) -> BTreeSet<String> {
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
    principals
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

/// An index name pattern as the engines spell index names, plus `*`. No
/// commas, colons, slashes, or a leading `-` or `+` (those are engine-side
/// expression syntax that policy doesn't accept).
fn valid_index_pattern(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= MAX_NAME_LEN
        && !p.starts_with(['-', '+', '_'])
        && p.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-' | b'*')
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

/// A writer grant names a real bot (one grant per bot) and real profiles.
fn check_writer_references(policy: &Policy) -> Result<(), PolicyError> {
    let mut writer_bots = BTreeMap::new();
    for (name, writer) in &policy.writers {
        let bot = &writer.spec.bot;
        if !policy.bots.contains_key(bot) {
            return Err(invalid(
                "policy_writer",
                name,
                format!("unknown bot {bot:?}"),
            ));
        }
        if let Some(previous) = writer_bots.insert(bot, name) {
            return Err(invalid(
                "policy_writer",
                name,
                format!("bot {bot:?} already has the grant {previous:?}; one grant per bot"),
            ));
        }
        for profile in &writer.spec.profiles {
            if !policy.profiles.contains_key(profile) {
                return Err(invalid(
                    "policy_writer",
                    name,
                    format!("unknown resource_profile {profile:?}"),
                ));
            }
        }
    }
    Ok(())
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
    if !role_has_rules(role) {
        return Err(invalid(
            "role",
            name,
            "role must have at least one allow or deny rule",
        ));
    }
    for rule in role.spec.allow.iter().chain(&role.spec.deny) {
        validate_selector(name, &rule.resources)?;
        if let Some(web) = &rule.web {
            validate_web_grant(name, web)?;
        }
        validate_principal_values(name, rule)?;
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
        validate_broker_grants(name, rule)?;
        if let Some(search) = &rule.search
            && let Some(bad) = search.indices.iter().find(|p| !valid_index_pattern(p))
        {
            return Err(invalid(
                "role",
                name,
                format!(
                    "search.indices entry {bad:?} must be lowercase letters, digits, and . _ - or *"
                ),
            ));
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
        if let Some(mongo) = &rule.mongo {
            if let Some(bad) = mongo.roles.iter().find(|r| !valid_mongo_role(r)) {
                return Err(invalid(
                    "role",
                    name,
                    format!(
                        "mongo.roles entry {bad:?} must be 1 to 64 letters, digits, '_', '.', or '-'"
                    ),
                ));
            }
            if let Some(bad) = mongo
                .databases
                .iter()
                .find(|d| *d != "*" && !valid_mongo_database(d))
            {
                return Err(invalid(
                    "role",
                    name,
                    format!(
                        "mongo.databases entry {bad:?} is not a MongoDB database name (or '*')"
                    ),
                ));
            }
            if let Some(bad) = mongo.deny_commands.iter().find(|c| {
                c.is_empty()
                    || c.len() > 64
                    || !c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            }) {
                return Err(invalid(
                    "role",
                    name,
                    format!("invalid value {bad:?} in mongo.deny_commands"),
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
    match (&role.spec.request, role.spec.break_glass) {
        (Some(request), break_glass) => validate_request(name, request, break_glass)?,
        (None, true) => {
            return Err(invalid(
                "role",
                name,
                "break_glass needs request.who: the groups that may use it",
            ));
        }
        (None, false) => {}
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

fn validate_request(
    role: &str,
    request: &model::RequestSpec,
    break_glass: bool,
) -> Result<(), PolicyError> {
    let bad_name = |v: &String| v.is_empty() || v.len() > 256 || v.chars().any(char::is_control);
    if request.who.is_empty() {
        return Err(invalid("role", role, "request.who must not be empty"));
    }
    for (field, values) in [
        ("request.who", &request.who),
        ("request.approvers", &request.approvers),
        ("request.approver_users", &request.approver_users),
    ] {
        if let Some(v) = values.iter().find(|v| bad_name(v)) {
            return Err(invalid(
                "role",
                role,
                format!("invalid value {v:?} in {field}"),
            ));
        }
    }
    if !(1..=5).contains(&request.approvals_required) {
        return Err(invalid(
            "role",
            role,
            "request.approvals_required must be 1 to 5",
        ));
    }
    if let Some(d) = request.max_duration
        && d.0 > model::MAX_REQUEST_DURATION
    {
        return Err(invalid("role", role, "request.max_duration is at most 7d"));
    }
    if break_glass {
        if !request.approvers.is_empty() || !request.approver_users.is_empty() {
            return Err(invalid(
                "role",
                role,
                "a break_glass role is granted at once: remove request.approvers",
            ));
        }
        if request.approvals_required != 1 {
            return Err(invalid(
                "role",
                role,
                "a break_glass role takes no approvals: remove request.approvals_required",
            ));
        }
        if !request.require_reason {
            return Err(invalid(
                "role",
                role,
                "break_glass always needs a reason: remove request.require_reason: false",
            ));
        }
        if let Some(d) = request.max_duration
            && d.0 > model::MAX_BREAK_GLASS_DURATION
        {
            return Err(invalid(
                "role",
                role,
                "request.max_duration is at most 1h for break_glass",
            ));
        }
    } else if request.approvers.is_empty() && request.approver_users.is_empty() {
        return Err(invalid(
            "role",
            role,
            "a requestable role needs request.approvers or request.approver_users",
        ));
    }
    if let Some(pattern) = &request.ticket_pattern {
        if !request.require_reason {
            return Err(invalid(
                "role",
                role,
                "request.ticket_pattern needs request.require_reason",
            ));
        }
        if pattern.len() > 256 {
            return Err(invalid(
                "role",
                role,
                "request.ticket_pattern is at most 256 chars",
            ));
        }
        compile_ticket_pattern(pattern).map_err(|e| {
            invalid(
                "role",
                role,
                format!("request.ticket_pattern is not a valid expression: {e}"),
            )
        })?;
    }
    Ok(())
}

/// The ticket expression, compiled with a bounded size. `regex-lite` matches
/// in linear time, so a hostile reason can't make it spin.
pub fn compile_ticket_pattern(pattern: &str) -> Result<regex_lite::Regex, regex_lite::Error> {
    regex_lite::RegexBuilder::new(pattern)
        .size_limit(100_000)
        .nest_limit(20)
        .build()
}

fn role_has_rules(role: &RoleDoc) -> bool {
    !role.spec.allow.is_empty() || !role.spec.deny.is_empty()
}

fn validate_principal_values(role_name: &str, rule: &Rule) -> Result<(), PolicyError> {
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
            return Err(invalid(
                "role",
                role_name,
                format!("{field} must not be empty"),
            ));
        }
        for value in values {
            let wildcard_ok = field == "db.databases" || field == "mongo.databases";
            if value.is_empty()
                || value.len() > MAX_NAME_LEN
                || value.chars().any(char::is_control)
                || (value.contains('*') && !(wildcard_ok && value == "*"))
            {
                return Err(invalid(
                    "role",
                    role_name,
                    format!("invalid value {value:?} in {field}"),
                ));
            }
        }
    }
    Ok(())
}

fn validate_web_grant(role_name: &str, web: &WebGrant) -> Result<(), PolicyError> {
    if let Some(method) = web.methods.iter().find(|method| {
        method.is_empty()
            || method.len() > 32
            || !method.bytes().all(|b| b.is_ascii_uppercase() || b == b'-')
    }) {
        return Err(invalid(
            "role",
            role_name,
            format!("web method {method:?} must be an uppercase HTTP method"),
        ));
    }
    if let Some(path) = web.path_prefixes.iter().find(|path| !valid_web_path(path)) {
        return Err(invalid(
            "role",
            role_name,
            format!("web path prefix {path:?} is not a normalized absolute path"),
        ));
    }
    Ok(())
}

fn valid_web_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 1024
        && path.starts_with('/')
        && !path.contains("//")
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.' | b'~'))
        && path
            .split('/')
            .all(|segment| segment != "." && segment != "..")
}

fn valid_dns_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
        })
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

/// A MongoDB role name: 1 to 64 of `[A-Za-z0-9_.-]`, not starting with a dot.
/// It names a file in `credentials_dir`, so nothing that could climb out of it.
#[must_use]
pub fn valid_mongo_role(role: &str) -> bool {
    (1..=64).contains(&role.len())
        && !role.starts_with('.')
        && role
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// A MongoDB database name as the server accepts it: 1 to 63 bytes, none of
/// `/\. "$*<>:|?` or NUL.
#[must_use]
pub fn valid_mongo_database(name: &str) -> bool {
    (1..=63).contains(&name.len())
        && !name.bytes().any(|b| {
            b == 0
                || b.is_ascii_control()
                || matches!(
                    b,
                    b'/' | b'\\'
                        | b'.'
                        | b' '
                        | b'"'
                        | b'$'
                        | b'*'
                        | b'<'
                        | b'>'
                        | b':'
                        | b'|'
                        | b'?'
                )
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

/// The patterns in a rule's `mq` and `kafka` grants (ADR-0037).
fn validate_broker_grants(owner: &str, rule: &Rule) -> Result<(), PolicyError> {
    if let Some(mq) = &rule.mq {
        validate_patterns(owner, "mq.vhosts", &mq.vhosts)?;
        validate_patterns(owner, "mq.names", &mq.names)?;
    }
    if let Some(kafka) = &rule.kafka {
        validate_patterns(owner, "kafka.topics", &kafka.topics)?;
        validate_patterns(owner, "kafka.groups", &kafka.groups)?;
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

fn validate_mongo_target(name: &str, t: &model::MongoTarget) -> Result<(), PolicyError> {
    use model::{MongoAuth, MongoFlavor};
    let bad = |why: &str| Err(invalid("resource", name, why.to_owned()));
    if let Some(db) = &t.default_database
        && !valid_mongo_database(db)
    {
        return bad("default_database is not a MongoDB database name");
    }
    if let Some(source) = &t.auth_source
        && source != "$external"
        && !valid_mongo_database(source)
    {
        return bad("auth_source must be a database name or $external");
    }
    if t.insecure_dev && t.flavor != MongoFlavor::Standard {
        return bad("insecure_dev is only for standard servers: Atlas and DocumentDB require TLS");
    }
    if t.auth == MongoAuth::X509 && t.flavor == MongoFlavor::Documentdb {
        return bad("DocumentDB doesn't support X.509 login; use scram, scram_sha1, or aws");
    }
    if t.auth == MongoAuth::Aws && t.flavor == MongoFlavor::Standard {
        return bad("auth: aws is for Atlas and DocumentDB (MONGODB-AWS)");
    }
    if t.auth != MongoAuth::Aws && t.credentials_dir.as_deref().is_none_or(str::is_empty) {
        return bad(
            "credentials_dir is required: the worker needs a password or certificate per role",
        );
    }
    if t.auth == MongoAuth::Aws && t.auth_source.as_deref().is_some_and(|s| s != "$external") {
        return bad("auth: aws logs in against $external");
    }
    Ok(())
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
    if let Some(web) = &resource.spec.web {
        if !valid_dns_host(&web.host) || web.host != web.host.to_ascii_lowercase() {
            return Err(invalid(
                "resource",
                name,
                format!("web.host {:?} must be a lowercase DNS host name", web.host),
            ));
        }
        if !web.insecure_dev && web.tls_ca_file.as_deref().is_none_or(str::is_empty) {
            return Err(invalid(
                "resource",
                name,
                "web.tls_ca_file is required for verified HTTPS upstreams",
            ));
        }
        if web.insecure_dev && web.tls_ca_file.is_some() {
            return Err(invalid(
                "resource",
                name,
                "web.tls_ca_file cannot be set when insecure_dev is enabled",
            ));
        }
        if web
            .tls_server_name
            .as_deref()
            .is_some_and(|host| !valid_dns_host(host))
        {
            return Err(invalid(
                "resource",
                name,
                "web.tls_server_name must be a DNS host name",
            ));
        }
        if web
            .health_path
            .as_deref()
            .is_some_and(|path| !valid_web_path(path))
        {
            return Err(invalid(
                "resource",
                name,
                "web.health_path must be a normalized absolute path",
            ));
        }
    }
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
    if let Some(target) = &resource.spec.mongodb {
        validate_mongo_target(name, target)?;
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
#[cfg(test)]
mod workflow_tests;
