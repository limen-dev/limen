//! A decision with its reasons (ADR-0028). Enforcement uses the lean
//! [`Policy::evaluate`]; this walks the same rules and keeps what it saw. A
//! test feeds both the same random requests and requires the same decision.

use std::collections::BTreeMap;

use limen_core::resource::ResourceKind;
use serde::{Deserialize, Serialize};

use crate::model::{ResourceDoc, RoleDoc, Rule, Selector};
use crate::{
    AccessRequest, Decision, DenyReason, Policy, Principal, labels_match, principal_fits_kind,
    resource_kind, rule_grants, rule_has_no_principals, rule_principals, selector_matches,
};

/// What a resource looked like to the decision. Admin-only: showing it to a
/// user would tell them a hidden resource exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceFacts {
    pub name: String,
    pub kind: ResourceKind,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Standing {
    /// The user has the role (from a group or an active grant).
    Held,
    /// The user could ask for the role (ADR-0025).
    Eligible,
}

/// One rule and what happened to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleNote {
    /// Position in the role's `allow` or `deny` list.
    pub rule: usize,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleTrace {
    pub role: String,
    pub standing: Standing,
    /// False when the role isn't in the policy (it grants nothing).
    pub known: bool,
    pub denied_by: Vec<RuleNote>,
    pub allowed_by: Vec<RuleNote>,
    /// Allow rules that didn't apply, and why.
    pub misses: Vec<RuleNote>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Trace {
    pub resource: Option<ResourceFacts>,
    pub decision: Decision,
    pub roles: Vec<RoleTrace>,
}

impl Policy {
    /// [`Policy::evaluate_eligible`] with the reasons.
    #[must_use]
    pub fn trace(&self, req: &AccessRequest<'_>, eligible: &[String]) -> Trace {
        let Some(resource) = self.resources.get(req.resource) else {
            return Trace {
                resource: None,
                decision: Decision::Deny {
                    reason: DenyReason::UnknownResource,
                },
                roles: Vec::new(),
            };
        };
        let kind = resource_kind(resource);
        let facts = Some(ResourceFacts {
            name: resource.metadata.name.clone(),
            kind,
            labels: resource
                .metadata
                .labels
                .iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
        });
        if !principal_fits_kind(&req.principal, kind) {
            return Trace {
                resource: facts,
                decision: Decision::Deny {
                    reason: DenyReason::InvalidRequest,
                },
                roles: Vec::new(),
            };
        }
        let mut roles: Vec<RoleTrace> = req
            .roles
            .iter()
            .map(|name| self.trace_role(name, Standing::Held, resource, &req.principal))
            .collect();
        let decision = if roles.iter().any(|r| !r.denied_by.is_empty()) {
            Decision::Deny {
                reason: DenyReason::ExplicitDeny,
            }
        } else {
            let matched: Vec<String> = roles
                .iter()
                .filter(|r| !r.allowed_by.is_empty())
                .map(|r| r.role.clone())
                .collect();
            if matched.is_empty() {
                Decision::Deny {
                    reason: DenyReason::NoMatchingRole,
                }
            } else {
                Decision::Allow {
                    matched_roles: matched,
                }
            }
        };
        if !matches!(
            decision,
            Decision::Deny {
                reason: DenyReason::NoMatchingRole
            }
        ) || eligible.is_empty()
        {
            return Trace {
                resource: facts,
                decision,
                roles,
            };
        }
        // Nothing held reaches it. Would a role the user could ask for?
        let eligible_traces: Vec<RoleTrace> = eligible
            .iter()
            .filter(|name| !req.roles.contains(name))
            .map(|name| self.trace_role(name, Standing::Eligible, resource, &req.principal))
            .collect();
        let any_deny = roles
            .iter()
            .chain(&eligible_traces)
            .any(|r| !r.denied_by.is_empty());
        let wanted: Vec<String> = eligible_traces
            .iter()
            .filter(|r| !r.allowed_by.is_empty())
            .map(|r| r.role.clone())
            .collect();
        roles.extend(eligible_traces);
        let decision = if any_deny || wanted.is_empty() {
            decision
        } else {
            Decision::RequiresApproval {
                reason: format!("request one of: {}", wanted.join(", ")),
                roles: wanted,
            }
        };
        Trace {
            resource: facts,
            decision,
            roles,
        }
    }

    fn trace_role(
        &self,
        name: &str,
        standing: Standing,
        resource: &ResourceDoc,
        principal: &Principal,
    ) -> RoleTrace {
        let Some(role) = self.roles.get(name) else {
            return RoleTrace {
                role: name.to_owned(),
                standing,
                known: false,
                denied_by: Vec::new(),
                allowed_by: Vec::new(),
                misses: Vec::new(),
            };
        };
        let mut out = RoleTrace {
            role: name.to_owned(),
            standing,
            known: true,
            denied_by: Vec::new(),
            allowed_by: Vec::new(),
            misses: Vec::new(),
        };
        for (i, rule) in role.spec.deny.iter().enumerate() {
            if selector_matches(&rule.resources, resource)
                && (rule_has_no_principals(rule)
                    || (!matches!(principal, Principal::WebAccess) && rule_grants(rule, principal)))
            {
                out.denied_by.push(RuleNote {
                    rule: i,
                    text: if rule_has_no_principals(rule) {
                        "denies the resource entirely".to_owned()
                    } else {
                        format!("denies {}", describe_principal(principal))
                    },
                });
            }
        }
        for (i, rule) in role.spec.allow.iter().enumerate() {
            if selector_matches(&rule.resources, resource) && rule_grants(rule, principal) {
                out.allowed_by.push(RuleNote {
                    rule: i,
                    text: format!("allows {}", describe_principal(principal)),
                });
            } else {
                out.misses.push(RuleNote {
                    rule: i,
                    text: miss_reason(rule, resource, Some(principal)),
                });
            }
        }
        out
    }
}

impl Policy {
    /// An admin's view of a resource when no principal is named: for each
    /// role, which rules reach it, what they offer, and why the others don't.
    #[must_use]
    pub fn explain_resource(
        &self,
        held: &[String],
        eligible: &[String],
        resource: &str,
    ) -> Vec<String> {
        let Some(res) = self.resources.get(resource) else {
            return vec!["The resource does not exist.".to_owned()];
        };
        let kind = resource_kind(res);
        let labels: Vec<String> = res
            .metadata
            .labels
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        let mut lines = vec![format!(
            "{resource} is a {} resource ({}).",
            kind.as_str(),
            if labels.is_empty() {
                "no labels".to_owned()
            } else {
                labels.join(", ")
            }
        )];
        let reachable = self
            .accessible(held)
            .into_iter()
            .find(|r| r.name == resource);
        lines.push(match &reachable {
            Some(r) => format!("Reachable now as: {}.", r.principals.join(", ")),
            None => "Not reachable with the roles held.".to_owned(),
        });
        let mut roles: Vec<(&str, &str)> = held.iter().map(|r| (r.as_str(), "held")).collect();
        roles.extend(
            eligible
                .iter()
                .filter(|r| !held.contains(r))
                .map(|r| (r.as_str(), "requestable")),
        );
        for (name, how) in roles {
            let Some(role) = self.roles.get(name) else {
                lines.push(format!("  role {name} ({how}): not in the policy"));
                continue;
            };
            for (i, rule) in role.spec.deny.iter().enumerate() {
                if selector_matches(&rule.resources, res) {
                    let what = if rule_has_no_principals(rule) {
                        "denies the resource entirely".to_owned()
                    } else {
                        format!("denies {}", rule_principals(rule, kind).join(", "))
                    };
                    lines.push(format!("  role {name} ({how}): deny rule {} {what}", i + 1));
                }
            }
            for (i, rule) in role.spec.allow.iter().enumerate() {
                let text = if selector_matches(&rule.resources, res) {
                    format!("allows {}", rule_principals(rule, kind).join(", "))
                } else {
                    miss_reason(rule, res, None)
                };
                lines.push(format!(
                    "  role {name} ({how}): allow rule {} {text}",
                    i + 1
                ));
            }
        }
        lines
    }
}

/// Why an allow rule didn't apply, first reason only.
fn miss_reason(rule: &Rule, resource: &ResourceDoc, principal: Option<&Principal>) -> String {
    let kind = resource_kind(resource);
    let sel = &rule.resources;
    if !sel.kind.contains(&kind) {
        return format!("covers {}, the resource is {}", kinds(sel), kind.as_str());
    }
    if let Some(names) = &sel.names
        && !names.iter().any(|n| n == &resource.metadata.name)
    {
        return format!("covers only {}", names.join(", "));
    }
    if !labels_match(&sel.labels, &resource.metadata.labels) {
        for (key, values) in &sel.labels {
            if !labels_match(
                &BTreeMap::from([(key.clone(), values.clone())]),
                &resource.metadata.labels,
            ) {
                return match resource.metadata.labels.get(key) {
                    Some(actual) => format!(
                        "needs {key} in [{}], the resource has {key}={actual}",
                        values.join(", ")
                    ),
                    None => format!("needs label {key}, the resource has none"),
                };
            }
        }
    }
    let offered = rule_principals(rule, kind);
    match (offered.is_empty(), principal) {
        (true, _) => format!("grants no {} access", kind.as_str()),
        (false, Some(p)) => format!(
            "grants {}, not {}",
            offered.join(", "),
            describe_principal(p)
        ),
        (false, None) => format!("grants {}", offered.join(", ")),
    }
}

fn kinds(selector: &Selector) -> String {
    selector
        .kind
        .iter()
        .map(|k| k.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

#[must_use]
pub fn describe_principal(p: &Principal) -> String {
    match p {
        Principal::SshLogin(l) => format!("login {l}"),
        Principal::DbRole { role, database } => format!("database role {role} on {database}"),
        Principal::KubeGroup(g) => format!("group {g}"),
        Principal::RedisUser(u) => format!("redis user {u}"),
        Principal::MongoRole { role, database } => format!("mongo role {role} on {database}"),
        Principal::SearchRole(r) => format!("search role {r}"),
        Principal::MqUser(u) => format!("RabbitMQ user {u}"),
        Principal::KafkaUser(u) => format!("Kafka user {u}"),
        Principal::WebAccess => "web access".to_owned(),
        Principal::TcpAccess => "TCP access".to_owned(),
    }
}

impl Trace {
    /// Plain-text lines for an admin: the full picture, resource facts included.
    #[must_use]
    pub fn render(&self) -> Vec<String> {
        let mut lines = Vec::new();
        match &self.resource {
            None => lines.push("The resource does not exist.".to_owned()),
            Some(f) => {
                let labels = if f.labels.is_empty() {
                    "no labels".to_owned()
                } else {
                    f.labels
                        .iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                lines.push(format!(
                    "{} is a {} resource ({labels}).",
                    f.name,
                    f.kind.as_str()
                ));
            }
        }
        lines.push(match &self.decision {
            Decision::Allow { matched_roles } => {
                format!("Decision: allow, through {}.", matched_roles.join(", "))
            }
            Decision::Deny { reason } => format!("Decision: deny ({}).", deny_text(reason)),
            Decision::RequiresApproval { roles, .. } => format!(
                "Decision: needs approval. A request for {} would be considered.",
                roles.join(" or ")
            ),
        });
        for r in &self.roles {
            let how = match r.standing {
                Standing::Held => "held",
                Standing::Eligible => "requestable",
            };
            if !r.known {
                lines.push(format!("  role {} ({how}): not in the policy", r.role));
                continue;
            }
            for n in &r.denied_by {
                lines.push(format!(
                    "  role {} ({how}): deny rule {} {}",
                    r.role,
                    n.rule + 1,
                    n.text
                ));
            }
            for n in &r.allowed_by {
                lines.push(format!(
                    "  role {} ({how}): allow rule {} {}",
                    r.role,
                    n.rule + 1,
                    n.text
                ));
            }
            if r.allowed_by.is_empty() {
                for n in &r.misses {
                    lines.push(format!(
                        "  role {} ({how}): allow rule {} {}",
                        r.role,
                        n.rule + 1,
                        n.text
                    ));
                }
                if r.misses.is_empty() && r.denied_by.is_empty() {
                    lines.push(format!("  role {} ({how}): has no allow rules", r.role));
                }
            }
        }
        lines
    }
}

fn deny_text(reason: &DenyReason) -> &'static str {
    match reason {
        DenyReason::NoMatchingRole => "no role grants it",
        DenyReason::ExplicitDeny => "a deny rule applies",
        DenyReason::UnknownResource => "unknown resource",
        DenyReason::PolicySnapshotStale => "policy is stale",
        DenyReason::InvalidRequest => "that principal does not fit this kind of resource",
    }
}

/// What a role allows, in words that name no resource. Safe to show to anyone
/// who holds (or may request) the role.
#[must_use]
pub fn summarize_role(role: &RoleDoc) -> Vec<String> {
    role.spec
        .allow
        .iter()
        .map(|rule| {
            let sel = &rule.resources;
            let mut parts = vec![kinds(sel)];
            for (k, v) in &sel.labels {
                parts.push(format!("{k} in [{}]", v.join(", ")));
            }
            if let Some(names) = &sel.names {
                parts.push(format!("named {}", names.join(", ")));
            }
            let mut principals: Vec<String> = Vec::new();
            for kind in &sel.kind {
                principals.extend(rule_principals(rule, *kind));
            }
            principals.sort();
            principals.dedup();
            format!(
                "{} as {}",
                parts.join(" where "),
                if principals.is_empty() {
                    "access".to_owned()
                } else {
                    principals.join(", ")
                }
            )
        })
        .collect()
}
