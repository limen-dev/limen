//! Shadow mode for deny rules and roles (ADR-0046): evaluated and reported,
//! never enforced.

use std::fmt;

use std::collections::BTreeMap;

use limen_core::resource::ResourceKind;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::Date;
use time::macros::format_description;

use crate::model::{RoleDoc, Rule, WebGrant};
use crate::{
    AccessRequest, Policy, deny_rule_matches, resource_kind, web_deny_rule_matches,
    web_grant_matches,
};

/// The longest a rule may stay in shadow, counted from the day it is applied.
/// The control plane enforces it at apply time; the policy crate cannot,
/// since proxies and workers also load policy and must not depend on a clock.
pub const MAX_SHADOW_DAYS: i64 = 90;

/// Whether a deny rule or role is enforced or only reported.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RuleMode {
    #[default]
    Enforce,
    /// A matching deny is reported as `policy.shadow_deny` and the request
    /// goes on as if the rule did not exist.
    Shadow,
}

impl RuleMode {
    #[must_use]
    pub fn is_enforce(&self) -> bool {
        matches!(self, RuleMode::Enforce)
    }
}

/// A calendar day written `2026-12-31`: when a shadow rule must be enforced
/// or renewed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ShadowDate(pub Date);

impl ShadowDate {
    /// Reads `YYYY-MM-DD`.
    pub fn parse(s: &str) -> Result<Self, String> {
        Date::parse(s.trim(), format_description!("[year]-[month]-[day]"))
            .map(Self)
            .map_err(|_| format!("invalid date {s:?}; use YYYY-MM-DD"))
    }
}

impl fmt::Display for ShadowDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02}",
            self.0.year(),
            u8::from(self.0.month()),
            self.0.day()
        )
    }
}

impl schemars::JsonSchema for ShadowDate {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ShadowDate".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "pattern": "^\\s*[0-9]{4}-[0-9]{2}-[0-9]{2}\\s*$",
            "description": "A calendar day, `YYYY-MM-DD`."
        })
    }
}

impl Serialize for ShadowDate {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ShadowDate {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// A rule or role in shadow mode, for listings and warnings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowRule {
    pub role: String,
    /// The deny rule's name.
    pub rule: String,
    /// Shadow because the whole role is.
    pub whole_role: bool,
    pub until: ShadowDate,
}

/// A shadow deny that matched a request that was then allowed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowMatch {
    pub role: String,
    /// The deny rule's `name`.
    pub rule: String,
    /// Its position in the role's `deny` list.
    pub index: usize,
}

impl Policy {
    /// The shadow deny rules that match `req`, when enforcement allows it.
    /// A request that enforced rules refuse teaches nothing about a shadow
    /// rule, so this is empty unless [`Policy::evaluate`] allows. Never
    /// changes the decision. Call it at the point that authorizes the request.
    #[must_use]
    pub fn shadow_denies(&self, req: &AccessRequest<'_>) -> Vec<ShadowMatch> {
        let roles = self.roles_in_play(req.roles);
        if !roles.iter().any(|r| r.spec.shadow_deny().next().is_some()) {
            return Vec::new();
        }
        if !self.evaluate(req).is_allowed() {
            return Vec::new();
        }
        let Some(resource) = self.resources.get(req.resource) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for role in roles {
            for (index, rule) in role.spec.shadow_deny() {
                if deny_rule_matches(rule, resource, &req.principal) {
                    out.push(shadow_match(role, index));
                }
            }
        }
        out
    }

    /// The shadow deny rules with a `web` grant that cover one web request,
    /// when [`Policy::web_request_allowed`] allows it. Rules that name no
    /// principals are reported by [`Policy::shadow_denies`].
    #[must_use]
    pub fn shadow_denies_web(
        &self,
        roles: &[String],
        resource_name: &str,
        method: &str,
        path: &str,
    ) -> Vec<ShadowMatch> {
        let roles = self.roles_in_play(roles);
        if !roles.iter().any(|r| r.spec.shadow_deny().next().is_some()) {
            return Vec::new();
        }
        let held: Vec<String> = roles.iter().map(|r| r.metadata.name.clone()).collect();
        if !self.web_request_allowed(&held, resource_name, method, path) {
            return Vec::new();
        }
        let Some(resource) = self.resources.get(resource_name) else {
            return Vec::new();
        };
        if resource_kind(resource) != ResourceKind::Web {
            return Vec::new();
        }
        let covers = |grant: &WebGrant| web_grant_matches(grant, method, path);
        let mut out = Vec::new();
        for role in roles {
            for (index, rule) in role.spec.shadow_deny() {
                if rule.web.is_some() && web_deny_rule_matches(rule, resource, &covers) {
                    out.push(shadow_match(role, index));
                }
            }
        }
        out
    }

    fn roles_in_play(&self, names: &[String]) -> Vec<&RoleDoc> {
        names.iter().filter_map(|r| self.roles.get(r)).collect()
    }
}

impl Policy {
    /// Every deny rule in shadow mode, with the date it must be settled by.
    #[must_use]
    pub fn shadow_rules(&self) -> Vec<ShadowRule> {
        let mut out = Vec::new();
        for role in self.roles.values() {
            for (_, rule) in role.spec.shadow_deny() {
                let until = if role.spec.is_shadow() {
                    role.spec.shadow_until
                } else {
                    rule.shadow_until
                };
                if let (Some(name), Some(until)) = (&rule.name, until) {
                    out.push(ShadowRule {
                        role: role.metadata.name.clone(),
                        rule: name.clone(),
                        whole_role: role.spec.is_shadow(),
                        until,
                    });
                }
            }
        }
        out
    }

    /// What is wrong with the shadow dates on `today`: a date that has passed
    /// (the rule must be enforced or renewed) or one more than
    /// [`MAX_SHADOW_DAYS`] ahead. Not part of loading a policy: proxies and
    /// workers must be able to load what the control plane stored. The control
    /// plane calls this when a change is applied.
    #[must_use]
    pub fn shadow_date_problems(&self, today: Date) -> Vec<String> {
        let latest = today + time::Duration::days(MAX_SHADOW_DAYS);
        let mut seen = std::collections::BTreeSet::new();
        let mut out = Vec::new();
        for r in self.shadow_rules() {
            // A shadow role has one date; say so once.
            let what = if r.whole_role {
                if !seen.insert(r.role.clone()) {
                    continue;
                }
                format!("role {} (shadow mode)", r.role)
            } else {
                format!("role {}, deny rule {:?} (shadow mode)", r.role, r.rule)
            };
            if r.until.0 < today {
                out.push(format!(
                    "{what}: shadow_until {} has passed; enforce it (remove mode: shadow) or renew the date",
                    r.until
                ));
            } else if r.until.0 > latest {
                out.push(format!(
                    "{what}: shadow_until {} is more than {MAX_SHADOW_DAYS} days away",
                    r.until
                ));
            }
        }
        out
    }

    /// Where `next` reports a deny rule that `self` enforced, or gives a
    /// shadow rule more time: loosening that changes no effective access the
    /// access diff could show, and so waits for a second admin (ADR-0046).
    /// Rules are matched by what they select and deny, not by name, so
    /// naming a rule and marking it shadow in one edit is still caught. A
    /// shadow rule with no counterpart in `self` is new, not loosened.
    #[must_use]
    pub fn shadow_loosening(&self, next: &Policy) -> Vec<String> {
        let mut out = Vec::new();
        for role in next.roles.values() {
            let Some(was) = self.roles.get(&role.metadata.name) else {
                continue;
            };
            let mut unmatched: BTreeMap<String, Vec<&Rule>> = BTreeMap::new();
            for rule in &was.spec.deny {
                unmatched.entry(content_key(rule)).or_default().push(rule);
            }
            for rule in &role.spec.deny {
                let candidates = unmatched.entry(content_key(rule)).or_default();
                let old = if candidates.is_empty() {
                    None
                } else {
                    Some(candidates.remove(0))
                };
                let Some(old) = old else { continue };
                let name = rule
                    .name
                    .clone()
                    .or_else(|| old.name.clone())
                    .unwrap_or_default();
                let label = format!("role {}, deny rule {name:?}", role.metadata.name);
                let now_shadow = role.spec.deny_is_shadow(rule);
                let was_shadow = was.spec.deny_is_shadow(old);
                if now_shadow && !was_shadow {
                    out.push(format!(
                        "{label}: enforced before, now reported only (shadow)"
                    ));
                } else if now_shadow {
                    let until = |r: &RoleDoc, rule: &Rule| {
                        if r.spec.is_shadow() {
                            r.spec.shadow_until
                        } else {
                            rule.shadow_until
                        }
                    };
                    if let (Some(then), Some(now)) = (until(was, old), until(role, rule))
                        && now > then
                    {
                        out.push(format!("{label}: shadow_until moves from {then} to {now}"));
                    }
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }
}

/// A deny rule's content with the shadow bookkeeping left out.
fn content_key(rule: &Rule) -> String {
    let mut value = serde_json::to_value(rule).unwrap_or_default();
    if let Some(object) = value.as_object_mut() {
        for field in ["name", "mode", "shadow_until"] {
            object.remove(field);
        }
    }
    value.to_string()
}

fn shadow_match(role: &RoleDoc, index: usize) -> ShadowMatch {
    ShadowMatch {
        role: role.metadata.name.clone(),
        rule: role.spec.deny[index].name.clone().unwrap_or_default(),
        index,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_round_trip() {
        let d = ShadowDate::parse("2026-12-31").expect("a date");
        assert_eq!(d.to_string(), "2026-12-31");
        for bad in ["", "2026-13-01", "2026-2-3", "tomorrow", "2026-02-30"] {
            assert!(ShadowDate::parse(bad).is_err(), "{bad}");
        }
    }
}
