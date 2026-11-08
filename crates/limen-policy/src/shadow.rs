//! Shadow mode for deny rules and roles (ADR-0046): evaluated and reported,
//! never enforced.

use std::fmt;

use limen_core::resource::ResourceKind;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::Date;
use time::macros::format_description;

use crate::model::{RoleDoc, WebGrant};
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
