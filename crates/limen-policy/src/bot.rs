//! Bots: CI jobs and automation as first-class principals (ADR-0019).
//!
//! A `bot` document says which workload identity token may log in as
//! `bot:<name>` and which roles that login gets. Matching is **exact**: no
//! wildcards anywhere, and the validator refuses rules that are too broad to
//! mean anything (a repository alone lets every branch and every fork in).

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::duration::DurationStr;
use crate::model::{Metadata, Version};
use crate::{PolicyError, invalid, validate_name};

/// Longest a bot credential may live, and the default. There is no refresh:
/// the next job logs in again.
pub const MAX_BOT_TTL: Duration = Duration::from_hours(1);
pub const DEFAULT_BOT_TTL: Duration = Duration::from_mins(15);

/// Where the bot's token comes from. Decides the default issuer and which
/// claims a rule must name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinMethod {
    GithubActions,
    Gitlab,
    /// Any OIDC provider (`CircleCI`, `Buildkite`, Bitbucket, Argo, Tekton, and so on).
    Oidc,
}

impl JoinMethod {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            JoinMethod::GithubActions => "github_actions",
            JoinMethod::Gitlab => "gitlab",
            JoinMethod::Oidc => "oidc",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "github_actions" => Some(JoinMethod::GithubActions),
            "gitlab" => Some(JoinMethod::Gitlab),
            "oidc" => Some(JoinMethod::Oidc),
            _ => None,
        }
    }

    /// The issuer used when a rule doesn't name one. `None` means it must.
    #[must_use]
    pub fn default_issuer(self) -> Option<&'static str> {
        match self {
            JoinMethod::GithubActions => Some("https://token.actions.githubusercontent.com"),
            JoinMethod::Gitlab => Some("https://gitlab.com"),
            JoinMethod::Oidc => None,
        }
    }
}

/// One value or a list of acceptable values for a claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ClaimValue {
    One(String),
    Many(Vec<String>),
}

impl ClaimValue {
    #[must_use]
    pub fn values(&self) -> &[String] {
        match self {
            ClaimValue::One(v) => std::slice::from_ref(v),
            ClaimValue::Many(v) => v,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BotDoc {
    pub version: Version,
    pub metadata: Metadata,
    pub spec: BotSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BotSpec {
    pub join: BotJoin,
    /// Roles the bot's logins get, exactly as for people.
    pub roles: Vec<String>,
    /// Credential lifetime: at most one hour, 15 minutes by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ttl: Option<DurationStr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BotJoin {
    pub method: JoinMethod,
    /// The token issuer. Defaults per method; required for `oidc`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Every entry must match a claim exactly; a list means "any of these".
    #[serde(rename = "match")]
    pub claims: BTreeMap<String, ClaimValue>,
}

impl BotJoin {
    /// The issuer this rule trusts, without a trailing slash.
    #[must_use]
    pub fn issuer(&self) -> Option<String> {
        self.issuer
            .as_deref()
            .or_else(|| self.method.default_issuer())
            .map(|i| i.trim_end_matches('/').to_owned())
    }

    /// Whether verified `claims` satisfy every entry of the rule.
    #[must_use]
    pub fn matches(&self, claims: &BTreeMap<String, String>) -> bool {
        self.claims.iter().all(|(key, want)| {
            claims
                .get(key)
                .is_some_and(|got| want.values().iter().any(|v| v == got))
        })
    }
}

impl BotDoc {
    /// The username its certificates carry.
    #[must_use]
    pub fn username(&self) -> String {
        limen_core::identity::bot_username(&self.metadata.name)
    }

    /// Credential lifetime: the rule's own, capped at one hour.
    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.spec
            .max_ttl
            .map_or(DEFAULT_BOT_TTL, |d| d.0)
            .min(MAX_BOT_TTL)
    }
}

pub(crate) fn validate_bot(bot: &BotDoc) -> Result<(), PolicyError> {
    let name = &bot.metadata.name;
    validate_name("bot", name, name)?;
    let bad = |message: String| invalid("bot", name, message);

    if bot.spec.roles.is_empty() {
        return Err(bad("roles must not be empty".into()));
    }
    for role in &bot.spec.roles {
        if role.starts_with("limen:") {
            return Err(bad(format!(
                "built-in role {role:?} can't be given to a bot: grant administration to people"
            )));
        }
    }
    if let Some(ttl) = bot.spec.max_ttl
        && ttl.0 > MAX_BOT_TTL
    {
        return Err(bad(
            "max_ttl is at most 1h: bots log in again for each job".into()
        ));
    }

    let join = &bot.spec.join;
    if join.claims.is_empty() {
        return Err(bad("join.match must name at least one claim".into()));
    }
    for (key, value) in &join.claims {
        let key_ok = !key.is_empty()
            && key.len() <= 64
            && key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'));
        if !key_ok {
            return Err(bad(format!("invalid claim name {key:?} in join.match")));
        }
        let values = value.values();
        if values.is_empty() {
            return Err(bad(format!("join.match.{key} has no values")));
        }
        for v in values {
            if v.is_empty() || v.len() > 256 || v.chars().any(char::is_control) {
                return Err(bad(format!("invalid value {v:?} for join.match.{key}")));
            }
            if v.contains('*') {
                return Err(bad(format!(
                    "join.match.{key} has a wildcard: bot rules match exactly"
                )));
            }
        }
    }

    match (join.method, &join.issuer) {
        (JoinMethod::Oidc, None) => return Err(bad("method oidc needs join.issuer".into())),
        (_, Some(issuer)) => validate_issuer(issuer).map_err(bad)?,
        _ => {}
    }

    let has = |k: &str| join.claims.contains_key(k);
    let value_is = |k: &str, want: &str| {
        join.claims
            .get(k)
            .is_some_and(|v| v.values().iter().all(|x| x == want))
    };
    match join.method {
        JoinMethod::GithubActions => {
            if !has("repository") {
                return Err(bad("github_actions must match `repository`".into()));
            }
            if !(has("ref") || has("environment")) {
                return Err(bad(
                    "github_actions must also match `ref` or `environment`: a repository alone lets every branch in"
                        .into(),
                ));
            }
            if join
                .claims
                .get("ref")
                .is_some_and(|v| v.values().iter().any(|r| r.starts_with("refs/pull/")))
            {
                return Err(bad(
                    "a pull request ref (refs/pull/...) can't be trusted: it runs code from a fork or a branch anyone can open".into(),
                ));
            }
            if join.claims.get("event_name").is_some_and(|v| {
                v.values()
                    .iter()
                    .any(|e| e == "pull_request" || e == "pull_request_target")
            }) {
                return Err(bad(
                    "pull request events can't be trusted for bot access".into()
                ));
            }
        }
        JoinMethod::Gitlab => {
            if !has("project_path") {
                return Err(bad("gitlab must match `project_path`".into()));
            }
            if !(has("ref") || has("environment")) {
                return Err(bad("gitlab must also match `ref` or `environment`".into()));
            }
            if has("ref") && !value_is("ref_protected", "true") {
                return Err(bad(
                    "matching a gitlab `ref` also needs `ref_protected: \"true\"`: anyone can create an unprotected branch with that name"
                        .into(),
                ));
            }
        }
        JoinMethod::Oidc => {
            if !has("sub") {
                return Err(bad("method oidc must match `sub`".into()));
            }
        }
    }
    Ok(())
}

/// `http(s)://host[:port][/path]` with no credentials, query, or fragment.
/// Plain `http` is only accepted at login when the control plane is told to
/// (development); policy can still name it.
fn validate_issuer(issuer: &str) -> Result<(), String> {
    let rest = issuer
        .strip_prefix("https://")
        .or_else(|| issuer.strip_prefix("http://"))
        .ok_or_else(|| format!("join.issuer {issuer:?} must start with https://"))?;
    let host = rest.split('/').next().unwrap_or_default();
    if host.is_empty()
        || host.contains('@')
        || rest.contains(['?', '#'])
        || issuer.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(format!(
            "join.issuer {issuer:?} needs a host and no credentials, query, or fragment"
        ));
    }
    Ok(())
}
