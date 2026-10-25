//! `kind: discovery` documents (ADR-0027): what workers look for in a cloud
//! account and how to name and label what they find. Discovery only makes
//! resources *selectable*. Access stays deny-by-default, and a new resource or
//! a changed label waits for an admin (the control plane enforces that).

use std::collections::BTreeMap;
use std::time::Duration;

use limen_core::labels::Labels;
use limen_core::resource::ResourceKind;
use serde::{Deserialize, Serialize};

use crate::duration::DurationStr;
use crate::model::Metadata;
use crate::model::Version;
use crate::{PolicyError, invalid, validate_name};

/// How often a worker runs a document's matchers when it doesn't say.
pub const DEFAULT_INTERVAL: Duration = Duration::from_mins(5);
/// The shortest interval accepted: describe calls are rate limited.
pub const MIN_INTERVAL: Duration = Duration::from_mins(1);
/// Missed cycles before a resource goes stale.
pub const DEFAULT_STALE_AFTER_CYCLES: u32 = 3;
/// How long a stale resource is kept before it is removed.
pub const DEFAULT_REMOVE_AFTER: Duration = Duration::from_hours(24 * 7);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryDoc {
    pub version: Version,
    pub metadata: Metadata,
    pub spec: DiscoverySpec,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoverySpec {
    pub provider: Provider,
    /// Accounts to assume a describe-only role in. Empty means the worker's own.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accounts: Vec<DiscoveryAccount>,
    pub regions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<DurationStr>,
    /// Workers that run this document: every label must match the worker's.
    /// Empty means every worker that has a discovery role configured.
    #[serde(default)]
    pub worker_selector: Labels,
    /// Label keys whose *changes* on a known resource are accepted without an
    /// admin. A new resource always waits.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auto_accept: Vec<String>,
    /// Cycles a resource may go unseen before new sessions are refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_after_cycles: Option<u32>,
    /// How long a stale resource is kept before it is removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remove_after: Option<DurationStr>,
    #[serde(rename = "match")]
    pub matchers: Vec<DiscoveryMatch>,
}

impl DiscoverySpec {
    /// Whether a worker with these labels (from its certificate) runs this
    /// document: every `worker_selector` label must match exactly. An empty
    /// selector means every worker. A component's display name never matches.
    #[must_use]
    pub fn worker_runs(&self, worker_labels: &BTreeMap<String, String>) -> bool {
        self.worker_selector.iter().all(|(k, v)| {
            k != limen_core::names::NAME_LABEL && worker_labels.get(k).is_some_and(|a| a == v)
        })
    }

    #[must_use]
    pub fn interval(&self) -> Duration {
        self.interval.map_or(DEFAULT_INTERVAL, |d| d.0)
    }

    #[must_use]
    pub fn stale_after_cycles(&self) -> u32 {
        self.stale_after_cycles
            .unwrap_or(DEFAULT_STALE_AFTER_CYCLES)
    }

    #[must_use]
    pub fn remove_after(&self) -> Duration {
        self.remove_after.map_or(DEFAULT_REMOVE_AFTER, |d| d.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    Aws,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryAccount {
    /// The describe-only role to assume (`arn:aws:iam::<account>:role/...`).
    pub role_arn: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryMatch {
    #[serde(rename = "type")]
    pub source: Source,
    /// Every key must be present with one of the listed values (`"*"` means
    /// any value). Empty matches everything the source lists.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tags: BTreeMap<String, Vec<String>>,
    /// The resource name. `{{ tag.Name }}`, `{{ id }}`, `{{ region }}`,
    /// `{{ account }}`. Default: `{{ tag.Name }}` for EC2, else `{{ id }}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_template: Option<String>,
    /// Only these tags become labels (lower-cased keys).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels_from_tags: Vec<String>,
    /// Labels added to everything this matcher finds.
    #[serde(default)]
    pub labels: Labels,
    /// EC2 only: how to reach the instance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh: Option<DiscoverySsh>,
}

/// What a matcher looks for. Each lands as its protocol did (ADR-0027).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// EC2 instances, as SSH resources.
    Ec2,
    /// RDS and Aurora instances and clusters (PostgreSQL, MySQL).
    Rds,
    /// Redshift clusters.
    Redshift,
    /// ElastiCache replication groups and clusters (Redis, Valkey).
    Elasticache,
    /// EKS clusters.
    Eks,
}

impl Source {
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "ec2" => Source::Ec2,
            "rds" => Source::Rds,
            "redshift" => Source::Redshift,
            "elasticache" => Source::Elasticache,
            "eks" => Source::Eks,
            _ => return None,
        })
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Ec2 => "ec2",
            Source::Rds => "rds",
            Source::Redshift => "redshift",
            Source::Elasticache => "elasticache",
            Source::Eks => "eks",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoverySsh {
    #[serde(default = "ssh_port", skip_serializing_if = "is_ssh_port")]
    pub port: u16,
    /// Which address to dial. Default `private_ip`.
    #[serde(default)]
    pub address: SshAddress,
}

fn ssh_port() -> u16 {
    22
}
#[allow(clippy::trivially_copy_pass_by_ref)] // serde `skip_serializing_if` takes a reference
fn is_ssh_port(p: &u16) -> bool {
    *p == 22
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshAddress {
    #[default]
    PrivateIp,
    PrivateDns,
}

pub(crate) fn validate_discovery(doc: &DiscoveryDoc) -> Result<(), PolicyError> {
    let name = &doc.metadata.name;
    validate_name("discovery", name, name)?;
    let spec = &doc.spec;
    if spec.regions.is_empty() {
        return Err(invalid("discovery", name, "regions must not be empty"));
    }
    if let Some(bad) = spec.regions.iter().find(|r| !valid_region(r)) {
        return Err(invalid(
            "discovery",
            name,
            format!("invalid region {bad:?}"),
        ));
    }
    if let Some(bad) = spec.accounts.iter().find(|a| !valid_role_arn(&a.role_arn)) {
        return Err(invalid(
            "discovery",
            name,
            format!(
                "account role_arn {:?} must look like arn:aws:iam::<12 digits>:role/<name>",
                bad.role_arn
            ),
        ));
    }
    if let Some(i) = spec.interval
        && i.0 < MIN_INTERVAL
    {
        return Err(invalid("discovery", name, "interval must be at least 1m"));
    }
    if spec.stale_after_cycles == Some(0) {
        return Err(invalid(
            "discovery",
            name,
            "stale_after_cycles must be at least 1",
        ));
    }
    if spec.matchers.is_empty() {
        return Err(invalid("discovery", name, "match must not be empty"));
    }
    for m in &spec.matchers {
        validate_match(name, m)?;
    }
    for key in &spec.auto_accept {
        if !spec
            .matchers
            .iter()
            .any(|m| m.labels_from_tags.iter().any(|t| t.to_lowercase() == *key))
        {
            return Err(invalid(
                "discovery",
                name,
                format!("auto_accept key {key:?} is not in any labels_from_tags"),
            ));
        }
    }
    Ok(())
}

fn validate_match(doc: &str, m: &DiscoveryMatch) -> Result<(), PolicyError> {
    if m.ssh.is_some() && m.source != Source::Ec2 {
        return Err(invalid(
            "discovery",
            doc,
            "ssh applies to ec2 matchers only",
        ));
    }
    if let Some(ssh) = &m.ssh
        && ssh.port == 0
    {
        return Err(invalid("discovery", doc, "ssh.port must be 1..=65535"));
    }
    for (key, values) in &m.tags {
        if key.is_empty() || key.len() > 128 || values.is_empty() {
            return Err(invalid(
                "discovery",
                doc,
                format!("tags[{key:?}] needs a key and at least one value"),
            ));
        }
    }
    for key in &m.labels_from_tags {
        let label = key.to_lowercase();
        let mut probe = Labels::default();
        if probe.insert(label.clone(), "x").is_err() {
            return Err(invalid(
                "discovery",
                doc,
                format!("labels_from_tags entry {key:?} is not a valid label key"),
            ));
        }
        // Reserved keys are set by Limen. A tag must not be able to write them.
        if label.starts_with("limen") {
            return Err(invalid(
                "discovery",
                doc,
                format!("labels_from_tags entry {key:?} is reserved"),
            ));
        }
    }
    if let Some(t) = &m.name_template {
        validate_template(doc, t)?;
    }
    Ok(())
}

/// Names the placeholders a template may use.
const PLACEHOLDERS: [&str; 3] = ["id", "region", "account"];

fn validate_template(doc: &str, template: &str) -> Result<(), PolicyError> {
    if template.is_empty() || template.len() > 128 {
        return Err(invalid(
            "discovery",
            doc,
            "name_template must be 1..=128 chars",
        ));
    }
    for placeholder in placeholders(template) {
        let ok = PLACEHOLDERS.contains(&placeholder)
            || placeholder
                .strip_prefix("tag.")
                .is_some_and(|k| !k.is_empty() && k.len() <= 128);
        if !ok {
            return Err(invalid(
                "discovery",
                doc,
                format!("unknown placeholder {{{{ {placeholder} }}}} in name_template"),
            ));
        }
    }
    if template.matches("{{").count() != template.matches("}}").count() {
        return Err(invalid(
            "discovery",
            doc,
            "unbalanced braces in name_template",
        ));
    }
    Ok(())
}

fn placeholders(template: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else { break };
        out.push(after[..end].trim());
        rest = &after[end + 2..];
    }
    out
}

/// What a template names, with the placeholders filled in. Anything that isn't
/// `[a-z0-9._-]` becomes `-`, and the result is trimmed to a valid resource
/// name. Returns `None` if nothing usable is left.
#[must_use]
pub fn render_name(template: &str, lookup: impl Fn(&str) -> Option<String>) -> Option<String> {
    let mut out = String::new();
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find("}}")?;
        out.push_str(&lookup(after[..end].trim())?);
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    let cleaned: String = out
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let cleaned = cleaned.trim_matches(['-', '.', '_']).to_owned();
    let cleaned: String = cleaned.chars().take(100).collect();
    (!cleaned.is_empty()).then_some(cleaned)
}

fn valid_region(r: &str) -> bool {
    // eu-west-1, us-gov-east-1, cn-north-1
    let parts: Vec<&str> = r.split('-').collect();
    (3..=4).contains(&parts.len())
        && parts
            .iter()
            .take(parts.len() - 1)
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_lowercase()))
        && parts
            .last()
            .is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

fn valid_role_arn(arn: &str) -> bool {
    let Some(rest) = arn
        .strip_prefix("arn:aws:iam::")
        .or_else(|| arn.strip_prefix("arn:aws-us-gov:iam::"))
        .or_else(|| arn.strip_prefix("arn:aws-cn:iam::"))
    else {
        return false;
    };
    let Some((account, role)) = rest.split_once(":role/") else {
        return false;
    };
    account.len() == 12
        && account.bytes().all(|b| b.is_ascii_digit())
        && !role.is_empty()
        && role.len() <= 512
        && role.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'+' | b'=' | b',' | b'.' | b'@' | b'_' | b'-' | b'/')
        })
}

// ---------------------------------------------------------------------------
// From what a worker saw to a proposed resource.

/// One thing a worker saw in a cloud account. It reports facts, not names or
/// labels: the control plane turns them into a [`Proposal`] with the
/// `discovery` document, so a compromised worker can't choose either.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Found {
    pub source: Source,
    pub account: String,
    pub region: String,
    /// The provider's id: an instance id, a DB instance identifier, a cluster name.
    pub provider_id: String,
    /// Where to dial: `host:port`, or the cluster name for EKS.
    pub target: String,
    /// Only the tags the matcher uses (its filter, its name template, its
    /// `labels_from_tags`), never the rest.
    pub tags: BTreeMap<String, String>,
    /// Source facts: `engine`, `iam_auth`, `tls`, `host_key`, `cluster_identifier`, ...
    pub facts: BTreeMap<String, String>,
}

impl Found {
    /// The identity of the thing across scans: stable while it exists.
    #[must_use]
    pub fn key(&self) -> String {
        format!(
            "aws:{}:{}:{}:{}",
            self.account,
            self.region,
            self.source.as_str(),
            self.provider_id
        )
    }
}

/// What the control plane would make of a [`Found`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Proposal {
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub kind: ResourceKind,
    pub target: String,
    /// The protocol section of the resource (`{"postgres": {...}}`).
    pub spec: serde_json::Value,
    /// Things that stop it being accepted until they are fixed.
    pub blockers: Vec<String>,
}

/// Labels the control plane puts on every discovered resource, from facts it
/// checked rather than from tags.
pub const LABEL_SOURCE: &str = "limen.io/source";
pub const LABEL_REGION: &str = "limen.io/region";
pub const LABEL_ACCOUNT: &str = "limen.io/account";
pub const LABEL_DISCOVERED: &str = "limen.io/discovered";

fn tag_matches(filter: &BTreeMap<String, Vec<String>>, tags: &BTreeMap<String, String>) -> bool {
    filter.iter().all(|(key, values)| {
        tags.get(key)
            .is_some_and(|actual| values.iter().any(|v| v == "*" || v == actual))
    })
}

fn account_of(role_arn: &str) -> Option<&str> {
    role_arn.split(':').nth(4)
}

/// Turn what a worker saw into a proposed resource, applying the document's
/// rules: the account and region must be the document's, the tags must match
/// its filter, the name comes from its template, and only its allow-listed
/// tags become labels. `Err` means the worker reported something the document
/// doesn't ask for, and the report is dropped.
pub fn propose(doc: &DiscoveryDoc, matcher: usize, found: &Found) -> Result<Proposal, String> {
    let m = doc
        .spec
        .matchers
        .get(matcher)
        .ok_or("no such matcher in the discovery document")?;
    if m.source != found.source {
        return Err(format!(
            "matcher {matcher} looks for {}, not {}",
            m.source.as_str(),
            found.source.as_str()
        ));
    }
    if !doc.spec.regions.contains(&found.region) {
        return Err(format!("region {} is not in the document", found.region));
    }
    if !doc.spec.accounts.is_empty()
        && !doc
            .spec
            .accounts
            .iter()
            .any(|a| account_of(&a.role_arn) == Some(found.account.as_str()))
    {
        return Err(format!("account {} is not in the document", found.account));
    }
    if found.account.len() != 12 || !found.account.bytes().all(|b| b.is_ascii_digit()) {
        return Err("the account is not a 12-digit id".into());
    }
    if found.provider_id.is_empty() || found.provider_id.len() > 200 {
        return Err("the provider id is missing or too long".into());
    }
    if !tag_matches(&m.tags, &found.tags) {
        return Err("the tags don't match the matcher's filter".into());
    }

    let default_template = if m.source == Source::Ec2 {
        "{{ tag.Name }}"
    } else {
        "{{ id }}"
    };
    let template = m.name_template.as_deref().unwrap_or(default_template);
    let name = render_name(template, |placeholder| match placeholder {
        "id" => Some(found.provider_id.clone()),
        "region" => Some(found.region.clone()),
        "account" => Some(found.account.clone()),
        other => other
            .strip_prefix("tag.")
            .and_then(|k| found.tags.get(k).cloned()),
    })
    // A name that can't be built from the tags falls back to the id: the
    // resource is still found, and the admin sees why it has that name.
    .or_else(|| render_name("{{ id }}", |_| Some(found.provider_id.clone())))
    .ok_or("no usable name")?;

    // Static labels first, tag labels over them, ours over everything.
    let mut labels: BTreeMap<String, String> = m
        .labels
        .iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
    for key in &m.labels_from_tags {
        if let Some(value) = found.tags.get(key) {
            let label = key.to_lowercase();
            let mut probe = Labels::default();
            if probe.insert(label.clone(), value.clone()).is_ok() {
                labels.insert(label, value.clone());
            }
        }
    }
    labels.insert(LABEL_DISCOVERED.into(), "true".into());
    labels.insert(LABEL_SOURCE.into(), m.source.as_str().into());
    labels.insert(LABEL_REGION.into(), found.region.clone());
    labels.insert(LABEL_ACCOUNT.into(), found.account.clone());

    let fact = |k: &str| found.facts.get(k).map(String::as_str);
    let mut blockers = Vec::new();
    let (kind, spec) = match m.source {
        Source::Ec2 => {
            let host_key = fact("host_key").filter(|k| !k.is_empty());
            if host_key.is_none() {
                blockers.push(
                    "the instance's SSH host key is not known (its console output has none); the worker refuses unpinned hosts"
                        .to_owned(),
                );
            }
            (
                ResourceKind::Ssh,
                serde_json::json!({ "ssh": { "address": found.target, "host_key": host_key } }),
            )
        }
        Source::Rds => {
            let engine = fact("engine").unwrap_or_default();
            let (kind, section) = if engine.contains("postgres") {
                (ResourceKind::Postgres, "postgres")
            } else if engine.contains("mysql") || engine.contains("mariadb") {
                (ResourceKind::Mysql, "mysql")
            } else {
                blockers.push(format!("engine {engine:?} is not PostgreSQL or MySQL"));
                (ResourceKind::Postgres, "postgres")
            };
            (
                kind,
                serde_json::json!({ section: {
                    "endpoint": found.target,
                    "region": found.region,
                    "iam_auth": fact("iam_auth") == Some("true"),
                    "password_dir": (fact("iam_auth") != Some("true")).then_some("/etc/limen/passwords"),
                }}),
            )
        }
        Source::Redshift => (
            ResourceKind::Redshift,
            serde_json::json!({ "redshift": {
                "endpoint": found.target,
                "region": found.region,
                "iam_auth": true,
                "cluster_identifier": found.provider_id,
            }}),
        ),
        Source::Elasticache => (
            ResourceKind::Redis,
            serde_json::json!({ "redis": {
                "endpoint": found.target,
                "region": found.region,
                "iam_auth": fact("iam_auth") == Some("true"),
                "cache_name": fact("replication_group").unwrap_or(&found.provider_id),
                "tls": fact("tls") != Some("false"),
            }}),
        ),
        Source::Eks => (
            ResourceKind::Kubernetes,
            serde_json::json!({ "kubernetes": { "cluster_name": found.target } }),
        ),
    };
    Ok(Proposal {
        name,
        labels,
        kind,
        target: found.target.clone(),
        spec,
        blockers,
    })
}

/// The resource document for an accepted proposal. `worker_selector` comes
/// from the discovery document, so only workers it names serve the resource.
pub fn resource_doc(
    name: &str,
    labels: &BTreeMap<String, String>,
    spec: &serde_json::Value,
    worker_selector: &Labels,
) -> Result<crate::model::ResourceDoc, String> {
    let mut spec = spec.clone();
    spec["worker_selector"] = serde_json::to_value(worker_selector).map_err(|e| e.to_string())?;
    let doc = serde_json::json!({
        "version": "v1",
        "metadata": { "name": name, "labels": labels },
        "spec": spec,
    });
    serde_json::from_value(doc).map_err(|e| format!("not a valid resource: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_cleaned() {
        let lookup = |p: &str| match p {
            "tag.Name" => Some("Web Prod #1".to_owned()),
            "id" => Some("i-0abc".to_owned()),
            _ => None,
        };
        assert_eq!(
            render_name("{{ tag.Name }}", lookup).as_deref(),
            Some("web-prod--1")
        );
        assert_eq!(
            render_name("aws-{{ id }}", lookup).as_deref(),
            Some("aws-i-0abc")
        );
        assert_eq!(render_name("{{ tag.Missing }}", |_| None), None);
        assert_eq!(render_name("{{ tag.Name }}", |_| Some("***".into())), None);
    }

    #[test]
    fn regions_and_arns() {
        assert!(valid_region("eu-west-1"));
        assert!(valid_region("us-gov-east-1"));
        assert!(!valid_region("eu-west"));
        assert!(!valid_region("EU-west-1"));
        assert!(valid_role_arn(
            "arn:aws:iam::111122223333:role/limen-discovery"
        ));
        assert!(!valid_role_arn("arn:aws:iam::1111:role/x"));
        assert!(!valid_role_arn("arn:aws:iam::111122223333:user/x"));
    }
}
