//! Delegated writes (ADR-0042 §4, §5).
//!
//! A bot writer never writes a full resource. A person writes a
//! `resource_profile` that fixes everything sensitive (the worker, credentials
//! and files on it, IAM, audit settings) and names the few fields a writer may
//! fill in, with bounds. A `policy_writer` document says which bot may write
//! which resources, from which profiles. Three layers keep a sloppy profile
//! from opening what the code forbids:
//!
//! 1. [`SETTABLE`] is the ceiling: only these fields can ever be settable.
//! 2. A profile bounds every settable endpoint (`hosts` or `cidrs`, and
//!    `ports`), and labels are fixed or chosen from allowed values.
//! 3. The finished resource carries [`Delegated`], and the worker refuses
//!    addresses [`forbidden_address`] names, and any outside the bounds.

use std::collections::BTreeMap;
use std::net::IpAddr;

use limen_core::labels::Labels;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::model::{Delegated, Metadata, ResourceDoc, ResourceSpec, Version};
use crate::{PolicyError, invalid, valid_dns_host, validate_name, validate_resource};

/// What kind of value a settable field holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settable {
    /// `host:port`, checked against the profile's bounds.
    Endpoint,
    /// A short free-text value, such as a database name or a host key.
    Text,
}

/// The fields a writer may **ever** set (ADR-0042 §5, layer 1). Everything
/// else in a resource, including every field added later, is profile-only.
/// `profile_only_fields_are_listed` keeps this honest.
pub const SETTABLE: &[(&str, Settable)] = &[
    ("ssh.address", Settable::Endpoint),
    ("ssh.host_key", Settable::Text),
    ("postgres.endpoint", Settable::Endpoint),
    ("postgres.default_database", Settable::Text),
    ("mysql.endpoint", Settable::Endpoint),
    ("mysql.default_database", Settable::Text),
    ("redshift.endpoint", Settable::Endpoint),
    ("redshift.default_database", Settable::Text),
    ("redis.endpoint", Settable::Endpoint),
    ("mongodb.endpoint", Settable::Endpoint),
    ("mongodb.default_database", Settable::Text),
    ("opensearch.endpoint", Settable::Endpoint),
    ("elasticsearch.endpoint", Settable::Endpoint),
    ("rabbitmq.endpoint", Settable::Endpoint),
    ("kafka.endpoint", Settable::Endpoint),
    ("tcp.address", Settable::Endpoint),
    ("web.address", Settable::Endpoint),
];

/// Longest settable text value.
const MAX_TEXT_LEN: usize = 1024;
/// Shortest IPv4 and IPv6 prefixes a profile may allow.
const MIN_V4_PREFIX: u8 = 8;
const MIN_V6_PREFIX: u8 = 32;
/// Most documents one writer may own, and the default.
pub const MAX_WRITER_DOCUMENTS: u32 = 10_000;
pub const DEFAULT_WRITER_DOCUMENTS: u32 = 200;

#[must_use]
pub fn settable(path: &str) -> Option<Settable> {
    SETTABLE.iter().find(|(p, _)| *p == path).map(|(_, s)| *s)
}

// ---- Documents --------------------------------------------------------------

/// The fixed half of a resource, which writers complete. People only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceProfileDoc {
    pub version: Version,
    pub metadata: Metadata,
    pub spec: ProfileSpec,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSpec {
    /// A partial resource `spec`: everything the writer can't change.
    pub template: Map<String, Value>,
    /// The fields a writer may set, as `protocol.field`, with their bounds.
    #[serde(default)]
    pub settable: BTreeMap<String, Bound>,
    #[serde(default)]
    pub labels: ProfileLabels,
}

/// Where a settable endpoint may point. Empty for a text field.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bound {
    /// Exact host names, or `*.suffix` for any name under `suffix`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    /// IP ranges, such as `10.20.0.0/16`, for IP literals and resolved names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cidrs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileLabels {
    /// Labels every resource from the profile carries. Writers can't change them.
    #[serde(default)]
    pub fixed: Labels,
    /// Labels a writer may set, and the values it may choose from.
    #[serde(default)]
    pub allowed: BTreeMap<String, Vec<String>>,
}

/// What one bot may write (ADR-0042 §4). People only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyWriterDoc {
    pub version: Version,
    pub metadata: Metadata,
    pub spec: WriterSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriterSpec {
    /// The `bot` document whose logins may write. One grant per bot.
    pub bot: String,
    /// The one namespace the writer owns documents in. Not `default`.
    pub namespace: String,
    /// Patterns every document name must match: exact, or `prefix*`.
    pub names: Vec<String>,
    /// What it may write. Stage 1: `resource`.
    pub kinds: Vec<WriterKind>,
    /// The profiles its resources may complete.
    #[serde(default)]
    pub profiles: Vec<String>,
    #[serde(default = "default_max_documents")]
    pub max_documents: u32,
    /// Who may approve its held changes, besides admins (stage 2).
    #[serde(default)]
    pub approvers: Approvers,
}

fn default_max_documents() -> u32 {
    DEFAULT_WRITER_DOCUMENTS
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriterKind {
    Resource,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approvers {
    /// IdP groups.
    #[serde(default)]
    pub groups: Vec<String>,
}

impl WriterSpec {
    /// Whether `name` matches one of the writer's patterns.
    #[must_use]
    pub fn name_allowed(&self, name: &str) -> bool {
        self.names.iter().any(|p| match p.strip_suffix('*') {
            Some(prefix) => name.len() > prefix.len() && name.starts_with(prefix),
            None => name == p,
        })
    }
}

// ---- Validation -------------------------------------------------------------

pub(crate) fn validate_profile(doc: &ResourceProfileDoc) -> Result<(), PolicyError> {
    let name = &doc.metadata.name;
    let err = |m: String| invalid("resource_profile", name, m);
    validate_name("resource_profile", name, name)?;
    let spec = &doc.spec;
    if spec.template.contains_key("delegated") {
        return Err(err(
            "template can't set delegated: the control plane sets it".into(),
        ));
    }
    for (path, bound) in &spec.settable {
        let Some(kind) = settable(path) else {
            return Err(err(format!(
                "{path:?} can't be settable; writers may only set {}",
                SETTABLE
                    .iter()
                    .map(|(p, _)| *p)
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        };
        if leaf(&spec.template, path).is_some() {
            return Err(err(format!(
                "{path:?} is both in the template and settable; pick one"
            )));
        }
        match kind {
            Settable::Text if *bound != Bound::default() => {
                return Err(err(format!(
                    "{path:?} is text and takes no bounds: use {{}}"
                )));
            }
            Settable::Endpoint => validate_bound(path, bound).map_err(err)?,
            Settable::Text => {}
        }
    }
    for (key, values) in &spec.labels.allowed {
        if spec.labels.fixed.get(key).is_some() {
            return Err(err(format!("label {key:?} is both fixed and allowed")));
        }
        if values.is_empty() {
            return Err(err(format!(
                "label {key:?} needs at least one allowed value"
            )));
        }
        let mut probe = Labels::default();
        for value in values {
            probe
                .insert(key.clone(), value.clone())
                .map_err(|e| err(e.to_string()))?;
        }
    }
    // One protocol: the template's and the settable fields' sections agree.
    let sections: std::collections::BTreeSet<&str> = spec
        .settable
        .keys()
        .filter_map(|p| p.split('.').next())
        .chain(
            spec.template
                .keys()
                .map(String::as_str)
                .filter(|k| *k != "worker_selector"),
        )
        .collect();
    if sections.len() > 1 {
        return Err(err(format!(
            "settable fields and the template must use one protocol; this doesn't belong to the template's protocol: {}",
            sections.into_iter().collect::<Vec<_>>().join(", ")
        )));
    }
    // The template plus placeholders must be a valid resource.
    let mut placeholders = Map::new();
    for path in spec.settable.keys() {
        let value = match settable(path) {
            Some(Settable::Endpoint) => "placeholder.invalid:1",
            _ => "placeholder",
        };
        set_leaf(&mut placeholders, path, Value::String(value.into()));
    }
    build(doc, name, None, &spec.labels.fixed, &placeholders, false).map_err(|e| {
        err(format!(
            "template with its settable fields is not a valid resource: {}",
            message(&e)
        ))
    })?;
    Ok(())
}

fn validate_bound(path: &str, bound: &Bound) -> Result<(), String> {
    if bound.ports.is_empty() || bound.ports.contains(&0) {
        return Err(format!("{path:?} needs ports, none of them 0"));
    }
    if bound.hosts.is_empty() && bound.cidrs.is_empty() {
        return Err(format!(
            "{path:?} needs hosts or cidrs: an unbounded endpoint could point anywhere the worker can reach"
        ));
    }
    for host in &bound.hosts {
        let exact = host.strip_prefix("*.").unwrap_or(host);
        let labels = exact.split('.').count();
        if !valid_dns_host(exact) || exact != exact.to_ascii_lowercase() {
            return Err(format!(
                "host {host:?} must be a lowercase DNS name or *.name"
            ));
        }
        if host.starts_with("*.") && labels < 2 {
            return Err(format!(
                "host {host:?} is too broad: a wildcard needs a suffix of at least two labels"
            ));
        }
    }
    for cidr in &bound.cidrs {
        let (net, prefix) =
            parse_cidr(cidr).ok_or_else(|| format!("cidr {cidr:?} is not addr/prefix"))?;
        let min = if net.is_ipv4() {
            MIN_V4_PREFIX
        } else {
            MIN_V6_PREFIX
        };
        if prefix < min {
            return Err(format!(
                "cidr {cidr:?} is too broad: at least /{min} for {}",
                if net.is_ipv4() { "IPv4" } else { "IPv6" }
            ));
        }
        if forbidden_address(net) {
            return Err(format!(
                "cidr {cidr:?} is in a range the worker always refuses (loopback, link-local, metadata, multicast)"
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_writer(doc: &PolicyWriterDoc) -> Result<(), PolicyError> {
    let name = &doc.metadata.name;
    let err = |m: &str| invalid("policy_writer", name, m);
    validate_name("policy_writer", name, name)?;
    let spec = &doc.spec;
    validate_name("policy_writer", name, &spec.bot)?;
    validate_name("policy_writer", name, &spec.namespace)?;
    if spec.namespace == "default" {
        return Err(err(
            "namespace default belongs to policy applied from files; give the writer its own",
        ));
    }
    if spec.names.is_empty() {
        return Err(err("names needs at least one pattern"));
    }
    for pattern in &spec.names {
        let fixed = pattern.strip_suffix('*').unwrap_or(pattern);
        if fixed.len() < 2 || fixed.contains('*') {
            return Err(err(
                "a name pattern is a name, or a prefix of at least two characters followed by *",
            ));
        }
        validate_name("policy_writer", name, fixed)?;
    }
    if spec.kinds.is_empty() {
        return Err(err("kinds needs at least one kind"));
    }
    if spec.kinds.contains(&WriterKind::Resource) && spec.profiles.is_empty() {
        return Err(err(
            "a writer of resources needs profiles: writers only complete profiles",
        ));
    }
    if spec.max_documents == 0 || spec.max_documents > MAX_WRITER_DOCUMENTS {
        return Err(invalid(
            "policy_writer",
            name,
            format!("max_documents must be 1..={MAX_WRITER_DOCUMENTS}"),
        ));
    }
    for group in &spec.approvers.groups {
        if group.is_empty() || group.len() > 256 {
            return Err(err("approver groups must be 1..=256 characters"));
        }
    }
    Ok(())
}

// ---- Building a resource from a profile -------------------------------------

/// What a writer sends for a resource: its name, labels, and the settable
/// fields it fills in, in the same shape as a resource `spec`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WriterResource {
    pub name: String,
    pub description: Option<String>,
    pub labels: BTreeMap<String, String>,
    pub spec: Map<String, Value>,
}

/// The resource enforcement uses: the profile's template, the writer's
/// fields within their bounds, the fixed and chosen labels, and the
/// [`Delegated`] marker the worker checks.
pub fn materialize(
    profile: &ResourceProfileDoc,
    input: &WriterResource,
) -> Result<ResourceDoc, PolicyError> {
    let name = &input.name;
    let err = |m: String| invalid("resource", name, m);
    let spec = &profile.spec;
    let fields = leaves(&input.spec, "");
    // Every path first, so a writer that touched a field it may never set
    // hears that, whatever else is wrong.
    if let Some((path, _)) = fields.iter().find(|(p, _)| !spec.settable.contains_key(p)) {
        return Err(err(format!(
            "{path:?} isn't settable in profile {:?}",
            profile.metadata.name
        )));
    }
    for (path, value) in fields {
        let Some(bound) = spec.settable.get(&path) else {
            continue;
        };
        let Value::String(text) = value else {
            return Err(err(format!("{path:?} must be a string")));
        };
        let checked = match settable(&path) {
            Some(Settable::Endpoint) => check_endpoint(text, bound),
            Some(Settable::Text) => check_text(text),
            None => Err("isn't settable".to_owned()),
        };
        checked.map_err(|m| err(format!("{path}: {m}")))?;
    }
    let mut labels = spec.labels.fixed.clone();
    for (key, value) in &input.labels {
        if spec.labels.fixed.get(key).is_some() {
            return Err(err(format!(
                "label {key:?} is fixed by profile {:?}",
                profile.metadata.name
            )));
        }
        match spec.labels.allowed.get(key) {
            Some(values) if values.contains(value) => {}
            Some(values) => {
                return Err(err(format!(
                    "label {key}={value:?} isn't allowed; choose one of {values:?}"
                )));
            }
            None => {
                return Err(err(format!(
                    "label {key:?} isn't allowed by profile {:?}",
                    profile.metadata.name
                )));
            }
        }
        labels
            .insert(key.clone(), value.clone())
            .map_err(|e| err(e.to_string()))?;
    }
    build(
        profile,
        name,
        input.description.clone(),
        &labels,
        &input.spec,
        true,
    )
}

fn build(
    profile: &ResourceProfileDoc,
    name: &str,
    description: Option<String>,
    labels: &Labels,
    fields: &Map<String, Value>,
    mark: bool,
) -> Result<ResourceDoc, PolicyError> {
    let mut json = profile.spec.template.clone();
    for (path, value) in leaves(fields, "") {
        set_leaf(&mut json, &path, value.clone());
    }
    let mut spec: ResourceSpec = serde_json::from_value(Value::Object(json))
        .map_err(|e| invalid("resource", name, e.to_string()))?;
    if mark {
        let protocol = protocol_of(&spec);
        let bound = profile
            .spec
            .settable
            .iter()
            .find(|(p, _)| {
                p.split('.').next() == Some(protocol) && settable(p) == Some(Settable::Endpoint)
            })
            .map(|(_, b)| b.clone())
            .unwrap_or_default();
        spec.delegated = Some(Delegated {
            profile: profile.metadata.name.clone(),
            hosts: bound.hosts,
            cidrs: bound.cidrs,
            ports: bound.ports,
        });
    }
    let doc = ResourceDoc {
        version: Version::V1,
        metadata: Metadata {
            name: name.to_owned(),
            description,
            labels: labels.clone(),
        },
        spec,
    };
    validate_resource(&doc)?;
    Ok(doc)
}

/// The protocol section a resource sets, such as `postgres`.
fn protocol_of(spec: &ResourceSpec) -> &'static str {
    spec.kinds().first().map_or("", |k| k.as_str())
}

fn check_text(text: &str) -> Result<(), String> {
    if text.is_empty() || text.len() > MAX_TEXT_LEN {
        return Err(format!("must be 1..={MAX_TEXT_LEN} characters"));
    }
    if text.chars().any(char::is_control) {
        return Err("must not contain control characters".into());
    }
    Ok(())
}

/// Whether `host:port` is inside `bound`. IP literals must be in `cidrs`,
/// names must match `hosts`, and the port must be listed. Addresses the
/// worker always refuses are refused here too.
pub fn check_endpoint(endpoint: &str, bound: &Bound) -> Result<(), String> {
    let (host, port) =
        split_host_port(endpoint).ok_or_else(|| format!("{endpoint:?} is not host:port"))?;
    if !bound.ports.contains(&port) {
        return Err(format!(
            "port {port} isn't allowed; allowed: {:?}",
            bound.ports
        ));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if forbidden_address(ip) {
            return Err(format!("{ip} is an address the worker always refuses"));
        }
        if !in_cidrs(ip, &bound.cidrs) {
            return Err(format!(
                "{ip} is outside the allowed cidrs {:?}",
                bound.cidrs
            ));
        }
        return Ok(());
    }
    if !host_allowed(host, &bound.hosts) {
        return Err(format!(
            "{host:?} doesn't match the allowed hosts {:?}",
            bound.hosts
        ));
    }
    Ok(())
}

/// Whether a host name matches one of the patterns (exact, or `*.suffix`).
#[must_use]
pub fn host_allowed(host: &str, patterns: &[String]) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    valid_dns_host(&host)
        && patterns.iter().any(|p| match p.strip_prefix("*.") {
            Some(suffix) => host
                .strip_suffix(suffix)
                .is_some_and(|rest| rest.len() > 1 && rest.ends_with('.')),
            None => host == *p,
        })
}

/// `host:port`, with IPv6 literals in brackets.
fn split_host_port(endpoint: &str) -> Option<(&str, u16)> {
    let (host, port) = if let Some(rest) = endpoint.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        (host, port)
    } else {
        let (host, port) = endpoint.rsplit_once(':')?;
        if host.contains(':') {
            return None;
        }
        (host, port)
    };
    let port = port.parse::<u16>().ok().filter(|p| *p != 0)?;
    (!host.is_empty()).then_some((host, port))
}

/// Whether `ip` is inside one of `cidrs`.
#[must_use]
pub fn in_cidrs(ip: IpAddr, cidrs: &[String]) -> bool {
    let ip = canonical(ip);
    cidrs
        .iter()
        .filter_map(|c| parse_cidr(c))
        .any(|(net, prefix)| match (canonical(net), ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        })
}

fn parse_cidr(cidr: &str) -> Option<(IpAddr, u8)> {
    let (addr, prefix) = cidr.split_once('/')?;
    let addr: IpAddr = addr.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    (prefix <= max).then_some((addr, prefix))
}

/// An IPv4-mapped IPv6 address as the IPv4 address it carries.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// Addresses a worker never dials for a resource from a profile: loopback,
/// unspecified, link-local (which holds the cloud metadata endpoints),
/// multicast, broadcast, and the AWS and Azure metadata addresses.
#[must_use]
pub fn forbidden_address(ip: IpAddr) -> bool {
    match canonical(ip) {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || a == 0
                || (a == 100 && b == 100 && v4.octets()[2] == 100 && v4.octets()[3] == 200)
                || v4 == std::net::Ipv4Addr::new(168, 63, 129, 16)
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || first & 0xffc0 == 0xfe80
                || v6 == std::net::Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254)
        }
    }
}

// ---- JSON paths -------------------------------------------------------------

/// `(path, value)` for every non-object value, with paths like `postgres.endpoint`.
fn leaves<'a>(map: &'a Map<String, Value>, prefix: &str) -> Vec<(String, &'a Value)> {
    let mut out = Vec::new();
    for (key, value) in map {
        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        match value {
            Value::Object(inner) => out.extend(leaves(inner, &path)),
            _ => out.push((path, value)),
        }
    }
    out
}

fn leaf<'a>(map: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    let mut parts = path.split('.');
    let mut value = map.get(parts.next()?)?;
    for part in parts {
        value = value.as_object()?.get(part)?;
    }
    Some(value)
}

fn set_leaf(map: &mut Map<String, Value>, path: &str, value: Value) {
    let mut parts: Vec<&str> = path.split('.').collect();
    let Some(last) = parts.pop() else { return };
    let mut current = map;
    for part in parts {
        let entry = current
            .entry(part.to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        if !entry.is_object() {
            *entry = Value::Object(Map::new());
        }
        let Value::Object(next) = entry else { return };
        current = next;
    }
    current.insert(last.to_owned(), value);
}

fn message(e: &PolicyError) -> String {
    match e {
        PolicyError::Invalid { message, .. } => message.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests;
