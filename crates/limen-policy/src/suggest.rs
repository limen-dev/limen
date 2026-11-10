//! Right-sizing roles from real usage (ADR-0050).
//!
//! [`suggest`] is a pure function: the active policy, what people used in a
//! window, and a clock go in; removals come out. It never adds or widens
//! anything. Before it returns, the suggested policy is rebuilt and compared
//! with the active one by the effective-access diff of ADR-0028, and the call
//! fails if the diff shows any gained access, so a bug here cannot hand out a
//! suggestion that opens a door.
//!
//! A session records the resource and the principal it used, not the role
//! that allowed it. So a session counts as use of **every** standing allow
//! rule that could have allowed it. That over-counts when roles overlap, and
//! over-counting can only hide a suggestion.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use limen_core::resource::ResourceKind;
use serde::{Deserialize, Serialize};

use crate::model::{Document, ResourceDoc, RoleDoc, Rule};
use crate::{Policy, resource_kind, selector_matches};

/// The window when none is given. The same as ADR-0029's "unused" bar.
pub const DEFAULT_WINDOW_DAYS: u32 = 90;
pub const MIN_WINDOW_DAYS: u32 = 7;
pub const MAX_WINDOW_DAYS: u32 = 365;
/// A role with this label (`suggest: keep`) is never touched.
pub const KEEP_LABEL: &str = "suggest";
pub const KEEP_VALUE: &str = "keep";
/// People listed in a report before it says it stopped.
pub const MAX_PEOPLE: usize = 5_000;

const DAY: i64 = 86_400;
/// What a session on a protocol that names no principal (raw TCP) is filed under.
const OPEN_ACCESS: &str = "access";

/// What one person used one resource as, in the window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageRow {
    pub user: String,
    pub resource: String,
    /// The login, database role, Redis user, and so on. Empty for raw TCP.
    pub principal: String,
    pub sessions: u64,
    pub last_used_unix: i64,
}

/// Everything [`suggest`] needs besides the policy.
#[derive(Debug, Clone)]
pub struct SuggestInput<'a> {
    pub usage: &'a [UsageRow],
    /// The standing roles each person holds now.
    pub people: &'a BTreeMap<String, Vec<String>>,
    /// When each role document last changed. A role with no entry is old.
    pub role_changed_unix: &'a BTreeMap<String, i64>,
    /// When each resource document was created. No entry means old.
    pub resource_created_unix: &'a BTreeMap<String, i64>,
    /// When Limen first saw anyone log in; `None` if it never has.
    pub watching_since_unix: Option<i64>,
    pub now_unix: i64,
    pub window_days: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SuggestError {
    #[error("the window must be between {MIN_WINDOW_DAYS} and {MAX_WINDOW_DAYS} days, not {0}")]
    Window(u32),
    #[error("Limen has not seen anyone log in yet, so there is no history to judge by")]
    NoHistory,
    #[error(
        "Limen has been watching for {available_days} days, which is less than the {window_days}-day window; \
         try --window-days {available_days} once that is at least {MIN_WINDOW_DAYS}, or wait"
    )]
    ShortHistory {
        window_days: u32,
        available_days: u32,
    },
    /// A bug: the result would have opened access, or no longer validates.
    #[error("the suggestion was refused by its own safety check: {0}")]
    Unsafe(String),
}

/// One edit to a role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    /// The rule's position in the role's `allow` list, from 1.
    pub rule: usize,
    pub action: Action,
    /// Which grant of the rule (`ssh`, `db`, `redis`, `mongo`, `mq`, `kafka`, `tcp`).
    pub grant: String,
    /// The logins, roles or users no longer listed (all of them for a removed grant).
    pub principals: Vec<String>,
    /// The resources the rule reached for this grant.
    pub resources: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Nothing in the grant was used: the grant, and with it a rule that has nothing else, goes.
    RemoveGrant,
    /// Some entries were used and these were not.
    RemovePrincipals,
}

impl Change {
    #[must_use]
    pub fn text(&self) -> String {
        let what = match self.action {
            Action::RemoveGrant => format!("remove the unused {} grant", self.grant),
            Action::RemovePrincipals => format!("drop {}", self.principals.join(", ")),
        };
        format!(
            "allow rule {}: {what} (reaches {})",
            self.rule,
            self.resources.join(", ")
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoleSuggestion {
    pub role: String,
    pub changes: Vec<Change>,
    /// The role as it would be after the changes.
    pub document: RoleDoc,
}

/// A role or rule left alone, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Skipped {
    pub role: String,
    /// The allow rule, from 1, or `None` for the whole role.
    pub rule: Option<usize>,
    pub reason: String,
}

/// Roles a person holds and did not use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonUnused {
    pub user: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Suggestions {
    pub window_days: u32,
    pub policy_digest: String,
    pub roles: Vec<RoleSuggestion>,
    /// Roles with no allow rule left: remove the role and its group mappings.
    pub unused_roles: Vec<String>,
    /// Roles never judged: break-glass, requestable, shadow, `suggest: keep`, or too new.
    pub kept: Vec<Skipped>,
    /// Rules left alone because use cannot be told, or the rule is too new to judge.
    pub not_assessed: Vec<Skipped>,
    pub people: Vec<PersonUnused>,
    pub people_truncated: bool,
}

impl Suggestions {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.roles.is_empty() && self.unused_roles.is_empty() && self.people.is_empty()
    }

    /// The changed roles as YAML documents, ready to replace the roles of the same name.
    pub fn to_yaml(&self, policy_version: u64) -> Result<String, String> {
        let mut out = format!(
            "# limen policy suggest: a proposal, never applied by Limen.\n\
             # Made from policy version {policy_version} (digest {}) and the last {} days of sessions.\n\
             # Only removals. Replace the roles of the same name in your policy repository, then run\n\
             # `limen policy diff active --new <your policy>` and `limen policy test`.\n",
            self.policy_digest, self.window_days
        );
        if self.roles.is_empty() {
            out.push_str("# No role changes.\n");
        }
        for r in &self.roles {
            let _ = writeln!(out, "---");
            out.push_str(
                &serde_saphyr::to_string(&Document::Role(r.document.clone()))
                    .map_err(|e| format!("writing role {}: {e}", r.role))?,
            );
        }
        Ok(out)
    }

    /// A report for a person to read.
    #[must_use]
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "Policy suggest, last {} days (policy {})",
            self.window_days,
            self.policy_digest.chars().take(12).collect::<String>()
        );
        let _ = writeln!(out, "\nRoles to tighten ({})", self.roles.len());
        for r in &self.roles {
            let _ = writeln!(out, "  {}", r.role);
            for c in &r.changes {
                let _ = writeln!(out, "    - {}", c.text());
            }
        }
        if self.roles.is_empty() {
            out.push_str("  none\n");
        }
        if !self.unused_roles.is_empty() {
            let _ = writeln!(
                out,
                "\nRoles nobody used (remove the role and its group mappings together)"
            );
            for r in &self.unused_roles {
                let _ = writeln!(out, "  {r}");
            }
        }
        if !self.people.is_empty() {
            let _ = writeln!(
                out,
                "\nPeople holding roles they did not use (ask them, or change their IdP groups)"
            );
            for p in &self.people {
                let _ = writeln!(out, "  {}: {}", p.user, p.roles.join(", "));
            }
            if self.people_truncated {
                let _ = writeln!(out, "  ... stopped at {MAX_PEOPLE} people");
            }
        }
        for (title, list) in [
            ("Left alone", &self.kept),
            ("Not assessed", &self.not_assessed),
        ] {
            if !list.is_empty() {
                let _ = writeln!(out, "\n{title}");
                for s in list {
                    match s.rule {
                        Some(n) => {
                            let _ = writeln!(out, "  {} rule {n}: {}", s.role, s.reason);
                        }
                        None => {
                            let _ = writeln!(out, "  {}: {}", s.role, s.reason);
                        }
                    }
                }
            }
        }
        out
    }
}

/// A grant of a rule, as a list of entries to judge.
struct GrantView {
    name: &'static str,
    kinds: &'static [ResourceKind],
    entries: Vec<String>,
}

const DB_KINDS: &[ResourceKind] = &[
    ResourceKind::Postgres,
    ResourceKind::Mysql,
    ResourceKind::Redshift,
];

/// The grants of a rule whose use is recorded per session with a principal.
fn grants(rule: &Rule) -> Vec<GrantView> {
    let mut out = grants_raw(rule);
    // A list may name an entry twice; judge each once.
    for g in &mut out {
        let mut seen = BTreeSet::new();
        g.entries.retain(|e| seen.insert(e.clone()));
    }
    out
}

fn grants_raw(rule: &Rule) -> Vec<GrantView> {
    let mut out = Vec::new();
    if let Some(g) = &rule.ssh {
        out.push(GrantView {
            name: "ssh",
            kinds: &[ResourceKind::Ssh],
            entries: g.logins.clone(),
        });
    }
    if let Some(g) = &rule.db {
        out.push(GrantView {
            name: "db",
            kinds: DB_KINDS,
            entries: g.roles.clone(),
        });
    }
    if let Some(g) = &rule.redis {
        out.push(GrantView {
            name: "redis",
            kinds: &[ResourceKind::Redis],
            entries: g.users.clone(),
        });
    }
    if let Some(g) = &rule.mongo {
        out.push(GrantView {
            name: "mongo",
            kinds: &[ResourceKind::Mongodb],
            entries: g.roles.clone(),
        });
    }
    if let Some(g) = &rule.mq {
        out.push(GrantView {
            name: "mq",
            kinds: &[ResourceKind::Rabbitmq],
            entries: g.users.clone(),
        });
    }
    if let Some(g) = &rule.kafka {
        out.push(GrantView {
            name: "kafka",
            kinds: &[ResourceKind::Kafka],
            entries: g.users.clone(),
        });
    }
    if rule.tcp.is_some() {
        out.push(GrantView {
            name: "tcp",
            kinds: &[ResourceKind::Tcp],
            entries: vec![OPEN_ACCESS.to_owned()],
        });
    }
    out
}

/// Grants whose use is not recorded with a principal per session.
fn unassessable(rule: &Rule) -> Vec<&'static str> {
    let mut out = Vec::new();
    if rule.kube.is_some() {
        out.push("kubernetes");
    }
    if rule.search.is_some() {
        out.push("search");
    }
    if rule.web.is_some() {
        out.push("web");
    }
    out
}

/// Drop `gone` from one grant of `rule`; the whole grant when `all`.
fn cut(rule: &mut Rule, grant: &str, gone: &BTreeSet<String>, all: bool) {
    fn keep(list: &mut Vec<String>, gone: &BTreeSet<String>) {
        list.retain(|e| !gone.contains(e));
    }
    match grant {
        "ssh" if all => rule.ssh = None,
        "ssh" => rule.ssh.iter_mut().for_each(|g| keep(&mut g.logins, gone)),
        "db" if all => rule.db = None,
        "db" => rule.db.iter_mut().for_each(|g| keep(&mut g.roles, gone)),
        "redis" if all => rule.redis = None,
        "redis" => rule.redis.iter_mut().for_each(|g| keep(&mut g.users, gone)),
        "mongo" if all => rule.mongo = None,
        "mongo" => rule.mongo.iter_mut().for_each(|g| keep(&mut g.roles, gone)),
        "mq" if all => rule.mq = None,
        "mq" => rule.mq.iter_mut().for_each(|g| keep(&mut g.users, gone)),
        "kafka" if all => rule.kafka = None,
        "kafka" => rule.kafka.iter_mut().for_each(|g| keep(&mut g.users, gone)),
        "tcp" => rule.tcp = None,
        _ => {}
    }
}

fn rule_is_empty(rule: &Rule) -> bool {
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

/// Why a role is never judged, if it is not.
fn exempt(role: &RoleDoc, changed: Option<i64>, since: i64) -> Option<String> {
    let spec = &role.spec;
    if spec.break_glass {
        return Some("break-glass roles are never suggested".into());
    }
    if spec.request.is_some() {
        return Some(
            "a requestable role is used through grants, which sessions do not show".into(),
        );
    }
    if spec.is_shadow() {
        return Some("a shadow role grants nothing".into());
    }
    if role
        .metadata
        .labels
        .get(KEEP_LABEL)
        .is_some_and(|v| v == KEEP_VALUE)
    {
        return Some(format!("labelled {KEEP_LABEL}: {KEEP_VALUE}"));
    }
    if changed.is_some_and(|c| c > since) {
        return Some("changed inside the window (or its age is not known), so it has not had a full window of use".into());
    }
    None
}

/// What was used, by resource: the principals seen and when.
fn used_by_resource(
    rows: &[&UsageRow],
    kinds_of: &BTreeMap<&str, ResourceKind>,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut used: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for r in rows {
        let principal = if kinds_of.get(r.resource.as_str()) == Some(&ResourceKind::Tcp) {
            OPEN_ACCESS.to_owned()
        } else {
            r.principal.clone()
        };
        used.entry(r.resource.clone())
            .or_default()
            .insert(principal);
    }
    used
}

/// The resources a grant of `rule` reaches.
fn reached<'a>(policy: &'a Policy, rule: &Rule, g: &GrantView) -> Vec<&'a ResourceDoc> {
    policy
        .resources()
        .filter(|res| {
            selector_matches(&rule.resources, res) && g.kinds.contains(&resource_kind(res))
        })
        .collect()
}

/// Propose removals from the standing roles of `policy`.
///
/// # Errors
/// [`SuggestError`] when the window is out of range, Limen has not watched
/// for a whole window, or the safety check on the result fails.
#[allow(clippy::too_many_lines)]
pub fn suggest(policy: &Policy, input: &SuggestInput<'_>) -> Result<Suggestions, SuggestError> {
    let window = input.window_days;
    if !(MIN_WINDOW_DAYS..=MAX_WINDOW_DAYS).contains(&window) {
        return Err(SuggestError::Window(window));
    }
    let since = input.now_unix.saturating_sub(i64::from(window) * DAY);
    let watching = input.watching_since_unix.ok_or(SuggestError::NoHistory)?;
    if watching > since {
        let available = u32::try_from((input.now_unix - watching).max(0) / DAY).unwrap_or(0);
        return Err(SuggestError::ShortHistory {
            window_days: window,
            available_days: available,
        });
    }

    // Defence in depth: only what is inside the window counts.
    let rows: Vec<&UsageRow> = input
        .usage
        .iter()
        .filter(|r| r.sessions > 0 && r.last_used_unix >= since)
        .collect();
    let kinds_of: BTreeMap<&str, ResourceKind> = policy
        .resources()
        .map(|r| (r.metadata.name.as_str(), resource_kind(r)))
        .collect();
    let used_all = used_by_resource(&rows, &kinds_of);

    let mut out = Suggestions {
        window_days: window,
        policy_digest: policy.digest(),
        roles: Vec::new(),
        unused_roles: Vec::new(),
        kept: Vec::new(),
        not_assessed: Vec::new(),
        people: Vec::new(),
        people_truncated: false,
    };

    // Roles judged, and for each rule which grants could be told apart.
    let mut judged: BTreeSet<&str> = BTreeSet::new();
    for role in policy.roles() {
        let name = role.metadata.name.as_str();
        if let Some(reason) = exempt(role, input.role_changed_unix.get(name).copied(), since) {
            out.kept.push(Skipped {
                role: name.to_owned(),
                rule: None,
                reason,
            });
            continue;
        }
        judged.insert(name);
        let mut doc = role.clone();
        let mut changes = Vec::new();
        for (i, rule) in role.spec.allow.iter().enumerate() {
            let n = i + 1;
            let skip = |out: &mut Suggestions, reason: String| {
                out.not_assessed.push(Skipped {
                    role: name.to_owned(),
                    rule: Some(n),
                    reason,
                });
            };
            let other = unassessable(rule);
            if !other.is_empty() {
                skip(
                    &mut out,
                    format!("{} use is not recorded per session", other.join(" and ")),
                );
                continue;
            }
            let views = grants(rule);
            let mut rule_changes = Vec::new();
            let mut blocked = false;
            for g in &views {
                let res = reached(policy, rule, g);
                if res.is_empty() {
                    // Grants nothing today; nothing to learn from usage.
                    continue;
                }
                if let Some(new) = res.iter().find(|r| {
                    input
                        .resource_created_unix
                        .get(&r.metadata.name)
                        .is_some_and(|c| *c > since)
                }) {
                    skip(
                        &mut out,
                        format!(
                            "{} reaches `{}`, created inside the window (or its age is not known)",
                            g.name, new.metadata.name
                        ),
                    );
                    blocked = true;
                    break;
                }
                let mut used: BTreeSet<&String> = BTreeSet::new();
                for r in &res {
                    if let Some(p) = used_all.get(&r.metadata.name) {
                        used.extend(p.iter());
                    }
                }
                let unused: BTreeSet<String> = g
                    .entries
                    .iter()
                    .filter(|e| !used.contains(e))
                    .cloned()
                    .collect();
                if unused.is_empty() {
                    continue;
                }
                let all = unused.len() == g.entries.len();
                rule_changes.push((
                    g.name,
                    unused.clone(),
                    all,
                    Change {
                        rule: n,
                        action: if all {
                            Action::RemoveGrant
                        } else {
                            Action::RemovePrincipals
                        },
                        grant: g.name.to_owned(),
                        principals: unused.into_iter().collect(),
                        resources: res.iter().map(|r| r.metadata.name.clone()).collect(),
                    },
                ));
            }
            if blocked {
                continue;
            }
            // Apply to the working copy; the index is stable because rules
            // are only emptied here and dropped after the loop.
            for (grant, gone, all, change) in rule_changes {
                cut(&mut doc.spec.allow[i], grant, &gone, all);
                changes.push(change);
            }
        }
        if changes.is_empty() {
            continue;
        }
        doc.spec.allow.retain(|r| !rule_is_empty(r));
        if doc.spec.allow.is_empty() && doc.spec.deny.is_empty() {
            // A role needs a rule; it cannot be written back empty.
            out.unused_roles.push(name.to_owned());
            continue;
        }
        out.roles.push(RoleSuggestion {
            role: name.to_owned(),
            changes,
            document: doc,
        });
    }

    // People: standing roles a person holds and none of their sessions matched.
    let by_user = {
        let mut m: BTreeMap<&str, Vec<&UsageRow>> = BTreeMap::new();
        for r in &rows {
            m.entry(r.user.as_str()).or_default().push(r);
        }
        m
    };
    for (user, held) in input.people {
        let mine = by_user.get(user.as_str()).cloned().unwrap_or_default();
        let used = used_by_resource(&mine, &kinds_of);
        let mut unused_roles = Vec::new();
        for r in held {
            let Some(role) = policy.role(r) else { continue };
            if !judged.contains(role.metadata.name.as_str()) {
                continue;
            }
            // A role with any rule whose use cannot be told cannot be called unused.
            if role
                .spec
                .allow
                .iter()
                .any(|rule| !unassessable(rule).is_empty())
            {
                continue;
            }
            let was_used = role.spec.allow.iter().any(|rule| {
                grants(rule).iter().any(|g| {
                    reached(policy, rule, g).iter().any(|res| {
                        used.get(&res.metadata.name)
                            .is_some_and(|seen| g.entries.iter().any(|e| seen.contains(e)))
                    })
                })
            });
            if !was_used && !role.spec.allow.is_empty() {
                unused_roles.push(r.clone());
            }
        }
        if !unused_roles.is_empty() {
            if out.people.len() >= MAX_PEOPLE {
                out.people_truncated = true;
                break;
            }
            unused_roles.sort();
            unused_roles.dedup();
            out.people.push(PersonUnused {
                user: user.clone(),
                roles: unused_roles,
            });
        }
    }

    verify(policy, &out)?;
    Ok(out)
}

/// The suggested policy is rebuilt and may only lose access.
fn verify(policy: &Policy, s: &Suggestions) -> Result<(), SuggestError> {
    if s.roles.is_empty() {
        return Ok(());
    }
    let next = s.apply_to(policy).map_err(SuggestError::Unsafe)?;
    let diff = policy.access_diff(&next);
    if diff.widens() {
        return Err(SuggestError::Unsafe(
            "the effective-access diff shows gained access".into(),
        ));
    }
    Ok(())
}

impl Suggestions {
    /// `policy` with the suggested roles in place of the same-named ones.
    pub fn apply_to(&self, policy: &Policy) -> Result<Policy, String> {
        let changed: BTreeMap<&str, &RoleDoc> = self
            .roles
            .iter()
            .map(|r| (r.role.as_str(), &r.document))
            .collect();
        let docs = policy.documents().into_iter().map(|d| match d {
            Document::Role(r) => match changed.get(r.metadata.name.as_str()) {
                Some(new) => Document::Role((*new).clone()),
                None => Document::Role(r),
            },
            other => other,
        });
        Policy::from_stored_documents(docs).map_err(|e| e.to_string())
    }
}
