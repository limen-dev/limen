//! Replay recorded sessions against a policy change (ADR-0049).
//!
//! The same decision code as enforcement: every record is turned into an
//! [`AccessRequest`] and answered by [`Policy::evaluate_eligible`] under the
//! active policy and under the proposed one. A session is *affected* only when
//! the active policy allows it and the proposed one does not. Records the
//! active policy already refuses are counted apart (`already_refused`): they
//! mean the reconstruction differs from what happened, not that the change
//! hurts anyone.
//!
//! The functions here are pure. The control plane reads the recorded sessions,
//! users and grants and hands them in as [`ReplayRecord`]s.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::trace::describe_principal;
use crate::{AccessRequest, Decision, Policy, Principal};

/// Who held the roles, as far as the record shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Holder {
    /// A person: roles come from their IdP groups through each policy.
    Person { groups: Vec<String> },
    /// A bot: roles come from its bot document in each policy.
    Bot { name: String },
}

/// One group of recorded sessions that share who, what and as whom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayRecord {
    pub user: String,
    pub holder: Holder,
    pub resource: String,
    pub principal: Principal,
    /// Roles the sessions got from approved access requests on this resource
    /// (ADR-0025), already limited to it. Added to the policy's own roles
    /// under both policies, as enforcement does.
    pub granted_roles: Vec<String>,
    pub sessions: u64,
    pub first_unix: i64,
    pub last_unix: i64,
}

/// What a policy says about a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Allow,
    /// Nothing held reaches it, but a role the person may ask for does.
    NeedsRequest,
    Deny,
}

impl Outcome {
    #[must_use]
    pub fn text(self) -> &'static str {
        match self {
            Outcome::Allow => "allowed",
            Outcome::NeedsRequest => "only by request",
            Outcome::Deny => "denied",
        }
    }
}

impl From<&Decision> for Outcome {
    fn from(d: &Decision) -> Self {
        match d {
            Decision::Allow { .. } => Outcome::Allow,
            Decision::RequiresApproval { .. } => Outcome::NeedsRequest,
            // Anything else, including variants added later, is a refusal.
            _ => Outcome::Deny,
        }
    }
}

/// A group of sessions the change would have refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Affected {
    pub user: String,
    pub bot: bool,
    pub resource: String,
    /// The upstream identity, as a sentence ("login ubuntu").
    pub principal: String,
    pub sessions: u64,
    pub first_unix: i64,
    pub last_unix: i64,
    /// What the proposed policy says instead of "allowed".
    pub now: Outcome,
    /// The resource's labels changed inside the window, so the answer rests
    /// on today's labels (ADR-0049, option A).
    pub labels_changed: bool,
}

/// A shadow rule (ADR-0046) of the proposed policy that would have fired.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowHit {
    /// `role/rule`.
    pub rule: String,
    pub sessions: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayReport {
    pub window_days: u32,
    /// Sessions that were replayed (not the skipped ones).
    pub examined: u64,
    /// Allowed before and after.
    pub unchanged: u64,
    /// The active policy already refuses these today: not caused by the change.
    pub already_refused: u64,
    pub affected_sessions: u64,
    pub affected: Vec<Affected>,
    pub shadow: Vec<ShadowHit>,
    /// Sessions that could not be replayed, by reason.
    pub skipped: BTreeMap<String, u64>,
    /// More groups matched than were replayed.
    pub truncated: bool,
}

impl ReplayReport {
    /// People and bots with at least one affected session.
    #[must_use]
    pub fn affected_users(&self) -> (usize, usize) {
        let people: BTreeSet<&str> = self
            .affected
            .iter()
            .filter(|a| !a.bot)
            .map(|a| a.user.as_str())
            .collect();
        let bots: BTreeSet<&str> = self
            .affected
            .iter()
            .filter(|a| a.bot)
            .map(|a| a.user.as_str())
            .collect();
        (people.len(), bots.len())
    }

    /// Note sessions that were not replayed.
    pub fn skip(&mut self, reason: &str, sessions: u64) {
        if sessions > 0 {
            *self.skipped.entry(reason.to_owned()).or_default() += sessions;
        }
    }

    #[must_use]
    pub fn skipped_total(&self) -> u64 {
        self.skipped.values().sum()
    }

    /// The headline, such as "would have refused 14 sessions by 3 people and
    /// 1 bot". Never says "nothing" without the numbers behind it.
    #[must_use]
    pub fn headline(&self) -> String {
        let (people, bots) = self.affected_users();
        let looked = format!(
            "{} sessions replayed over {} days, {} not replayable",
            self.examined,
            self.window_days,
            self.skipped_total()
        );
        if self.affected_sessions == 0 {
            return format!("No replayed session would have been refused ({looked}).");
        }
        let who = match (people, bots) {
            (p, 0) => format!("{p} {}", plural(p as u64, "person", "people")),
            (0, b) => format!("{b} {}", plural(b as u64, "bot", "bots")),
            (p, b) => format!(
                "{p} {} and {b} {}",
                plural(p as u64, "person", "people"),
                plural(b as u64, "bot", "bots")
            ),
        };
        format!(
            "Would have refused {} {} by {who} ({looked}).",
            self.affected_sessions,
            plural(self.affected_sessions, "session", "sessions"),
        )
    }

    /// Plain text, one line per fact.
    #[must_use]
    pub fn render_text(&self) -> String {
        let mut out = vec![self.headline()];
        if self.truncated {
            out.push("This is partial: more session groups matched than were replayed.".into());
        }
        for a in &self.affected {
            out.push(format!(
                "  {}{} {} on {}: {} {}, now {}{}",
                plain(&a.user),
                if a.bot { " (bot)" } else { "" },
                plain(&a.principal),
                plain(&a.resource),
                a.sessions,
                plural(a.sessions, "session", "sessions"),
                a.now.text(),
                if a.labels_changed {
                    " (labels changed in the window)"
                } else {
                    ""
                },
            ));
        }
        for s in &self.shadow {
            out.push(format!(
                "  shadow rule {} would have fired for {} sessions",
                plain(&s.rule),
                s.sessions
            ));
        }
        if self.already_refused > 0 {
            out.push(format!(
                "{} sessions are refused by the active policy today already (groups or roles changed since): not caused by this change.",
                self.already_refused
            ));
        }
        for (reason, n) in &self.skipped {
            out.push(format!("{n} sessions not replayed: {reason}"));
        }
        out.push(CAVEAT.into());
        out.join("\n")
    }

    /// Markdown for a pull request comment.
    #[must_use]
    pub fn render_markdown(&self) -> String {
        let mut out = format!("### Replay of recorded sessions\n\n{}\n\n", self.headline());
        if self.truncated {
            out.push_str("_Partial: more session groups matched than were replayed._\n\n");
        }
        if !self.affected.is_empty() {
            out.push_str("| Who | As | Resource | Sessions | Now |\n|---|---|---|---|---|\n");
            for a in &self.affected {
                let _ = writeln!(
                    out,
                    "| {}{} | {} | {} | {} | {}{} |",
                    md(&a.user),
                    if a.bot { " (bot)" } else { "" },
                    md(&a.principal),
                    md(&a.resource),
                    a.sessions,
                    a.now.text(),
                    if a.labels_changed {
                        " ⚠ labels changed"
                    } else {
                        ""
                    },
                );
            }
            out.push('\n');
        }
        for s in &self.shadow {
            let _ = writeln!(
                out,
                "- shadow rule `{}` would have fired for {} sessions",
                md(&s.rule),
                s.sessions
            );
        }
        if self.already_refused > 0 {
            let _ = writeln!(
                out,
                "- {} sessions are already refused by the active policy (not caused by this change)",
                self.already_refused
            );
        }
        for (reason, n) in &self.skipped {
            let _ = writeln!(out, "- {n} sessions not replayed: {}", md(reason));
        }
        let _ = writeln!(out, "\n_{CAVEAT}_");
        out
    }
}

/// Printed with every report: what the replay rests on.
pub const CAVEAT: &str = "Approximate: roles use each person's latest IdP groups and resource labels are today's, not those of the time. Only allowed sessions are recorded, so this shows narrowing; `policy diff` shows widening.";

fn plural(n: u64, one: &'static str, many: &'static str) -> &'static str {
    if n == 1 { one } else { many }
}

/// Text for a terminal: control characters (an ANSI escape in a name) become
/// spaces. Names come from recorded sessions, so they are not trusted.
fn plain(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// Escape what a table cell cannot hold. Names and logins come from policy
/// and from recorded sessions, so they are not trusted in a comment.
fn md(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '|' | '`' | '*' | '_' | '<' | '>' | '[' | ']' | '\\' | '!' | '&' => {
                format!("\\{c}")
            }
            c if c.is_control() => " ".to_owned(),
            c => c.to_string(),
        })
        .collect()
}

/// Why a recorded session could not become a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreplayable {
    Kubernetes,
    UnknownKind,
    NoPrincipal,
    NoDatabase,
}

impl Unreplayable {
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Unreplayable::Kubernetes => {
                "Kubernetes sessions record no group, so they are not replayed"
            }
            Unreplayable::UnknownKind => "session kind not supported by replay",
            Unreplayable::NoPrincipal => "the session recorded no upstream identity",
            Unreplayable::NoDatabase => "the session predates recording the database",
        }
    }
}

/// The inverse of the proxy's mapping from request to `session.start`.
/// `kind` is the resource kind the proxy recorded, `upstream` the `login`,
/// `redis_user`, `mongo_role`, `mq_user` or `kafka_user` it wrote, and
/// `database` the database it resolved.
pub fn principal_from_session(
    kind: &str,
    upstream: Option<&str>,
    database: Option<&str>,
) -> Result<Principal, Unreplayable> {
    let need = || {
        upstream
            .filter(|u| !u.is_empty())
            .map(str::to_owned)
            .ok_or(Unreplayable::NoPrincipal)
    };
    let db = || {
        database
            .filter(|d| !d.is_empty())
            .map(str::to_owned)
            .ok_or(Unreplayable::NoDatabase)
    };
    Ok(match kind {
        "ssh" => Principal::SshLogin(need()?),
        "postgres" | "mysql" | "redshift" => Principal::DbRole {
            role: need()?,
            database: db()?,
        },
        "mongodb" => Principal::MongoRole {
            role: need()?,
            database: db()?,
        },
        "redis" => Principal::RedisUser(need()?),
        "opensearch" | "elasticsearch" => Principal::SearchRole(need()?),
        "rabbitmq" => Principal::MqUser(need()?),
        "kafka" => Principal::KafkaUser(need()?),
        "web" => Principal::WebAccess,
        "tcp" => Principal::TcpAccess,
        "kubernetes" | "kube" => return Err(Unreplayable::Kubernetes),
        _ => return Err(Unreplayable::UnknownKind),
    })
}

impl Policy {
    /// The roles a record holds under this policy: the policy's own for the
    /// holder, plus roles granted for the resource.
    fn replay_roles(
        &self,
        record: &ReplayRecord,
        bootstrap_admin_groups: &[String],
    ) -> (Vec<String>, Vec<String>) {
        let (mut roles, eligible): (BTreeSet<String>, BTreeSet<String>) = match &record.holder {
            Holder::Person { groups } => (
                self.roles_for_groups(groups.iter().map(String::as_str), bootstrap_admin_groups),
                self.requestable_roles_for_groups(groups.iter().map(String::as_str)),
            ),
            Holder::Bot { name } => (
                self.bot(name)
                    .map(|b| b.spec.roles.iter().cloned().collect())
                    .unwrap_or_default(),
                BTreeSet::new(),
            ),
        };
        roles.extend(record.granted_roles.iter().cloned());
        (roles.into_iter().collect(), eligible.into_iter().collect())
    }

    /// What this policy says about a record: [`Policy::evaluate_eligible`]
    /// on the roles the holder has under it.
    #[must_use]
    pub fn replay_decision(
        &self,
        record: &ReplayRecord,
        bootstrap_admin_groups: &[String],
    ) -> Decision {
        let (roles, eligible) = self.replay_roles(record, bootstrap_admin_groups);
        self.evaluate_eligible(
            &AccessRequest {
                roles: &roles,
                resource: &record.resource,
                principal: record.principal.clone(),
            },
            &eligible,
        )
    }

    /// Replay `records` under `self` (the active policy) and `proposed`.
    /// `relabeled` names resources whose labels changed in the window.
    #[must_use]
    pub fn replay(
        &self,
        proposed: &Policy,
        records: &[ReplayRecord],
        bootstrap_admin_groups: &[String],
        relabeled: &BTreeSet<String>,
    ) -> ReplayReport {
        let mut report = ReplayReport::default();
        let mut shadow: BTreeMap<String, u64> = BTreeMap::new();
        for record in records {
            report.examined += record.sessions;
            let before = self.replay_decision(record, bootstrap_admin_groups);
            if !before.is_allowed() {
                report.already_refused += record.sessions;
                continue;
            }
            let after = proposed.replay_decision(record, bootstrap_admin_groups);
            if after.is_allowed() {
                report.unchanged += record.sessions;
                let (roles, _) = proposed.replay_roles(record, bootstrap_admin_groups);
                let req = AccessRequest {
                    roles: &roles,
                    resource: &record.resource,
                    principal: record.principal.clone(),
                };
                for m in proposed.shadow_denies(&req) {
                    *shadow.entry(format!("{}/{}", m.role, m.rule)).or_default() += record.sessions;
                }
                continue;
            }
            report.affected_sessions += record.sessions;
            report.affected.push(Affected {
                user: record.user.clone(),
                bot: matches!(record.holder, Holder::Bot { .. }),
                resource: record.resource.clone(),
                principal: describe_principal(&record.principal),
                sessions: record.sessions,
                first_unix: record.first_unix,
                last_unix: record.last_unix,
                now: Outcome::from(&after),
                labels_changed: relabeled.contains(&record.resource),
            });
        }
        report.affected.sort_by(|a, b| {
            b.sessions
                .cmp(&a.sessions)
                .then_with(|| a.user.cmp(&b.user))
        });
        report.shadow = shadow
            .into_iter()
            .map(|(rule, sessions)| ShadowHit { rule, sessions })
            .collect();
        report
    }
}
