//! Questions to ask a policy (ADR-0028): who can reach this, what can they
//! reach, what changed in *effective access*, and why was I refused. All pure
//! functions over [`Policy`], so the CLI, the console, and the API share one
//! answer.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use limen_core::resource::ResourceKind;
use serde::{Deserialize, Serialize};

use crate::duration::DurationStr;
use crate::trace::summarize_role;
use crate::{AccessibleResource, Policy, RequestableResource};

/// How access is obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Via {
    /// A role mapped to the group (or held by the bot).
    Standing,
    /// By asking and being approved (ADR-0025).
    Request,
    /// Granted at once, with a reason, and reviewed after (ADR-0025).
    BreakGlass,
}

impl Via {
    fn suffix(self) -> &'static str {
        match self {
            Via::Standing => "",
            Via::Request => " (after a request is approved)",
            Via::BreakGlass => " (break-glass)",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "name", rename_all = "snake_case")]
pub enum Subject {
    Group(String),
    Bot(String),
    Role(String),
}

impl Subject {
    fn text(&self) -> String {
        match self {
            Subject::Group(g) => format!("group `{g}`"),
            Subject::Bot(b) => format!("bot `{b}`"),
            Subject::Role(r) => format!("role `{r}`"),
        }
    }
}

type Key = (Subject, String, Via);

/// Who reaches which resource, as which principals, and how.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveAccess {
    entries: BTreeMap<Key, (ResourceKind, BTreeSet<String>)>,
}

impl EffectiveAccess {
    /// The principals `subject` has on `resource` by `via`.
    #[must_use]
    pub fn principals(
        &self,
        subject: &Subject,
        resource: &str,
        via: Via,
    ) -> Option<&BTreeSet<String>> {
        self.entries
            .get(&(subject.clone(), resource.to_owned(), via))
            .map(|(_, p)| p)
    }

    fn add(
        &mut self,
        subject: &Subject,
        via: Via,
        res: &AccessibleResource,
        only: Option<&BTreeSet<String>>,
    ) {
        let principals: BTreeSet<String> = res
            .principals
            .iter()
            .filter(|p| only.is_none_or(|o| !o.contains(*p)))
            .cloned()
            .collect();
        if principals.is_empty() {
            return;
        }
        self.entries.insert(
            (subject.clone(), res.name.clone(), via),
            (res.kind, principals),
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Gain,
    Loss,
}

/// One line of an access diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessChange {
    pub change: ChangeKind,
    pub subject: Subject,
    pub resource: String,
    pub kind: ResourceKind,
    pub via: Via,
    pub principals: Vec<String>,
}

impl AccessChange {
    #[must_use]
    pub fn text(&self) -> String {
        format!(
            "{} {} {} access to `{}` as {}{}",
            self.subject.text(),
            match self.change {
                ChangeKind::Gain => "gains",
                ChangeKind::Loss => "loses",
            },
            self.kind.as_str(),
            self.resource,
            self.principals.join(", "),
            self.via.suffix()
        )
    }
}

/// What changes in effective access going from one policy to another.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessDiff {
    /// Documents added, removed, or changed (the YAML-level diff).
    pub documents: crate::PolicyDiff,
    pub changes: Vec<AccessChange>,
}

impl AccessDiff {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.documents.is_empty() && self.changes.is_empty()
    }

    /// Whether anyone gained access to anything.
    #[must_use]
    pub fn widens(&self) -> bool {
        self.changes.iter().any(|c| c.change == ChangeKind::Gain)
    }

    /// Whether anyone gained *standing* access (not just the right to ask).
    #[must_use]
    pub fn widens_standing(&self) -> bool {
        self.changes
            .iter()
            .any(|c| c.change == ChangeKind::Gain && c.via == Via::Standing)
    }

    /// Plain text, one change per line.
    #[must_use]
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        for c in &self.changes {
            let _ = writeln!(
                out,
                "{} {}",
                if c.change == ChangeKind::Gain {
                    "+"
                } else {
                    "-"
                },
                c.text()
            );
        }
        if self.changes.is_empty() {
            out.push_str("No change in effective access.\n");
        }
        for (label, docs) in [
            ("added", &self.documents.added),
            ("removed", &self.documents.removed),
            ("changed", &self.documents.changed),
        ] {
            if !docs.is_empty() {
                let _ = writeln!(out, "documents {label}: {}", docs.join(", "));
            }
        }
        out
    }

    /// Markdown for a pull request comment.
    #[must_use]
    pub fn render_markdown(&self) -> String {
        let mut out = String::from("### Limen policy: effective access\n\n");
        let section =
            |out: &mut String, title: &str, kind: ChangeKind, subject: fn(&Subject) -> bool| {
                let rows: Vec<&AccessChange> = self
                    .changes
                    .iter()
                    .filter(|c| c.change == kind && subject(&c.subject))
                    .collect();
                if rows.is_empty() {
                    return;
                }
                let _ = writeln!(out, "**{title}**\n");
                for c in rows {
                    let _ = writeln!(out, "- {}", c.text());
                }
                out.push('\n');
            };
        let people = |s: &Subject| !matches!(s, Subject::Role(_));
        let roles = |s: &Subject| matches!(s, Subject::Role(_));
        section(
            &mut out,
            ":warning: Access gained",
            ChangeKind::Gain,
            people,
        );
        section(&mut out, "Access removed", ChangeKind::Loss, people);
        section(&mut out, "Roles that reach more", ChangeKind::Gain, roles);
        section(&mut out, "Roles that reach less", ChangeKind::Loss, roles);
        if self.changes.is_empty() {
            out.push_str("No change in who can reach what.\n\n");
        }
        let docs = &self.documents;
        if !docs.is_empty() {
            let _ = writeln!(
                out,
                "<sub>Documents: {} added, {} removed, {} changed.</sub>",
                docs.added.len(),
                docs.removed.len(),
                docs.changed.len()
            );
        }
        out
    }
}

/// One way a resource is reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhoCanEntry {
    pub role: String,
    pub via: Via,
    pub principals: Vec<String>,
    /// IdP groups that hold the role (or may ask for it).
    pub groups: Vec<String>,
    pub bots: Vec<String>,
    /// Who approves, for a requestable role.
    pub approvers: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhatCan {
    pub standing: Vec<AccessibleResource>,
    pub requestable: Vec<RequestableResource>,
}

impl Policy {
    /// Every `(who, resource)` pair the policy opens, by group, bot, and role.
    #[must_use]
    pub fn effective_access(&self) -> EffectiveAccess {
        let mut access = EffectiveAccess::default();
        let mut groups: BTreeSet<&String> = self.group_roles.keys().collect();
        for role in self.requestable_roles() {
            if let Some(q) = &role.spec.request {
                groups.extend(q.who.iter());
            }
        }
        for group in groups {
            let standing: Vec<String> = self
                .group_roles
                .get(group)
                .map(|r| r.iter().cloned().collect())
                .unwrap_or_default();
            let held: BTreeMap<String, AccessibleResource> = self
                .accessible(&standing)
                .into_iter()
                .map(|r| (r.name.clone(), r))
                .collect();
            let subject = Subject::Group(group.clone());
            for res in held.values() {
                access.add(&subject, Via::Standing, res, None);
            }
            for role in self.requestable_roles() {
                let name = &role.metadata.name;
                let asks = role
                    .spec
                    .request
                    .as_ref()
                    .is_some_and(|q| q.who.contains(group));
                if !asks || standing.contains(name) {
                    continue;
                }
                let via = if role.spec.break_glass {
                    Via::BreakGlass
                } else {
                    Via::Request
                };
                let mut with: Vec<String> = standing.clone();
                with.push(name.clone());
                for res in self.accessible(&with) {
                    let already = held
                        .get(&res.name)
                        .map(|h| h.principals.iter().cloned().collect());
                    access.add(&subject, via, &res, already.as_ref());
                }
            }
        }
        for bot in self.bots() {
            let subject = Subject::Bot(bot.metadata.name.clone());
            for res in self.accessible(&bot.spec.roles) {
                access.add(&subject, Via::Standing, &res, None);
            }
        }
        for role in self.roles.values() {
            let subject = Subject::Role(role.metadata.name.clone());
            for res in self.accessible(std::slice::from_ref(&role.metadata.name)) {
                access.add(&subject, Via::Standing, &res, None);
            }
        }
        access
    }

    /// What changes in effective access going from `self` to `next`.
    #[must_use]
    pub fn access_diff(&self, next: &Policy) -> AccessDiff {
        let (old, new) = (self.effective_access(), next.effective_access());
        let mut changes = Vec::new();
        let keys: BTreeSet<&Key> = old.entries.keys().chain(new.entries.keys()).collect();
        for key in keys {
            let before = old.entries.get(key);
            let after = new.entries.get(key);
            let empty = BTreeSet::new();
            let (b, a) = (
                before.map_or(&empty, |e| &e.1),
                after.map_or(&empty, |e| &e.1),
            );
            let kind = after.or(before).map_or(ResourceKind::Ssh, |e| e.0);
            for (change, principals) in [
                (ChangeKind::Gain, a.difference(b)),
                (ChangeKind::Loss, b.difference(a)),
            ] {
                let mut principals: Vec<String> = principals.cloned().collect();
                if change == ChangeKind::Loss && key.2 != Via::Standing {
                    // Asking became unnecessary because the access is now
                    // standing: not a loss.
                    if let Some(standing) = new.principals(&key.0, &key.1, Via::Standing) {
                        principals.retain(|p| !standing.contains(p));
                    }
                }
                if !principals.is_empty() {
                    changes.push(AccessChange {
                        change,
                        subject: key.0.clone(),
                        resource: key.1.clone(),
                        kind,
                        via: key.2,
                        principals,
                    });
                }
            }
        }
        AccessDiff {
            documents: self.diff(next),
            changes,
        }
    }

    /// Every role that reaches `resource`, and who holds or may ask for it.
    #[must_use]
    pub fn who_can(&self, resource: &str) -> Vec<WhoCanEntry> {
        let mut out = Vec::new();
        for role in self.roles.values() {
            let name = &role.metadata.name;
            let Some(res) = self
                .accessible(std::slice::from_ref(name))
                .into_iter()
                .find(|r| r.name == resource)
            else {
                continue;
            };
            let mapped: Vec<String> = self
                .group_roles
                .iter()
                .filter(|(_, roles)| roles.contains(name))
                .map(|(g, _)| g.clone())
                .collect();
            let bots: Vec<String> = self
                .bots()
                .filter(|b| b.spec.roles.contains(name))
                .map(|b| b.metadata.name.clone())
                .collect();
            if !mapped.is_empty() || !bots.is_empty() {
                out.push(WhoCanEntry {
                    role: name.clone(),
                    via: Via::Standing,
                    principals: res.principals.clone(),
                    groups: mapped,
                    bots,
                    approvers: Vec::new(),
                });
            }
            if let Some(q) = &role.spec.request {
                out.push(WhoCanEntry {
                    role: name.clone(),
                    via: if role.spec.break_glass {
                        Via::BreakGlass
                    } else {
                        Via::Request
                    },
                    principals: res.principals.clone(),
                    groups: q.who.clone(),
                    bots: Vec::new(),
                    approvers: q
                        .approvers
                        .iter()
                        .cloned()
                        .chain(q.approver_users.iter().map(|u| format!("user {u}")))
                        .collect(),
                });
            }
            // A role nobody holds or may ask for reaches nothing: left out.
        }
        out
    }

    /// What a member of `groups`, or the bot `bot`, can reach and could ask for.
    pub fn what_can(&self, groups: &[String], bot: Option<&str>) -> Result<WhatCan, String> {
        let mut held: BTreeSet<String> = self
            .roles_for_groups(groups.iter().map(String::as_str), &[])
            .into_iter()
            .collect();
        if let Some(b) = bot {
            let doc = self.bot(b).ok_or_else(|| format!("no bot named {b}"))?;
            held.extend(doc.spec.roles.iter().cloned());
        }
        let held: Vec<String> = held.into_iter().collect();
        let eligible: Vec<String> = self
            .requestable_roles_for_groups(groups.iter().map(String::as_str))
            .into_iter()
            .collect();
        Ok(WhatCan {
            standing: self.accessible(&held),
            requestable: self.requestable_resources(&held, &eligible),
        })
    }

    /// Why a user can't reach `resource`, in words that name no resource
    /// facts. A resource that exists but is hidden from them answers exactly
    /// like one that doesn't (ADR-0028). The caller adds locks and grants,
    /// which live outside the policy.
    #[must_use]
    pub fn explain_for_user(
        &self,
        held: &[String],
        eligible: &[String],
        resource: &str,
        principal: Option<&crate::Principal>,
    ) -> Vec<String> {
        let reachable = self
            .accessible(held)
            .into_iter()
            .find(|r| r.name == resource);
        let requestable = self
            .requestable_resources(held, eligible)
            .into_iter()
            .find(|r| r.name == resource);
        let mut lines = Vec::new();
        if let Some(res) = reachable {
            lines.push(format!("You can reach `{resource}`."));
            lines.push(format!(
                "Principals you may use: {}.",
                res.principals.join(", ")
            ));
            if let Some(p) = principal {
                let ok = self.evaluate(&crate::AccessRequest {
                    roles: held,
                    resource,
                    principal: p.clone(),
                });
                if !ok.is_allowed() {
                    lines.push(format!(
                        "But not as {}: use one of the principals above.",
                        crate::trace::describe_principal(p)
                    ));
                }
            }
            return lines;
        }
        if let Some(req) = requestable {
            lines.push(format!(
                "You can't reach `{resource}` yet, but you can ask for it."
            ));
            lines.push(format!("Request one of: {}.", req.roles.join(", ")));
            // Who approves: the requester is eligible for these roles, and
            // knowing whom to ping is the point (ADR-0025).
            for name in &req.roles {
                if let Some(line) = self.how_granted(name) {
                    lines.push(format!("  - `{name}`: {line}"));
                }
            }
            lines.push(self.request_command(resource, &req.roles));
            return lines;
        }
        // The same words whether the resource is missing or hidden.
        lines.push(format!(
            "No role you hold grants access to `{resource}`, or it does not exist."
        ));
        if held.is_empty() {
            lines.push("You hold no roles.".to_owned());
        }
        for name in held {
            match self.roles.get(name) {
                Some(role) => {
                    lines.push(format!("Your role `{name}` allows:"));
                    for line in summarize_role(role) {
                        lines.push(format!("  - {line}"));
                    }
                }
                None => lines.push(format!("Your role `{name}` is not in the policy.")),
            }
        }
        if !eligible.is_empty() {
            lines.push(format!("Roles you may request: {}.", eligible.join(", ")));
        }
        lines
    }

    /// How a requestable role is granted, for its requester: who approves, or
    /// that it is break-glass.
    fn how_granted(&self, role: &str) -> Option<String> {
        let doc = self.roles.get(role)?;
        let spec = doc.spec.request.as_ref()?;
        if doc.spec.break_glass {
            return Some(
                "break-glass: granted at once with a reason, and reviewed afterwards".to_owned(),
            );
        }
        let mut who: Vec<String> = spec
            .approvers
            .iter()
            .map(|g| format!("members of {g}"))
            .collect();
        who.extend(spec.approver_users.iter().cloned());
        // Validation requires an approver for every role that isn't break-glass.
        let who = who.join(" or ");
        Some(if spec.approvals_required > 1 {
            format!("{} approvals from {who}", spec.approvals_required)
        } else {
            format!("approved by {who}")
        })
    }

    /// The command that asks for `resource`: an ordinary request when one of
    /// `roles` takes approval, break-glass only when nothing else reaches it.
    /// The duration never exceeds the role's own limit, so the command works as printed.
    fn request_command(&self, resource: &str, roles: &[String]) -> String {
        let break_glass = |r: &&String| self.roles.get(*r).is_some_and(|d| d.spec.break_glass);
        let ordinary: Vec<&String> = roles.iter().filter(|r| !break_glass(r)).collect();
        let for_flag = |role: &str| {
            let thirty = DurationStr(std::time::Duration::from_mins(30));
            let limit = self
                .roles
                .get(role)
                .and_then(|d| d.spec.request.as_ref())
                .and_then(|r| r.max_duration);
            format!("--for {}", limit.map_or(thirty, |l| l.min(thirty)))
        };
        match ordinary.as_slice() {
            [] => {
                // Several break-glass roles need the one to ask for named.
                let role = match roles {
                    [first, _, ..] => format!(" --role {first}"),
                    _ => String::new(),
                };
                format!("Run: limen request {resource} --break-glass{role} --reason \"...\"")
            }
            [only] => format!(
                "Run: limen request {resource} {} --reason \"...\"",
                for_flag(only)
            ),
            [first, ..] => format!(
                "Run: limen request {resource} --role {first} {} --reason \"...\"",
                for_flag(first)
            ),
        }
    }
}
