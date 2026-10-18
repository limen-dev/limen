//! `mongo.command` and `mongo.command.end` events (ADR-0035).

use std::time::Instant;

use limen_audit::{AuditError, Context, Emitter, EventKind};
use serde_json::{Value, json};
use uuid::Uuid;

use super::redact::Summary;
use super::reply::ReplyInfo;
use super::rules::{Inspected, Refusal};

/// Longest error message kept (only with `full_commands`).
const MAX_ERROR: usize = 4096;
/// Names a client chooses are cut before they reach the trail.
const MAX_NAME: usize = 64;

/// How a command ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    Error,
    /// `moreToCome`: the client asked for no answer.
    Unacknowledged,
    /// The session ended before the server answered.
    NotCompleted,
}

impl Status {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Error => "error",
            Status::Unacknowledged => "unacknowledged",
            Status::NotCompleted => "not_completed",
        }
    }
}

/// Writes the audit events of one MongoDB session.
#[derive(Debug, Clone)]
pub struct Auditor {
    emitter: Emitter,
    ctx: Context,
    resource: String,
    role: String,
    flavor: &'static str,
    actor_type: &'static str,
    full: bool,
}

fn clip(s: &str) -> &str {
    if s.len() <= MAX_NAME {
        return s;
    }
    let mut end = MAX_NAME;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

impl Auditor {
    #[must_use]
    pub fn new(
        emitter: Emitter,
        session_id: Uuid,
        username: &str,
        resource: &str,
        role: &str,
        flavor: &'static str,
        full: bool,
    ) -> Self {
        Self {
            emitter,
            ctx: Context {
                user: Some(username.to_owned()),
                session_id: Some(session_id),
            },
            resource: resource.to_owned(),
            role: role.to_owned(),
            flavor,
            actor_type: limen_core::identity::actor_type(username),
            full,
        }
    }

    #[must_use]
    pub fn full(&self) -> bool {
        self.full
    }

    fn base(&self, phase: &str) -> Value {
        json!({
            "protocol": "mongodb",
            "phase": phase,
            "actor_type": self.actor_type,
            "resource": self.resource,
            "mongo_role": self.role,
            "flavor": self.flavor,
        })
    }

    /// Record a command *before* it is forwarded. An error means the command
    /// must not run (fail closed).
    pub async fn command(
        &self,
        command: &Inspected<'_>,
        summary: &Summary,
        request_id: i32,
        unacknowledged: bool,
    ) -> Result<Uuid, AuditError> {
        let mut data = self.base("forward");
        data["command"] = json!(clip(command.name));
        data["database"] = json!(clip(command.database));
        if let Some(c) = command.collection {
            data["collection"] = json!(clip(c));
        }
        data["summary"] = json!(summary.text);
        if summary.truncated {
            data["summary_truncated"] = json!(true);
        }
        data["redacted"] = json!(!self.full);
        data["request_id"] = json!(request_id);
        if unacknowledged {
            data["unacknowledged"] = json!(true);
        }
        self.emitter
            .emit(EventKind::MongoCommand, self.ctx.clone(), data)
            .await
    }

    /// Record a command the worker refused.
    pub async fn refused(
        &self,
        name: &str,
        database: &str,
        refusal: &Refusal,
        request_id: i32,
    ) -> Result<Uuid, AuditError> {
        let mut data = self.base("refused");
        data["command"] = json!(clip(name));
        data["database"] = json!(clip(database));
        data["reason"] = json!(refusal.reason);
        data["error_code"] = json!(refusal.code);
        data["request_id"] = json!(request_id);
        self.emitter
            .emit(EventKind::MongoCommand, self.ctx.clone(), data)
            .await
    }

    /// How a forwarded command ended.
    pub async fn finished(
        &self,
        command_id: Uuid,
        started: Instant,
        status: Status,
        reply: Option<&ReplyInfo>,
    ) -> Result<(), AuditError> {
        let mut data = self.base("end");
        if let Some(m) = data.as_object_mut() {
            m.remove("phase");
        }
        data["command_id"] = json!(command_id);
        data["status"] = json!(status.as_str());
        data["duration_ms"] =
            json!(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));
        if let Some(r) = reply {
            if let Some(docs) = r.docs {
                data["docs"] = json!(docs);
            }
            if let Some(code) = r.code {
                data["error_code"] = json!(code);
            }
            if let Some(name) = &r.code_name {
                data["error_code_name"] = json!(name);
            }
            if r.write_errors > 0 {
                data["write_errors"] = json!(r.write_errors);
            }
            // Error messages quote the data ("dup key: { email: ... }"), so they
            // are kept only when the resource keeps values.
            if self.full
                && let Some(m) = &r.message
            {
                data["error"] = json!(m.chars().take(MAX_ERROR).collect::<String>());
            }
        }
        self.emitter
            .emit(EventKind::MongoCommandEnd, self.ctx.clone(), data)
            .await
            .map(|_| ())
    }
}
