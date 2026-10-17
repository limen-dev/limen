//! `db.query` and `db.query.end` events (ADR-0033 section 5).

use std::time::Instant;

use limen_audit::{AuditError, Context, Emitter, EventKind};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::Engine;
use super::sqltext::{self, Flavor, Statement};

/// Longest statement text stored in one event.
const MAX_TEXT: usize = 256 * 1024;
/// Execute events repeat the statement text only when it is short.
const MAX_REPEAT_TEXT: usize = 4 * 1024;

/// What the end event reports for a statement.
#[derive(Debug, Default, Clone)]
pub struct Outcome {
    pub rows: Option<u64>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    /// MySQL's own error number (the SQLSTATE is in `error_code`).
    pub error_number: Option<u32>,
    /// When the target said it was done.
    pub finished: Option<Instant>,
}

/// How a statement was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Simple,
    Parse,
    Execute,
    FunctionCall,
    Cancel,
    /// A command the worker refused to forward.
    Refused,
}

impl Phase {
    fn as_str(self) -> &'static str {
        match self {
            Phase::Simple => "simple",
            Phase::Parse => "parse",
            Phase::Execute => "execute",
            Phase::FunctionCall => "function_call",
            Phase::Cancel => "cancel",
            Phase::Refused => "refused",
        }
    }
}

/// Writes the audit events of one database session.
#[derive(Debug, Clone)]
pub struct Auditor {
    emitter: Emitter,
    ctx: Context,
    engine: Engine,
    resource: String,
    db_role: String,
    database: String,
    actor_type: &'static str,
    normalize: bool,
}

impl Auditor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        emitter: Emitter,
        session_id: Uuid,
        username: &str,
        resource: &str,
        engine: Engine,
        db_role: &str,
        database: &str,
        normalize: bool,
    ) -> Self {
        Self {
            emitter,
            ctx: Context {
                user: Some(username.to_owned()),
                session_id: Some(session_id),
            },
            engine,
            resource: resource.to_owned(),
            db_role: db_role.to_owned(),
            database: database.to_owned(),
            actor_type: limen_core::identity::actor_type(username),
            normalize,
        }
    }

    pub fn flavor(&self) -> Flavor {
        match self.engine {
            Engine::Mysql => Flavor::Mysql,
            Engine::Postgres | Engine::Redshift => Flavor::Postgres,
        }
    }

    fn base(&self, phase: Phase) -> Value {
        json!({
            "protocol": self.engine.as_str(),
            "phase": phase.as_str(),
            "actor_type": self.actor_type,
            "resource": self.resource,
            "db_role": self.db_role,
            "database": self.database,
        })
    }

    /// Record a statement *before* it is forwarded. An error means the
    /// statement must not run (fail closed).
    pub async fn statement(
        &self,
        phase: Phase,
        statement: &Statement,
        name: Option<&str>,
        parse_query_id: Option<Uuid>,
    ) -> Result<Uuid, AuditError> {
        let mut data = self.base(phase);
        data["statement_type"] = json!(statement.kind);
        if let Some(name) = name {
            data["statement_name"] = json!(name);
        }
        if let Some(id) = parse_query_id {
            data["parse_query_id"] = json!(id);
        }
        let text = if self.normalize {
            data["normalized"] = json!(true);
            sqltext::normalize(&statement.text, self.flavor())
        } else {
            statement.text.clone()
        };
        let repeat = phase == Phase::Execute && text.len() > MAX_REPEAT_TEXT;
        if !repeat {
            let (text, truncated) = truncate(&text, MAX_TEXT);
            data["statement"] = json!(text);
            if truncated {
                data["truncated"] = json!(true);
                data["statement_sha256"] = json!(hex(&Sha256::digest(statement.text.as_bytes())));
            }
        }
        self.emitter
            .emit(EventKind::DbQuery, self.ctx.clone(), data)
            .await
    }

    /// A function call or other action with no SQL text.
    pub async fn action(&self, phase: Phase, kind: &str) -> Result<Uuid, AuditError> {
        let mut data = self.base(phase);
        data["statement_type"] = json!(kind);
        self.emitter
            .emit(EventKind::DbQuery, self.ctx.clone(), data)
            .await
    }

    pub async fn finished(
        &self,
        query_id: Uuid,
        started: Instant,
        outcome: &Outcome,
    ) -> Result<(), AuditError> {
        let end = outcome.finished.unwrap_or_else(Instant::now);
        let status = if outcome.error_code.is_some() {
            "error"
        } else if outcome.finished.is_some() {
            "ok"
        } else {
            "not_completed"
        };
        let mut data = self.base(Phase::Simple);
        data.as_object_mut().map(|m| m.remove("phase"));
        data["query_id"] = json!(query_id);
        data["status"] = json!(status);
        data["duration_ms"] = json!(
            u64::try_from(end.saturating_duration_since(started).as_millis()).unwrap_or(u64::MAX)
        );
        if let Some(rows) = outcome.rows {
            data["rows"] = json!(rows);
        }
        if let Some(code) = &outcome.error_code {
            data["error_code"] = json!(code);
        }
        if let Some(number) = outcome.error_number {
            data["error_number"] = json!(number);
        }
        if let Some(message) = &outcome.error_message {
            data["error"] = json!(truncate(message, 4096).0);
        }
        self.emitter
            .emit(EventKind::DbQueryEnd, self.ctx.clone(), data)
            .await
            .map(|_| ())
    }
}

fn truncate(text: &str, max: usize) -> (&str, bool) {
    if text.len() <= max {
        return (text, false);
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (&text[..end], true)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_on_a_char_boundary() {
        assert_eq!(truncate("héllo", 2), ("h", true));
        assert_eq!(truncate("héllo", 3), ("hé", true));
        assert_eq!(truncate("abc", 10), ("abc", false));
    }
}
