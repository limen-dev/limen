//! `search.request`, `search.response`, and `auth.denied` events (ADR-0036 §6).

use limen_audit::{AuditError, Context, Emitter, EventKind};
use limen_policy::SearchAudit;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::rules::{BodyFacts, MAX_LISTED, Scope, Shape};

/// The most of a request body a `search.request` event holds when
/// `audit.log_bodies` is on.
const MAX_BODY_TEXT: usize = 16 * 1024;
/// The longest raw target a denial event records.
const MAX_RAW_TARGET: usize = 256;

/// What a response turned out to be, for the `search.response` event.
#[derive(Debug, Default, Clone)]
pub struct Outcome {
    pub status: u16,
    pub duration_ms: u64,
    pub content_length: Option<u64>,
    /// The engine's `error.type`, never its reason (which can echo data).
    pub error_type: Option<String>,
    /// The worker answered instead of the server.
    pub by_worker: bool,
}

/// Writes the audit events of one search session.
#[derive(Debug, Clone)]
pub struct Auditor {
    emitter: Emitter,
    ctx: Context,
    engine: &'static str,
    resource: String,
    engine_role: String,
    actor_type: &'static str,
    settings: SearchAudit,
}

impl Auditor {
    #[must_use]
    pub fn new(
        emitter: Emitter,
        session_id: Uuid,
        username: &str,
        resource: &str,
        engine: &'static str,
        engine_role: &str,
        settings: SearchAudit,
    ) -> Self {
        Self {
            emitter,
            ctx: Context {
                user: Some(username.to_owned()),
                session_id: Some(session_id),
            },
            engine,
            resource: resource.to_owned(),
            engine_role: engine_role.to_owned(),
            actor_type: limen_core::identity::actor_type(username),
            settings,
        }
    }

    #[must_use]
    pub fn settings(&self) -> &SearchAudit {
        &self.settings
    }

    fn base(&self) -> Value {
        json!({
            "protocol": "search",
            "engine": self.engine,
            "actor_type": self.actor_type,
            "resource": self.resource,
            "engine_role": self.engine_role,
        })
    }

    /// The path for the trail: as sent, with document ids hashed if the
    /// resource asks for it.
    #[must_use]
    pub fn path(&self, shape: &Shape) -> String {
        let mut out = String::new();
        for (i, seg) in shape.segments.iter().enumerate() {
            out.push('/');
            if self.settings.redact_ids && shape.id_segments.contains(&i) {
                let mut h = Sha256::new();
                h.update(self.resource.as_bytes());
                h.update([0]);
                h.update(seg.as_bytes());
                out.push_str("h:");
                out.push_str(&hex(&h.finalize()[..8]));
            } else {
                out.push_str(seg);
            }
        }
        if out.is_empty() {
            out.push('/');
        }
        out
    }

    /// Record a request *before* it is forwarded. An error means the request
    /// must not be sent (fail closed).
    #[allow(clippy::too_many_arguments)]
    pub async fn request(
        &self,
        method: &str,
        shape: &Shape,
        facts: &BodyFacts,
        query: Option<&str>,
        body_bytes: u64,
        body_text: Option<&str>,
    ) -> Result<Uuid, AuditError> {
        let mut data = self.base();
        data["method"] = json!(method);
        data["path"] = json!(self.path(shape));
        data["api"] = json!(shape.api);
        data["class"] = json!(shape.class.as_str());
        let mut names: Vec<&String> = facts.named.names.iter().collect();
        if names.len() > MAX_LISTED {
            data["indices_truncated"] = json!(true);
            names.truncate(MAX_LISTED);
        }
        data["indices"] = json!(names);
        data["indices_all"] = json!(facts.named.all);
        if self.settings.log_query {
            if let Some(q) = query.filter(|q| !q.is_empty()) {
                data["query"] = json!(cut(q, 4096).0);
            }
        } else if !shape.params.is_empty() {
            data["query_params"] = json!(shape.params);
        }
        data["body_bytes"] = json!(body_bytes);
        if facts.items > 0 {
            data["items"] = json!(facts.items);
        }
        if !facts.bulk_ops.is_empty() {
            let mut ops = serde_json::Map::new();
            for (index, by_action) in facts.bulk_ops.iter().take(MAX_LISTED) {
                ops.insert(index.clone(), json!(by_action));
            }
            data["bulk"] = Value::Object(ops);
        }
        if facts.remote {
            data["remote"] = json!(true);
        }
        if let Some(text) = body_text
            && self.settings.log_bodies
            && !shape.sensitive
        {
            let (t, truncated) = cut(text, MAX_BODY_TEXT);
            data["body"] = json!(t);
            if truncated {
                data["body_truncated"] = json!(true);
            }
        }
        self.emitter
            .emit(EventKind::SearchRequest, self.ctx.clone(), data)
            .await
    }

    pub async fn response(&self, request_id: Uuid, outcome: &Outcome) -> Result<(), AuditError> {
        let mut data = self.base();
        data["request_id"] = json!(request_id);
        data["status"] = json!(outcome.status);
        data["outcome"] = json!(if outcome.status >= 400 { "error" } else { "ok" });
        data["duration_ms"] = json!(outcome.duration_ms);
        if let Some(n) = outcome.content_length {
            data["content_length"] = json!(n);
        }
        if let Some(t) = &outcome.error_type {
            data["error_type"] = json!(cut(t, 256).0);
        }
        if outcome.by_worker {
            data["by_worker"] = json!(true);
        }
        self.emitter
            .emit(EventKind::SearchResponse, self.ctx.clone(), data)
            .await
            .map(|_| ())
    }

    /// A request the worker refused. `shape` is there once the head was understood.
    pub async fn denied(
        &self,
        method: &str,
        raw_target: &str,
        shape: Option<&Shape>,
        reason: &str,
    ) -> Result<(), AuditError> {
        let mut data = self.base();
        data["action"] = json!("search");
        data["method"] = json!(method);
        match shape {
            Some(s) => {
                data["path"] = json!(self.path(s));
                data["api"] = json!(s.api);
                data["class"] = json!(s.class.as_str());
                if let Scope::Indices(v) = &s.scope {
                    data["indices"] = json!(v.iter().take(MAX_LISTED).collect::<Vec<_>>());
                } else if matches!(s.scope, Scope::All) {
                    data["indices_all"] = json!(true);
                }
            }
            None => {
                let path = raw_target.split('?').next().unwrap_or(raw_target);
                data["path"] = json!(cut(path, MAX_RAW_TARGET).0);
            }
        }
        data["reason"] = json!(reason);
        self.emitter
            .emit(EventKind::AuthDenied, self.ctx.clone(), data)
            .await
            .map(|_| ())
    }
}

/// The engine's error type from a JSON error body, if it has one.
#[must_use]
pub fn error_type(body: &[u8]) -> Option<String> {
    let v: Value = serde_json::from_slice(body).ok()?;
    match v.get("error")? {
        Value::Object(e) => e.get("type")?.as_str().map(str::to_owned),
        Value::String(_) => Some("unknown".to_owned()),
        _ => None,
    }
}

fn cut(text: &str, max: usize) -> (&str, bool) {
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
    fn error_types_come_from_the_error_object_only() {
        assert_eq!(
            error_type(br#"{"error":{"type":"index_not_found_exception","reason":"no such index [secret]"},"status":404}"#).as_deref(),
            Some("index_not_found_exception")
        );
        assert_eq!(
            error_type(br#"{"error":"Incorrect HTTP method"}"#).as_deref(),
            Some("unknown")
        );
        assert_eq!(error_type(b"not json"), None);
        assert_eq!(error_type(br#"{"hits":{}}"#), None);
    }

    #[test]
    fn cuts_on_a_char_boundary() {
        assert_eq!(cut("héllo", 2), ("h", true));
        assert_eq!(cut("abc", 10), ("abc", false));
    }
}
