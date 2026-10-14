//! Audit event schema (v1) and emission.
//!
//! Phase 1 ships the [`Emitter`] and a stub sink: a local, fsynced JSONL
//! file ([`sink::JsonlFileSink`]). The disk spool and the S3 and Datadog
//! sinks arrive in Phase 3 (ADR-0009). The envelope defined here is the
//! stable contract that the Glue table and Grafana dashboards are built on,
//! so changes must bump [`SCHEMA_VERSION`].

pub mod emitter;
pub mod sink;

pub use emitter::{AuditError, Context, Emitter, FailureMode};
pub use sink::{AuditSink, JsonlFileSink, MemorySink};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Version of the event envelope.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventKind {
    #[serde(rename = "auth.login")]
    AuthLogin,
    #[serde(rename = "auth.denied")]
    AuthDenied,
    #[serde(rename = "session.start")]
    SessionStart,
    #[serde(rename = "session.end")]
    SessionEnd,
    #[serde(rename = "ssh.exec")]
    SshExec,
    #[serde(rename = "db.query")]
    DbQuery,
    #[serde(rename = "redis.command")]
    RedisCommand,
    #[serde(rename = "kube.request")]
    KubeRequest,
    #[serde(rename = "policy.change")]
    PolicyChange,
    /// A proxy or worker enrolled. `data.kind` says which.
    #[serde(rename = "worker.enroll")]
    WorkerEnroll,
    #[serde(rename = "join_token.create")]
    JoinTokenCreate,
}

/// Component that emitted the event, plus its per-producer sequence number.
/// Gaps in `seq` for a producer mean events were lost.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Producer {
    pub component: String,
    pub instance_id: String,
    pub seq: u64,
}

/// The v1 event envelope. Kind-specific fields go in `data`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub schema_version: u32,
    /// `UUIDv7`: unique, and sortable by creation time. Also the idempotency key.
    pub event_id: Uuid,
    pub kind: EventKind,
    #[serde(with = "time::serde::rfc3339")]
    pub time: OffsetDateTime,
    pub producer: Producer,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<Uuid>,
    pub data: serde_json::Value,
}

impl Event {
    #[must_use]
    pub fn new(kind: EventKind, producer: Producer, data: serde_json::Value) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            event_id: Uuid::now_v7(),
            kind,
            time: OffsetDateTime::now_utc(),
            producer,
            user: None,
            session_id: None,
            data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn producer() -> Producer {
        Producer {
            component: "control-plane".into(),
            instance_id: "cp-1".into(),
            seq: 7,
        }
    }

    #[test]
    fn round_trips_through_json() {
        let mut event = Event::new(
            EventKind::DbQuery,
            producer(),
            serde_json::json!({"statement": "select 1"}),
        );
        event.user = Some("alice@example.com".into());
        let line = serde_json::to_string(&event).expect("serialize");
        assert!(line.contains(r#""kind":"db.query""#));
        let back: Event = serde_json::from_str(&line).expect("deserialize");
        assert_eq!(back, event);
    }

    #[test]
    fn event_ids_are_unique_and_v7() {
        let a = Event::new(EventKind::AuthLogin, producer(), serde_json::Value::Null);
        let b = Event::new(EventKind::AuthLogin, producer(), serde_json::Value::Null);
        assert_ne!(a.event_id, b.event_id);
        assert_eq!(a.event_id.get_version_num(), 7);
    }
}
