//! Audit event schema (v1) and emission.
//!
//! Phase 1 ships the [`Emitter`] and a stub sink: a local, fsynced JSONL
//! file ([`sink::JsonlFileSink`]). The disk spool and the S3 and Datadog
//! sinks arrive in Phase 3 (ADR-0009). The envelope defined here is the
//! stable contract that the Glue table and Grafana dashboards are built on,
//! so changes must bump [`SCHEMA_VERSION`].

pub mod emitter;
pub mod ship;
pub mod sink;
pub mod spool;

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
    /// A user ended their login (`limen logout`). `data.login_id` says which.
    #[serde(rename = "auth.logout")]
    AuthLogout,
    #[serde(rename = "auth.denied")]
    AuthDenied,
    #[serde(rename = "session.start")]
    SessionStart,
    #[serde(rename = "session.end")]
    SessionEnd,
    #[serde(rename = "ssh.exec")]
    SshExec,
    /// A statement (or prepared-statement execution) sent to a SQL database.
    /// Written before the statement is forwarded (ADR-0033).
    #[serde(rename = "db.query")]
    DbQuery,
    /// How a `db.query` ended: duration, rows affected, error. `data.query_id` is its event id.
    #[serde(rename = "db.query.end")]
    DbQueryEnd,
    /// The worker created, changed, or found drift in a `limen_*` database role.
    #[serde(rename = "db.bootstrap")]
    DbBootstrap,
    /// A request sent to `OpenSearch` or Elasticsearch. Written before the
    /// request is forwarded (ADR-0036).
    #[serde(rename = "search.request")]
    SearchRequest,
    /// How a `search.request` ended: status, duration, bytes. `data.request_id` is its event id.
    #[serde(rename = "search.response")]
    SearchResponse,
    #[serde(rename = "redis.command")]
    RedisCommand,
    /// A command sent to a MongoDB-compatible server, or one the worker
    /// refused (`data.phase`). Written before the command is forwarded
    /// (ADR-0035).
    #[serde(rename = "mongo.command")]
    MongoCommand,
    /// How a `mongo.command` ended: status, duration, error code.
    /// `data.command_id` is its event id.
    #[serde(rename = "mongo.command.end")]
    MongoCommandEnd,
    /// An AMQP operation on a `RabbitMQ` session (publish, consume, declare, …),
    /// written before it is forwarded. Never holds a message body (ADR-0037).
    #[serde(rename = "mq.operation")]
    MqOperation,
    /// What a `RabbitMQ` session did in total, written when it ends.
    #[serde(rename = "mq.summary")]
    MqSummary,
    /// A Kafka request (first contact with a topic, group and admin
    /// operations, …), written before it is forwarded. Never holds a record.
    #[serde(rename = "kafka.request")]
    KafkaRequest,
    /// Produce and fetch traffic per topic since the last event, written once a
    /// minute and when the session ends.
    #[serde(rename = "kafka.summary")]
    KafkaSummary,
    #[serde(rename = "kube.request")]
    KubeRequest,
    /// A web app request, durably recorded before forwarding.
    #[serde(rename = "web.request")]
    WebRequest,
    /// The final status and byte counts for a web request.
    #[serde(rename = "web.response")]
    WebResponse,
    /// End of a WebSocket stream, including duration and byte counts.
    #[serde(rename = "web.websocket")]
    WebSocket,
    #[serde(rename = "policy.change")]
    PolicyChange,
    /// A bot writer's write was refused by its grant or the escalation rules
    /// (ADR-0042 §11), dry runs included. A pipeline probing its limits is a
    /// detection signal.
    #[serde(rename = "policy.write_denied")]
    PolicyWriteDenied,
    /// A document moved to another owner (ADR-0042 §3).
    #[serde(rename = "policy.ownership_transfer")]
    PolicyOwnershipTransfer,
    /// A write that widens standing access was held for a person's approval
    /// (ADR-0042 §6).
    #[serde(rename = "policy.change_pending")]
    PolicyChangePending,
    /// A held change was approved (and applied), rejected, cancelled,
    /// superseded, or expired. `data.state` says which.
    #[serde(rename = "policy.change_decided")]
    PolicyChangeDecided,
    /// A proxy or worker enrolled. `data.kind` says which.
    #[serde(rename = "worker.enroll")]
    WorkerEnroll,
    #[serde(rename = "join_token.create")]
    JoinTokenCreate,
    /// A session recording was stored. Links the session to the recording's location.
    #[serde(rename = "session.recording")]
    SessionRecording,
    /// An admin locked a user: no new logins or sessions, and open sessions end.
    #[serde(rename = "user.lock")]
    UserLock,
    #[serde(rename = "user.unlock")]
    UserUnlock,
    /// An admin ended a session. `session_id` says which.
    #[serde(rename = "session.kill")]
    SessionKill,
    /// An admin revoked a proxy or worker.
    #[serde(rename = "component.revoke")]
    ComponentRevoke,
    /// Someone asked for a requestable role on a resource (ADR-0025).
    /// `data.request_id`, `role`, `resource`, `reason`, `duration_secs`.
    #[serde(rename = "access.request")]
    AccessRequest,
    /// An approver approved a request. Two approvals are two events.
    #[serde(rename = "access.approve")]
    AccessApprove,
    /// An approver denied a request.
    #[serde(rename = "access.deny")]
    AccessDeny,
    /// A request became a grant: the role is held on the resource until
    /// `data.expires_at`.
    #[serde(rename = "access.grant")]
    AccessGrant,
    /// An admin ended a grant early; its open sessions end with it.
    #[serde(rename = "access.revoke")]
    AccessRevoke,
    /// A pending request lapsed unanswered, or a grant reached its deadline.
    #[serde(rename = "access.expire")]
    AccessExpire,
    /// A break-glass grant was made at once, with a reason, and will be
    /// reviewed.
    #[serde(rename = "access.break_glass")]
    AccessBreakGlass,
    /// The requester withdrew a pending request.
    #[serde(rename = "access.cancel")]
    AccessCancel,
    /// Someone searched the audit trail (ADR-0026). Holds the query's
    /// identity and filters, never its results.
    #[serde(rename = "audit.search")]
    AuditSearch,
    /// A worker reported a resource no policy document names (ADR-0027).
    /// It waits for an admin.
    #[serde(rename = "resource.discovered")]
    ResourceDiscovered,
    /// A known discovered resource came back with different labels. The new
    /// labels wait for an admin.
    #[serde(rename = "resource.relabel")]
    ResourceRelabel,
    /// An admin accepted or rejected a pending discovered resource or relabel.
    #[serde(rename = "resource.review")]
    ResourceReview,
    /// A discovered resource was not seen for several cycles, or was removed.
    #[serde(rename = "resource.stale")]
    ResourceStale,
    /// An access review started, or an item in it was decided (ADR-0029).
    #[serde(rename = "review.start")]
    ReviewStart,
    #[serde(rename = "review.decide")]
    ReviewDecide,
    #[serde(rename = "review.complete")]
    ReviewComplete,
    /// A flagged review item took a role away from a user for a while.
    #[serde(rename = "access.deny_override")]
    AccessDenyOverride,
    /// An evidence pack was produced. `data.manifest_sha256` anchors it in
    /// the audit chain.
    #[serde(rename = "evidence.export")]
    EvidenceExport,
    /// Someone began or stopped watching a live session (ADR-0030).
    #[serde(rename = "session.watch.start")]
    SessionWatchStart,
    #[serde(rename = "session.watch.stop")]
    SessionWatchStop,
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
        event.user = Some("admin@example.com".into());
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
