//! A projection of Limen audit events into OCSF (ADR-0047).
//!
//! The native envelope and the S3 hash chain stay the source of truth. This
//! module only reads an event and builds a second JSON document from it; it
//! never feeds anything back. Every record carries the native `event_id`
//! (`metadata.uid`) and the producer position, so a SIEM user can get back to
//! the original.
//!
//! The mapping in [`classify`] is an exhaustive `match` on [`EventKind`] with
//! no wildcard arm, so a new event kind does not compile until someone picks
//! its OCSF class.

use serde_json::{Map, Value, json};

use crate::{Event, EventKind};

/// The OCSF schema version every record is written against
/// (`metadata.version`). Class and activity ids below are from the 1.9.0
/// class pages on schema.ocsf.io. Changing this is an ADR-0047 amendment.
pub const OCSF_VERSION: &str = "1.9.0";

/// The most raw text kept from an event that could not be parsed. Native events
/// are at most 1 MiB; a SIEM record does not need all of a corrupt one.
const MAX_RAW: usize = 32 * 1024;

/// How deep `unmapped.limen.data` is copied. Events come from a
/// `serde_json` parse (limit 128), but a bound here keeps the walk cheap.
const MAX_DEPTH: usize = 32;

/// Words that mark a field as a secret. Native events never hold one
/// (design §8); this is a second lock, so a mistake upstream does not leave
/// the building through a SIEM feed.
const SECRET_WORDS: [&str; 9] = [
    "password",
    "passwd",
    "secret",
    "private_key",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "credential",
];

const REDACTED: &str = "[redacted]";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Class {
    uid: u32,
    name: &'static str,
    category_uid: u32,
    category: &'static str,
}

const BASE: Class = Class {
    uid: 0,
    name: "Base Event",
    category_uid: 0,
    category: "Uncategorized",
};
const AUTHENTICATION: Class = Class {
    uid: 3002,
    name: "Authentication",
    category_uid: 3,
    category: "Identity & Access Management",
};
const AUTHORIZE_SESSION: Class = Class {
    uid: 3003,
    name: "Authorize Session",
    category_uid: 3,
    category: "Identity & Access Management",
};
const ENTITY_MANAGEMENT: Class = Class {
    uid: 3004,
    name: "Entity Management",
    category_uid: 3,
    category: "Identity & Access Management",
};
const NETWORK_ACTIVITY: Class = Class {
    uid: 4001,
    name: "Network Activity",
    category_uid: 4,
    category: "Network Activity",
};
const HTTP_ACTIVITY: Class = Class {
    uid: 4002,
    name: "HTTP Activity",
    category_uid: 4,
    category: "Network Activity",
};
const SSH_ACTIVITY: Class = Class {
    uid: 4007,
    name: "SSH Activity",
    category_uid: 4,
    category: "Network Activity",
};
const API_ACTIVITY: Class = Class {
    uid: 6003,
    name: "API Activity",
    category_uid: 6,
    category: "Application Activity",
};
const DATASTORE_ACTIVITY: Class = Class {
    uid: 6005,
    name: "Datastore Activity",
    category_uid: 6,
    category: "Application Activity",
};

/// Activity ids, with the caption OCSF gives each (`activity_name` must match
/// it exactly for every id except 99).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Activity {
    id: u32,
    name: &'static str,
}

const OTHER: Activity = Activity {
    id: 99,
    name: "Other",
};
const fn act(id: u32, name: &'static str) -> Activity {
    Activity { id, name }
}

/// OCSF `severity_id`.
const INFORMATIONAL: u32 = 1;
const LOW: u32 = 2;
const MEDIUM: u32 = 3;
const HIGH: u32 = 4;

/// OCSF `status_id`.
const SUCCESS: u32 = 1;
const FAILURE: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Mapped {
    class: Class,
    activity: Activity,
    severity: u32,
    /// `None` when the event says nothing about success.
    status: Option<u32>,
    /// A custom `activity_name` for `Other` (the OCSF caption is fixed for
    /// the listed ids).
    detail: Option<&'static str>,
}

impl Mapped {
    const fn new(class: Class, activity: Activity) -> Self {
        Self {
            class,
            activity,
            severity: INFORMATIONAL,
            status: None,
            detail: None,
        }
    }
    const fn severity(mut self, severity: u32) -> Self {
        self.severity = severity;
        self
    }
    const fn status(mut self, status: u32) -> Self {
        self.status = Some(status);
        self
    }
    const fn detail(mut self, detail: &'static str) -> Self {
        self.detail = Some(detail);
        self
    }
}

fn text<'a>(data: &'a Value, key: &str) -> Option<&'a str> {
    data.get(key).and_then(Value::as_str)
}

/// The HTTP status of an event as a code, if it has one.
fn status_code(data: &Value) -> Option<u16> {
    data.get("status")
        .and_then(Value::as_u64)
        .and_then(|n| u16::try_from(n).ok())
        .filter(|n| (100..=599).contains(n))
}

fn status_from_code(data: &Value) -> Option<u32> {
    status_code(data).map(|c| if c >= 400 { FAILURE } else { SUCCESS })
}

/// HTTP Activity ids follow the IANA method registry.
fn http_activity(method: Option<&str>) -> Activity {
    match method.map(str::to_ascii_uppercase).as_deref() {
        Some("CONNECT") => act(1, "Connect"),
        Some("DELETE") => act(2, "Delete"),
        Some("GET") => act(3, "Get"),
        Some("HEAD") => act(4, "Head"),
        Some("OPTIONS") => act(5, "Options"),
        Some("POST") => act(6, "Post"),
        Some("PUT") => act(7, "Put"),
        Some("TRACE") => act(8, "Trace"),
        Some("PATCH") => act(9, "Patch"),
        _ => OTHER,
    }
}

/// API Activity for a Kubernetes verb.
fn kube_activity(verb: Option<&str>) -> Activity {
    match verb {
        Some("create") => act(1, "Create"),
        Some("get" | "list" | "watch") => act(2, "Read"),
        Some("update" | "patch") => act(3, "Update"),
        Some("delete" | "deletecollection") => act(4, "Delete"),
        _ => OTHER,
    }
}

/// Datastore Activity for a SQL statement class.
fn sql_activity(statement_type: Option<&str>) -> Activity {
    match statement_type
        .map(str::to_ascii_lowercase)
        .as_deref()
        .map(str::trim)
    {
        Some("select" | "show" | "explain" | "with" | "describe") => act(4, "Query"),
        Some("insert" | "copy" | "replace") => act(5, "Write"),
        Some("update" | "merge") => act(2, "Update"),
        Some("delete" | "truncate" | "drop") => act(7, "Delete"),
        Some("create") => act(6, "Create"),
        _ => OTHER,
    }
}

/// The OCSF class, activity and severity for an event. Exhaustive on
/// purpose: no `_` arm (ADR-0047).
// Arms that look alike stay separate: one line per kind is the mapping table.
#[allow(clippy::too_many_lines, clippy::match_same_arms)]
fn classify(kind: EventKind, data: &Value) -> Mapped {
    use EventKind as K;
    match kind {
        K::AuthLogin => Mapped::new(AUTHENTICATION, act(1, "Logon")).status(SUCCESS),
        K::AuthLogout => Mapped::new(AUTHENTICATION, act(2, "Logoff")).status(SUCCESS),
        K::AuthDenied => Mapped::new(AUTHENTICATION, act(1, "Logon"))
            .status(FAILURE)
            .severity(LOW),

        K::SessionStart => Mapped::new(NETWORK_ACTIVITY, act(1, "Open")),
        K::SessionEnd => Mapped::new(NETWORK_ACTIVITY, act(2, "Close")),
        K::SessionKill => Mapped::new(NETWORK_ACTIVITY, act(2, "Close")).severity(LOW),
        // Watching is not a network event and has no better class.
        K::SessionWatchStart | K::SessionWatchStop => {
            Mapped::new(BASE, OTHER).detail("session watch")
        }
        K::SessionRecording => Mapped::new(API_ACTIVITY, act(1, "Create")),

        K::SshExec => Mapped::new(SSH_ACTIVITY, OTHER).detail("exec"),

        K::DbQuery => Mapped::new(
            DATASTORE_ACTIVITY,
            sql_activity(text(data, "statement_type")),
        ),
        K::DbQueryEnd | K::DbBootstrap | K::MongoCommand | K::MongoCommandEnd | K::RedisCommand => {
            Mapped::new(DATASTORE_ACTIVITY, OTHER)
        }

        K::SearchRequest | K::SearchResponse | K::WebRequest | K::WebResponse | K::WebSocket => {
            let mut m = Mapped::new(HTTP_ACTIVITY, http_activity(text(data, "method")));
            m.status = status_from_code(data);
            m
        }

        K::KubeRequest => {
            let mut m = Mapped::new(API_ACTIVITY, kube_activity(text(data, "verb")));
            m.status = status_from_code(data);
            m
        }
        K::MqOperation | K::MqSummary | K::KafkaRequest | K::KafkaSummary => {
            Mapped::new(API_ACTIVITY, OTHER)
        }

        K::PolicyChange => Mapped::new(ENTITY_MANAGEMENT, act(3, "Update")),
        K::PolicyOwnershipTransfer => Mapped::new(ENTITY_MANAGEMENT, act(5, "Move")),
        K::PolicyChangePending | K::PolicyChangeDecided => {
            Mapped::new(ENTITY_MANAGEMENT, OTHER).detail("policy change review")
        }
        // An evaluation and a refusal, not a change to an entity.
        K::PolicyShadowDeny => Mapped::new(BASE, OTHER)
            .detail("shadow deny")
            .severity(MEDIUM),
        K::PolicyWriteDenied => Mapped::new(BASE, OTHER)
            .detail("policy write denied")
            .severity(LOW)
            .status(FAILURE),

        K::WorkerEnroll => Mapped::new(ENTITY_MANAGEMENT, act(6, "Enroll")),
        K::JoinTokenCreate => Mapped::new(ENTITY_MANAGEMENT, act(1, "Create")),
        K::ComponentRevoke => Mapped::new(ENTITY_MANAGEMENT, act(7, "Unenroll")).severity(LOW),
        K::UserLock => Mapped::new(ENTITY_MANAGEMENT, act(12, "Suspend")).severity(LOW),
        K::UserUnlock => Mapped::new(ENTITY_MANAGEMENT, act(13, "Resume")),
        K::ResourceDiscovered | K::ResourceRelabel => {
            Mapped::new(ENTITY_MANAGEMENT, act(1, "Create"))
        }
        K::ResourceReview | K::ResourceStale => Mapped::new(ENTITY_MANAGEMENT, OTHER),

        K::AccessGrant => Mapped::new(AUTHORIZE_SESSION, act(3, "Assign Roles")),
        K::AccessBreakGlass => {
            Mapped::new(AUTHORIZE_SESSION, act(3, "Assign Roles")).severity(HIGH)
        }
        K::AccessRequest => Mapped::new(ENTITY_MANAGEMENT, OTHER).detail("access request"),
        K::AccessApprove => Mapped::new(ENTITY_MANAGEMENT, OTHER).detail("access approve"),
        K::AccessDeny => Mapped::new(ENTITY_MANAGEMENT, OTHER).detail("access deny"),
        K::AccessRevoke => Mapped::new(ENTITY_MANAGEMENT, OTHER).detail("access revoke"),
        K::AccessExpire => Mapped::new(ENTITY_MANAGEMENT, OTHER).detail("access expire"),
        K::AccessCancel => Mapped::new(ENTITY_MANAGEMENT, OTHER).detail("access cancel"),
        K::AccessDenyOverride => {
            Mapped::new(ENTITY_MANAGEMENT, OTHER).detail("access deny override")
        }
        K::ReviewStart | K::ReviewDecide | K::ReviewComplete => {
            Mapped::new(ENTITY_MANAGEMENT, OTHER).detail("access review")
        }

        K::AuditSearch | K::AuditVerifyAccess => Mapped::new(API_ACTIVITY, act(2, "Read")),
        K::EvidenceExport => Mapped::new(API_ACTIVITY, act(1, "Create")),
    }
}

/// `key` names a secret.
fn is_secret_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    if SECRET_WORDS.iter().any(|w| k.contains(w)) {
        return true;
    }
    // "token" alone is a secret; an id or digest of one is not.
    k.contains("token")
        && !(k.ends_with("_id")
            || k.ends_with("_sha256")
            || k.ends_with("_hash")
            || k == "token_id")
}

/// A copy of `value` with secret-named fields replaced and a depth bound.
fn scrub(value: &Value, depth: usize) -> Value {
    if depth >= MAX_DEPTH {
        return json!("[truncated]");
    }
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| {
                    let v = if is_secret_key(k) {
                        json!(REDACTED)
                    } else {
                        scrub(v, depth + 1)
                    };
                    (k.clone(), v)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(|v| scrub(v, depth + 1)).collect()),
        other => other.clone(),
    }
}

fn severity_name(id: u32) -> &'static str {
    match id {
        1 => "Informational",
        2 => "Low",
        3 => "Medium",
        4 => "High",
        _ => "Other",
    }
}

fn status_name(id: u32) -> &'static str {
    if id == SUCCESS { "Success" } else { "Failure" }
}

fn millis(event: &Event) -> i64 {
    i64::try_from(event.time.unix_timestamp_nanos() / 1_000_000).unwrap_or(0)
}

/// An IP address from the event, if it is one (the native field is free
/// text for some producers).
fn ip(data: &Value, key: &str) -> Option<String> {
    text(data, key)
        .and_then(|s| s.parse::<std::net::IpAddr>().ok())
        .map(|a| a.to_string())
}

fn product(version: &str, component: Option<&str>) -> Value {
    let mut p = json!({
        "name": "Limen",
        "vendor_name": "Limen",
        "version": version,
    });
    if let Some(component) = component {
        p["feature"] = json!({ "name": component });
    }
    p
}

/// Project one event. `product_version` is Limen's own version.
#[must_use]
pub fn to_ocsf(event: &Event, product_version: &str) -> Value {
    let mapped = classify(event.kind, &event.data);
    let Mapped {
        class,
        activity,
        severity,
        status,
        detail,
    } = mapped;
    let kind = serde_json::to_value(event.kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();
    let activity_name = if activity.id == OTHER.id {
        detail.unwrap_or(activity.name)
    } else {
        activity.name
    };
    let type_uid = u64::from(class.uid) * 100 + u64::from(activity.id);
    let user = event.user.as_deref().unwrap_or("-");
    let mut out = json!({
        "class_uid": class.uid,
        "class_name": class.name,
        "category_uid": class.category_uid,
        "category_name": class.category,
        "activity_id": activity.id,
        "activity_name": activity_name,
        "type_uid": type_uid,
        "type_name": format!("{}: {activity_name}", class.name),
        "time": millis(event),
        "severity_id": severity,
        "severity": severity_name(severity),
        "message": format!("{kind} {user}"),
        "metadata": {
            "version": OCSF_VERSION,
            "uid": event.event_id.to_string(),
            "product": product(product_version, Some(&event.producer.component)),
        },
        "unmapped": {
            "limen": {
                "schema_version": event.schema_version,
                "kind": kind,
                "producer": {
                    "component": event.producer.component,
                    "instance_id": event.producer.instance_id,
                    "seq": event.producer.seq,
                },
                "session_id": event.session_id.map(|s| s.to_string()),
                "data": scrub(&event.data, 0),
            }
        },
    });
    let Value::Object(obj) = &mut out else {
        return out;
    };
    if let Some(id) = status {
        obj.insert("status_id".into(), json!(id));
        obj.insert("status".into(), json!(status_name(id)));
    }
    if let Some(user) = &event.user {
        let actor_type = text(&event.data, "actor_type");
        let who = json!({ "name": user, "type": actor_type });
        obj.insert("actor".into(), json!({ "user": who }));
        if class.uid == AUTHENTICATION.uid {
            obj.insert("user".into(), who);
        }
    }
    if let Some(addr) = ip(&event.data, "client_addr") {
        obj.insert("src_endpoint".into(), json!({ "ip": addr }));
    }
    if class.uid == HTTP_ACTIVITY.uid {
        let mut req = Map::new();
        if let Some(m) = text(&event.data, "method") {
            req.insert("http_method".into(), json!(m));
        }
        if !req.is_empty() {
            obj.insert("http_request".into(), Value::Object(req));
        }
        if let Some(code) = status_code(&event.data) {
            obj.insert("http_response".into(), json!({ "code": code }));
        }
    }
    out
}

/// Project one spooled line. A line that is not a readable native event (a
/// bug upstream, or an event kind from a newer producer) still becomes a Base
/// Event with the raw text kept, so this sink never drops one.
#[must_use]
pub fn raw_to_ocsf(raw: &[u8], product_version: &str) -> (Value, Option<String>) {
    match serde_json::from_slice::<Event>(raw) {
        Ok(event) => {
            let day_hour = day_hour(&event);
            (to_ocsf(&event, product_version), Some(day_hour))
        }
        Err(e) => {
            let lossy = String::from_utf8_lossy(raw);
            let mut end = lossy.len().min(MAX_RAW);
            while !lossy.is_char_boundary(end) {
                end -= 1;
            }
            let record = json!({
                "class_uid": BASE.uid,
                "class_name": BASE.name,
                "category_uid": BASE.category_uid,
                "category_name": BASE.category,
                "activity_id": OTHER.id,
                "activity_name": "unreadable audit event",
                "type_uid": u64::from(OTHER.id),
                "type_name": "Base Event: unreadable audit event",
                "time": time::OffsetDateTime::now_utc().unix_timestamp() * 1000,
                "severity_id": MEDIUM,
                "severity": severity_name(MEDIUM),
                "message": "unreadable audit event",
                "metadata": {
                    "version": OCSF_VERSION,
                    "product": product(product_version, None),
                },
                "unmapped": { "limen": {
                    "error": e.to_string(),
                    "raw": &lossy[..end],
                    "truncated": end < lossy.len(),
                } },
            });
            (record, None)
        }
    }
}

/// `YYYY-MM-DD/HH` (UTC) of the event, for partitioning.
fn day_hour(event: &Event) -> String {
    let t = event.time.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}/{:02}",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour()
    )
}

/// Every event kind, for tests and for the generated mapping table.
#[cfg(test)]
const ALL_KINDS: &[EventKind] = &[
    EventKind::AuthLogin,
    EventKind::AuthLogout,
    EventKind::AuthDenied,
    EventKind::SessionStart,
    EventKind::SessionEnd,
    EventKind::SshExec,
    EventKind::DbQuery,
    EventKind::DbQueryEnd,
    EventKind::DbBootstrap,
    EventKind::SearchRequest,
    EventKind::SearchResponse,
    EventKind::RedisCommand,
    EventKind::MongoCommand,
    EventKind::MongoCommandEnd,
    EventKind::MqOperation,
    EventKind::MqSummary,
    EventKind::KafkaRequest,
    EventKind::KafkaSummary,
    EventKind::KubeRequest,
    EventKind::WebRequest,
    EventKind::WebResponse,
    EventKind::WebSocket,
    EventKind::PolicyChange,
    EventKind::PolicyShadowDeny,
    EventKind::PolicyWriteDenied,
    EventKind::PolicyOwnershipTransfer,
    EventKind::PolicyChangePending,
    EventKind::PolicyChangeDecided,
    EventKind::WorkerEnroll,
    EventKind::JoinTokenCreate,
    EventKind::SessionRecording,
    EventKind::UserLock,
    EventKind::UserUnlock,
    EventKind::SessionKill,
    EventKind::ComponentRevoke,
    EventKind::AccessRequest,
    EventKind::AccessApprove,
    EventKind::AccessDeny,
    EventKind::AccessGrant,
    EventKind::AccessRevoke,
    EventKind::AccessExpire,
    EventKind::AccessBreakGlass,
    EventKind::AccessCancel,
    EventKind::AuditSearch,
    EventKind::AuditVerifyAccess,
    EventKind::ResourceDiscovered,
    EventKind::ResourceRelabel,
    EventKind::ResourceReview,
    EventKind::ResourceStale,
    EventKind::ReviewStart,
    EventKind::ReviewDecide,
    EventKind::ReviewComplete,
    EventKind::AccessDenyOverride,
    EventKind::EvidenceExport,
    EventKind::SessionWatchStart,
    EventKind::SessionWatchStop,
];

#[cfg(test)]
#[allow(clippy::unwrap_used)] // assertions on JSON built in the test
mod tests {
    use super::*;
    use crate::Producer;

    fn producer() -> Producer {
        Producer {
            component: "proxy".into(),
            instance_id: "p-1".into(),
            seq: 41,
        }
    }

    fn event(kind: EventKind, data: Value) -> Event {
        let mut e = Event::new(kind, producer(), data);
        e.user = Some("dev@example.com".into());
        e
    }

    /// The kinds listed above are every kind: serializing each and finding it in
    /// the enum's own list keeps `ALL_KINDS` from going stale unnoticed (the
    /// `match` in `classify` is what forces a mapping; this forces a test).
    #[test]
    fn all_kinds_has_no_duplicates_and_matches_the_enum_size() {
        let mut names: Vec<String> = ALL_KINDS
            .iter()
            .map(|k| {
                serde_json::to_value(k)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        let before = names.len();
        names.sort();
        names.dedup();
        assert_eq!(before, names.len(), "a kind is listed twice");
        // `EventKind` is `Copy` and has no iterator; this count is what the
        // enum had when the mapping was written. A new kind must be added to
        // `ALL_KINDS` and to `classify` (which will not compile otherwise).
        assert_eq!(before, 56);
    }

    #[test]
    fn every_kind_carries_the_required_ocsf_attributes_and_the_native_ids() {
        for kind in ALL_KINDS {
            let e = event(*kind, json!({"method": "GET", "status": 200}));
            let v = to_ocsf(&e, "9.9.9");
            for key in [
                "class_uid",
                "category_uid",
                "activity_id",
                "type_uid",
                "time",
                "severity_id",
                "metadata",
            ] {
                assert!(v.get(key).is_some(), "{kind:?} lacks {key}");
            }
            let class = v["class_uid"].as_u64().unwrap();
            let activity = v["activity_id"].as_u64().unwrap();
            assert_eq!(v["type_uid"].as_u64().unwrap(), class * 100 + activity);
            assert_eq!(v["metadata"]["version"], OCSF_VERSION);
            assert_eq!(v["metadata"]["uid"], e.event_id.to_string());
            assert_eq!(v["metadata"]["product"]["version"], "9.9.9");
            assert_eq!(v["unmapped"]["limen"]["producer"]["seq"], 41);
            assert_eq!(v["unmapped"]["limen"]["producer"]["instance_id"], "p-1");
            assert_eq!(v["time"].as_i64().unwrap(), millis(&e));
            // The activity_name is the OCSF caption except for Other.
            if activity != 99 {
                assert_ne!(v["activity_name"].as_str().unwrap(), "");
            }
            // Plain JSON on one line: the sink writes NDJSON.
            assert!(!serde_json::to_string(&v).unwrap().contains('\n'));
        }
    }

    #[test]
    fn logins_and_denials_map_to_authentication() {
        let ok = to_ocsf(
            &event(EventKind::AuthLogin, json!({"client_addr": "203.0.113.9"})),
            "1",
        );
        assert_eq!(ok["class_uid"], 3002);
        assert_eq!(ok["activity_id"], 1);
        assert_eq!(ok["type_uid"], 300_201);
        assert_eq!(ok["status_id"], 1);
        assert_eq!(ok["user"]["name"], "dev@example.com");
        assert_eq!(ok["src_endpoint"]["ip"], "203.0.113.9");

        let denied = to_ocsf(
            &event(EventKind::AuthDenied, json!({"reason": "user locked"})),
            "1",
        );
        assert_eq!(denied["class_uid"], 3002);
        assert_eq!(denied["status_id"], 2);
        assert_eq!(denied["severity_id"], 2);
    }

    #[test]
    fn http_methods_and_statuses_map() {
        let v = to_ocsf(
            &event(
                EventKind::WebRequest,
                json!({"method": "post", "status": 503}),
            ),
            "1",
        );
        assert_eq!(v["class_uid"], 4002);
        assert_eq!(v["activity_id"], 6);
        assert_eq!(v["activity_name"], "Post");
        assert_eq!(v["type_uid"], 400_206);
        assert_eq!(v["status_id"], 2);
        assert_eq!(v["http_response"]["code"], 503);
        let odd = to_ocsf(
            &event(EventKind::WebRequest, json!({"method": "BREW"})),
            "1",
        );
        assert_eq!(odd["activity_id"], 99);
        assert!(odd.get("status_id").is_none());
    }

    #[test]
    fn kube_verbs_and_sql_statement_classes_map() {
        let k = to_ocsf(
            &event(EventKind::KubeRequest, json!({"verb": "deletecollection"})),
            "1",
        );
        assert_eq!(
            (k["class_uid"].as_u64(), k["activity_id"].as_u64()),
            (Some(6003), Some(4))
        );
        let q = to_ocsf(
            &event(EventKind::DbQuery, json!({"statement_type": "SELECT"})),
            "1",
        );
        assert_eq!(
            (q["class_uid"].as_u64(), q["activity_id"].as_u64()),
            (Some(6005), Some(4))
        );
        let w = to_ocsf(
            &event(EventKind::DbQuery, json!({"statement_type": "insert"})),
            "1",
        );
        assert_eq!(w["activity_id"], 5);
    }

    #[test]
    fn severity_defaults_and_overrides() {
        let sev = |k| to_ocsf(&event(k, json!({})), "1")["severity_id"].as_u64();
        assert_eq!(sev(EventKind::SessionStart), Some(1));
        assert_eq!(sev(EventKind::PolicyShadowDeny), Some(3));
        assert_eq!(sev(EventKind::AccessBreakGlass), Some(4));
        assert_eq!(sev(EventKind::PolicyWriteDenied), Some(2));
    }

    #[test]
    fn secret_named_fields_never_reach_the_projection() {
        let e = event(
            EventKind::JoinTokenCreate,
            json!({
                "token": "abc",
                "join_token": "def",
                "token_id": "kept",
                "access_token": "ghi",
                "Password": "hunter2",
                "nested": {"api_key": "k", "list": [{"client_secret": "s"}]},
                "authorization": "Bearer x",
                "cookie": "c",
                "resource": "orders-prod"
            }),
        );
        let text = serde_json::to_string(&to_ocsf(&e, "1")).unwrap();
        for leaked in [
            "abc", "def", "ghi", "hunter2", "Bearer x", "\"k\"", "\"s\"", "\"c\"",
        ] {
            assert!(!text.contains(leaked), "{leaked} leaked: {text}");
        }
        assert!(text.contains("kept"));
        assert!(text.contains("orders-prod"));
        assert!(text.contains(REDACTED));
    }

    #[test]
    fn deep_data_is_cut_off() {
        let mut v = json!("leaf");
        for _ in 0..(MAX_DEPTH + 10) {
            v = json!({ "a": v });
        }
        let s = serde_json::to_string(&scrub(&v, 0)).unwrap();
        assert!(s.contains("[truncated]"));
        assert!(!s.contains("leaf"));
    }

    #[test]
    fn a_non_ip_client_addr_is_not_copied_into_the_endpoint() {
        let v = to_ocsf(
            &event(EventKind::AuthLogin, json!({"client_addr": "not an ip"})),
            "1",
        );
        assert!(v.get("src_endpoint").is_none());
    }

    #[test]
    fn unreadable_lines_become_base_events_with_the_raw_text() {
        let (v, hour) = raw_to_ocsf(br#"{"kind":"from.the.future","event_id":"x"}"#, "1");
        assert!(hour.is_none());
        assert_eq!(v["class_uid"], 0);
        assert_eq!(v["activity_id"], 99);
        assert!(
            v["unmapped"]["limen"]["raw"]
                .as_str()
                .unwrap()
                .contains("from.the.future")
        );
        // Not UTF-8, and very long: still one valid record.
        let mut raw = vec![0xff, 0xfe];
        raw.extend(std::iter::repeat_n(b'a', MAX_RAW * 2));
        let (v, _) = raw_to_ocsf(&raw, "1");
        assert_eq!(v["unmapped"]["limen"]["truncated"], true);
        assert!(v["unmapped"]["limen"]["raw"].as_str().unwrap().len() <= MAX_RAW);
    }

    /// The mapping table of the guide, built from `classify` itself.
    fn mapping_markdown() -> String {
        use EventKind as K;
        use std::fmt::Write as _;
        let mut out = String::from(
            "| Limen event | OCSF class (uid) | Activity (id) | Severity |\n|---|---|---|---|\n",
        );
        for kind in ALL_KINDS {
            let name = serde_json::to_value(kind)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned();
            let m = classify(*kind, &Value::Null);
            let activity = match (kind, m.detail) {
                (
                    K::SearchRequest
                    | K::SearchResponse
                    | K::WebRequest
                    | K::WebResponse
                    | K::WebSocket,
                    _,
                ) => "by method".to_owned(),
                (K::KubeRequest, _) => "by verb".to_owned(),
                (K::DbQuery, _) => "by statement class".to_owned(),
                (_, Some(d)) if m.activity.id == OTHER.id => format!("{d} ({})", m.activity.id),
                _ => format!("{} ({})", m.activity.name, m.activity.id),
            };
            let _ = writeln!(
                out,
                "| `{name}` | {} ({}) | {activity} | {} |",
                m.class.name,
                m.class.uid,
                severity_name(m.severity)
            );
        }
        out
    }

    /// The guide's table is generated from the mapping, so it cannot drift.
    /// `LIMEN_UPDATE_DOCS=1 cargo test -p limen-audit --lib guide_mapping` rewrites it.
    #[test]
    fn guide_mapping_table_matches_the_code() {
        const BEGIN: &str = "<!-- BEGIN_OCSF_MAPPING -->\n";
        const END: &str = "<!-- END_OCSF_MAPPING -->";
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/guides/audit-ocsf.md");
        let guide = std::fs::read_to_string(&path).expect("the guide exists");
        let start = guide.find(BEGIN).expect("begin marker") + BEGIN.len();
        let end = guide.find(END).expect("end marker");
        let want = mapping_markdown();
        if std::env::var_os("LIMEN_UPDATE_DOCS").is_some() {
            let new = format!("{}{want}{}", &guide[..start], &guide[end..]);
            std::fs::write(&path, new).expect("write guide");
            return;
        }
        assert_eq!(
            &guide[start..end],
            want,
            "docs/guides/audit-ocsf.md is out of date: run `LIMEN_UPDATE_DOCS=1 cargo test -p limen-audit --lib guide_mapping`"
        );
    }

    #[test]
    fn partition_is_the_events_utc_hour() {
        let mut e = event(EventKind::AuthLogin, json!({}));
        e.time = time::macros::datetime!(2026-11-09 23:59:59 +02:00);
        assert_eq!(day_hour(&e), "2026-11-09/21");
        let line = serde_json::to_vec(&e).unwrap();
        let (_, hour) = raw_to_ocsf(&line, "1");
        assert_eq!(hour.as_deref(), Some("2026-11-09/21"));
    }
}
