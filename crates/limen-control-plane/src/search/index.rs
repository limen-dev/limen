//! What of an audit event goes into the search index (ADR-0026): its
//! metadata, and the command or statement text, with secret shapes masked.
//! Nothing here reads a payload that the console's own 30-day summary leaves
//! out for being sensitive: values in Redis commands and request bodies are
//! already redacted by the workers before they become events.

use serde_json::Value;
use uuid::Uuid;

use super::mask;
use crate::db::Db;

/// The most text kept for one event.
const MAX_TEXT: usize = 8 * 1024;

/// Fields that describe what was done, in the order they read best. Anything
/// not listed (claims, certificates, group lists) is left out.
const FIELDS: [&str; 34] = [
    "command",
    "statement",
    "query",
    "method",
    "path",
    "verb",
    "k8s_group",
    "k8s_resource",
    "subresource",
    "namespace",
    "name",
    "index",
    "indices",
    "topic",
    "topics",
    "exchange",
    "queue",
    "resource",
    "login",
    "db_role",
    "redis_user",
    "mongo_role",
    "mq_user",
    "kafka_user",
    "role",
    "target_user",
    "action",
    "what",
    "reason",
    "comment",
    "request_id",
    "component_name",
    "error",
    "message",
];

/// Events with nothing to search for: they only close or total up another.
fn is_noise(kind: &str) -> bool {
    matches!(
        kind,
        "db.query.end"
            // A search for a word would otherwise find the searches for it.
            | "audit.search"
            | "search.response"
            | "web.response"
            | "web.websocket"
            | "mongo.command.end"
            | "mq.summary"
            | "kafka.summary"
    )
}

/// The searchable text of an event, or `None` if it has none worth keeping.
#[must_use]
pub fn event_text(kind: &str, data: &Value) -> Option<String> {
    if is_noise(kind) {
        return None;
    }
    let mut parts: Vec<String> = Vec::new();
    for field in FIELDS {
        match data.get(field) {
            Some(Value::String(s)) if !s.is_empty() => parts.push(s.clone()),
            Some(Value::Number(n)) => parts.push(n.to_string()),
            Some(Value::Array(a)) => parts.extend(
                a.iter()
                    .filter_map(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned),
            ),
            _ => {}
        }
    }
    if parts.is_empty() {
        return None;
    }
    let text = mask::mask(&parts.join(" "));
    Some(cut(text, MAX_TEXT))
}

fn cut(mut text: String, max: usize) -> String {
    if text.len() > max {
        let mut end = max;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

/// `denied` for a refusal, `ok` otherwise.
#[must_use]
pub fn outcome(kind: &str, data: &Value) -> &'static str {
    let phase = data.get("phase").and_then(Value::as_str);
    let status = data.get("status").and_then(Value::as_str);
    let result = data.get("outcome").and_then(Value::as_str);
    if kind == "auth.denied"
        || phase == Some("denied")
        || status == Some("denied")
        || result == Some("denied")
        || kind == "access.deny"
    {
        "denied"
    } else {
        "ok"
    }
}

/// Add one event to the index. Idempotent by event id.
pub async fn index_event(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    e: &limen_audit::Event,
    kind: &str,
) -> Result<(), sqlx::Error> {
    let Some(text) = event_text(kind, &e.data) else {
        return Ok(());
    };
    sqlx::query(
        "INSERT INTO audit_search (event_id, at, kind, username, session_id, resource, outcome, text)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (event_id) DO NOTHING",
    )
    .bind(e.event_id)
    .bind(e.time)
    .bind(kind)
    .bind(&e.user)
    .bind(e.session_id)
    .bind(
        e.data
            .get("resource")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty()),
    )
    .bind(outcome(kind, &e.data))
    .bind(text)
    .execute(&mut **tx)
    .await
    .map(|_| ())
}

/// Delete what has aged out of the search window. Batched, so a large
/// backlog never holds a long lock. Returns how many rows went.
pub async fn trim(db: &Db, retention_days: i32) -> Result<u64, sqlx::Error> {
    let mut deleted = 0;
    for sql in [
        "DELETE FROM audit_search WHERE ctid IN (SELECT ctid FROM audit_search WHERE at < now() - make_interval(days => $1) LIMIT 5000)",
        "DELETE FROM recording_text WHERE ctid IN (SELECT t.ctid FROM recording_text t
           WHERE NOT EXISTS (SELECT 1 FROM recording_text_state s WHERE s.session_id = t.session_id AND s.indexed_at >= now() - make_interval(days => $1)) LIMIT 5000)",
        "DELETE FROM recording_text_state WHERE indexed_at < now() - make_interval(days => $1)",
    ] {
        deleted += sqlx::query(sql)
            .bind(retention_days)
            .execute(db)
            .await?
            .rows_affected();
    }
    Ok(deleted)
}

/// Put a stored recording's output text in the search index (ADR-0026).
/// Replaces what an earlier upload of the same session left.
pub async fn index_recording(
    db: &Db,
    session_id: Uuid,
    file: &std::path::Path,
) -> anyhow::Result<()> {
    let bytes = tokio::fs::read(file).await?;
    let extracted = super::recording::extract(&bytes);
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM recording_text WHERE session_id = $1")
        .bind(session_id)
        .execute(&mut *tx)
        .await?;
    for (seq, chunk) in extracted.chunks.iter().enumerate() {
        sqlx::query(
            "INSERT INTO recording_text (session_id, seq, t, text) VALUES ($1, $2, $3, $4)",
        )
        .bind(session_id)
        .bind(i32::try_from(seq).unwrap_or(i32::MAX))
        .bind(chunk.t)
        .bind(&chunk.text)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        "INSERT INTO recording_text_state (session_id, bytes, truncated) VALUES ($1, $2, $3)
         ON CONFLICT (session_id) DO UPDATE SET bytes = $2, truncated = $3, indexed_at = now()",
    )
    .bind(session_id)
    .bind(i32::try_from(extracted.bytes).unwrap_or(i32::MAX))
    .bind(extracted.truncated)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Whether a recording already has its text indexed.
pub async fn recording_indexed(db: &Db, session_id: Uuid) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM recording_text_state WHERE session_id = $1)")
        .bind(session_id)
        .fetch_one(db)
        .await
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn statements_and_commands_are_searchable_and_masked() {
        let t = event_text(
            "db.query",
            &json!({ "statement": "DROP TABLE orders_2024", "resource": "orders-prod", "db_role": "limen_write" }),
        )
        .expect("text");
        assert!(t.contains("DROP TABLE orders_2024") && t.contains("orders-prod"));
        let t = event_text(
            "ssh.exec",
            &json!({ "command": "mysql -h db --password=hunter2", "resource": "web-1", "login": "ubuntu" }),
        )
        .expect("text");
        assert!(t.contains("mysql -h db") && !t.contains("hunter2"), "{t}");
    }

    #[test]
    fn what_the_console_leaves_out_stays_out() {
        let t = event_text(
            "auth.login",
            &json!({ "idp_subject": "abc", "groups": ["secret-group"], "roles": ["r"], "cert_serial": "ff", "flow": "pkce" }),
        );
        assert_eq!(
            t, None,
            "claims, groups, and serials are not text to search"
        );
        let t = event_text(
            "access.request",
            &json!({ "reason": "INC-1 db down", "role": "prod-db", "resource": "orders" }),
        )
        .expect("text");
        assert!(t.contains("INC-1 db down"));
    }

    #[test]
    fn closing_events_are_not_indexed() {
        for kind in ["db.query.end", "web.response", "kafka.summary"] {
            assert_eq!(
                event_text(kind, &json!({ "statement": "x", "resource": "r" })),
                None
            );
        }
    }

    #[test]
    fn refusals_are_marked() {
        assert_eq!(outcome("auth.denied", &json!({})), "denied");
        assert_eq!(
            outcome("redis.command", &json!({ "phase": "denied" })),
            "denied"
        );
        assert_eq!(outcome("db.query", &json!({ "phase": "forwarded" })), "ok");
    }

    #[test]
    fn long_text_is_cut_on_a_character_boundary() {
        let t = event_text("db.query", &json!({ "statement": "é".repeat(10_000) })).expect("text");
        assert!(t.len() <= MAX_TEXT && t.chars().all(|c| c == 'é'));
    }
}
