//! The console's `sessions` table is a projection of the audit stream. The
//! stream is delivered at least once and not necessarily in order, so the
//! projection must give the same answer however it arrives.

use limen_audit::{Event, EventKind, Producer};
use limen_control_plane::console::store::{self, SessionFilter};
use serde_json::json;
use sqlx::Connection;
use uuid::Uuid;

async fn fresh_db() -> Option<limen_control_plane::db::Db> {
    let base = limen_testkit::database_url()?;
    let mut conn = sqlx::PgConnection::connect(&base).await.expect("connect");
    let name = format!("limen_store_{}", Uuid::now_v7().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
        .execute(&mut conn)
        .await
        .expect("create db");
    let url = format!("{}/{name}", base.rsplit_once('/').expect("url").0);
    Some(
        limen_control_plane::db::connect(&url)
            .await
            .expect("migrate"),
    )
}

fn event(kind: EventKind, session: Uuid, user: &str, data: serde_json::Value) -> Event {
    let mut e = Event::new(
        kind,
        Producer {
            component: "proxy".into(),
            instance_id: "proxy-1".into(),
            seq: 0,
        },
        data,
    );
    e.user = Some(user.to_owned());
    e.session_id = Some(session);
    e
}

fn start(session: Uuid) -> Event {
    event(
        EventKind::SessionStart,
        session,
        "bob@example.com",
        json!({ "kind": "ssh", "resource": "web-1", "login": "ubuntu", "worker_id": "w1", "proxy_id": "p1", "client_addr": "10.0.0.9:5555" }),
    )
}

fn end(session: Uuid) -> Event {
    event(
        EventKind::SessionEnd,
        session,
        "bob@example.com",
        json!({ "kind": "ssh", "resource": "web-1", "login": "ubuntu", "worker_id": "w1", "reason": "user locked", "duration_ms": 1500, "bytes_in": 10, "bytes_out": 20, "recording_sha256": "abc" }),
    )
}

fn recording(session: Uuid) -> Event {
    event(
        EventKind::SessionRecording,
        session,
        "bob@example.com",
        json!({ "recording_uri": "file:///r/1.cast", "sha256": "abc" }),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn projection_is_idempotent_and_order_independent() {
    let Some(db) = fresh_db().await else { return };
    let (a, b) = (Uuid::now_v7(), Uuid::now_v7());

    // Session a: in order. Session b: the recording first, then the end, then
    // the start, with everything delivered twice.
    store::project_events(&db, &[start(a), end(a), recording(a)])
        .await
        .expect("a");
    let b_events = [recording(b), end(b), start(b)];
    store::project_events(&db, &b_events).await.expect("b");
    store::project_events(&db, &b_events)
        .await
        .expect("b again");
    store::project_events(&db, &[start(a), end(a), recording(a)])
        .await
        .expect("a again");

    for id in [a, b] {
        let s = store::session(&db, id).await.expect("query").expect("row");
        assert_eq!(s.username.as_deref(), Some("bob@example.com"));
        assert_eq!(s.resource.as_deref(), Some("web-1"));
        assert_eq!(s.login.as_deref(), Some("ubuntu"));
        assert_eq!(s.worker_id.as_deref(), Some("w1"));
        assert_eq!(s.proxy_id.as_deref(), Some("p1"));
        assert_eq!(s.client_addr.as_deref(), Some("10.0.0.9:5555"));
        assert!(s.started_at.is_some() && s.ended_at.is_some());
        assert_eq!(s.end_reason.as_deref(), Some("user locked"));
        assert_eq!(s.duration_ms, Some(1500));
        assert_eq!(s.recording_uri.as_deref(), Some("file:///r/1.cast"));
        assert_eq!(s.recording_sha256.as_deref(), Some("abc"));
        assert!(!s.active, "ended sessions aren't active");
    }
    let all = store::list_sessions(
        &db,
        &SessionFilter {
            limit: 50,
            ..SessionFilter::default()
        },
    )
    .await
    .expect("list");
    assert_eq!(all.len(), 2, "no duplicates");
}

#[tokio::test(flavor = "multi_thread")]
async fn active_sessions_and_user_filter() {
    let Some(db) = fresh_db().await else { return };
    let (open, done, other) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
    let mut carol = start(other);
    carol.user = Some("carol@example.com".into());
    store::project_events(&db, &[start(open), start(done), end(done), carol])
        .await
        .expect("project");

    let active = store::list_sessions(
        &db,
        &SessionFilter {
            active_only: true,
            limit: 50,
            ..SessionFilter::default()
        },
    )
    .await
    .expect("active");
    let ids: Vec<_> = active.iter().map(|s| s.session_id).collect();
    assert!(ids.contains(&open) && ids.contains(&other) && !ids.contains(&done));
    assert_eq!(store::active_session_count(&db).await.expect("count"), 2);

    let carols = store::list_sessions(
        &db,
        &SessionFilter {
            username: Some("carol@example.com".into()),
            limit: 50,
            ..SessionFilter::default()
        },
    )
    .await
    .expect("carol");
    assert_eq!(carols.len(), 1);
    assert_eq!(carols[0].session_id, other);

    // A session that started long ago and never ended isn't "active".
    sqlx::query("UPDATE sessions SET started_at = now() - interval '3 days' WHERE session_id = $1")
        .bind(open)
        .execute(&db)
        .await
        .expect("age it");
    let s = store::session(&db, open).await.expect("q").expect("row");
    assert!(!s.active, "stale open sessions are shown as unknown");
}

#[tokio::test(flavor = "multi_thread")]
async fn login_state_is_single_use_and_expires() {
    let Some(db) = fresh_db().await else { return };
    let soon = time::OffsetDateTime::now_utc() + time::Duration::minutes(5);
    store::insert_login(&db, b"state-1", "nonce", "verifier", soon)
        .await
        .expect("insert");
    assert_eq!(
        store::take_login(&db, b"state-1").await.expect("take"),
        Some(("nonce".into(), "verifier".into()))
    );
    assert_eq!(
        store::take_login(&db, b"state-1").await.expect("again"),
        None
    );

    let past = time::OffsetDateTime::now_utc() - time::Duration::minutes(1);
    store::insert_login(&db, b"state-2", "n", "v", past)
        .await
        .expect("insert");
    assert_eq!(
        store::take_login(&db, b"state-2").await.expect("expired"),
        None
    );
}
