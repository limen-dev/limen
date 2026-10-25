//! Searching audit events and recording text (ADR-0026) against a real
//! PostgreSQL. Set `LIMEN_TEST_DATABASE_URL` to run them.

// A whole control plane is started in each test.
#![allow(clippy::large_futures, clippy::assert_is_empty)]

mod common;

use common::{Harness, forwarded};
use limen_audit::{Event, EventKind, Producer};
use limen_control_plane::console::store::project_events;
use limen_control_plane::search;
use limen_proto::v1::SearchRequest;
use limen_proto::v1::audit_search_client::AuditSearchClient;
use limen_testkit::users::{ADMIN, AUDITOR, DEVELOPER};
use limen_tunnel::connect::TracedChannel as Channel;
use rustls_pki_types::CertificateDer;
use serde_json::json;
use tonic::Code;
use uuid::Uuid;

const POLICY: &str = r"
kind: resource
version: v1
metadata: { name: orders-prod, labels: { env: prod } }
spec: { postgres: { endpoint: 'db.internal:5432' } }
---
kind: role
version: v1
metadata: { name: dev }
spec:
  allow:
    - resources: { kind: [postgres], labels: { env: [prod] } }
      db: { roles: [limen_read], databases: ['*'] }
---
kind: role_mapping
version: v1
metadata: { name: m }
spec:
  - { idp_group: developers, roles: [dev] }
  - { idp_group: auditors, roles: ['limen:auditor'] }
";

struct Rig {
    h: Harness,
    ch: Channel,
    auditor: CertificateDer<'static>,
    admin: CertificateDer<'static>,
    dev: CertificateDer<'static>,
}

async fn rig(extra: &[String]) -> Option<Rig> {
    let h = Harness::start_with(extra).await?;
    h.set_policy(&[("p.yaml", POLICY)]);
    let (_, proxy) = h.enroll_proxy().await;
    let ch = h.channel(Some(proxy));
    let (_, auditor) = h.login(AUDITOR, &["auditors"]).await.expect("auditor");
    let (_, admin) = h.login(ADMIN, &["admins"]).await.expect("admin");
    let (_, dev) = h.login(DEVELOPER, &["developers"]).await.expect("dev");
    Some(Rig {
        h,
        ch,
        auditor,
        admin,
        dev,
    })
}

fn event(kind: EventKind, user: &str, session: Option<Uuid>, data: serde_json::Value) -> Event {
    let mut e = Event::new(
        kind,
        Producer {
            component: "worker".into(),
            instance_id: "w".into(),
            seq: 0,
        },
        data,
    );
    e.user = Some(user.into());
    e.session_id = session;
    e
}

impl Rig {
    async fn find(
        &self,
        who: &CertificateDer<'static>,
        query: &str,
    ) -> Result<limen_proto::v1::SearchResponse, tonic::Status> {
        AuditSearchClient::new(self.ch.clone())
            .search(forwarded(
                SearchRequest {
                    query: query.into(),
                    limit: 0,
                },
                Some(who),
            ))
            .await
            .map(tonic::Response::into_inner)
    }

    async fn texts(&self, query: &str) -> Vec<String> {
        self.find(&self.auditor, query)
            .await
            .expect("search")
            .hits
            .into_iter()
            .map(|h| format!("{}{}{}", h.before, h.matched, h.after))
            .collect()
    }

    async fn seed(&self) -> Uuid {
        let session = Uuid::now_v7();
        let events = vec![
            event(
                EventKind::SessionStart,
                DEVELOPER,
                Some(session),
                json!({ "kind": "postgres", "resource": "orders-prod", "db_role": "limen_read", "worker_id": "w" }),
            ),
            event(
                EventKind::DbQuery,
                DEVELOPER,
                Some(session),
                json!({ "resource": "orders-prod", "statement": "SELECT * FROM orders WHERE id = 5", "phase": "forwarded" }),
            ),
            event(
                EventKind::DbQuery,
                DEVELOPER,
                Some(session),
                json!({ "resource": "orders-prod", "statement": "DROP TABLE orders_2024", "phase": "forwarded" }),
            ),
            event(
                EventKind::DbQuery,
                ADMIN,
                None,
                json!({ "resource": "billing-prod", "statement": "CREATE USER x WITH PASSWORD 'hunter2'", "phase": "forwarded" }),
            ),
            event(
                EventKind::AuthDenied,
                DEVELOPER,
                None,
                json!({ "action": "ssh", "resource": "web-prod", "reason": "policy_denied" }),
            ),
            event(
                EventKind::DbQueryEnd,
                DEVELOPER,
                Some(session),
                json!({ "resource": "orders-prod", "statement": "must not be indexed", "status": "ok" }),
            ),
        ];
        project_events(&self.h.state.db, &events)
            .await
            .expect("project");
        session
    }
}

#[tokio::test]
async fn finding_a_statement_by_its_text() {
    let Some(r) = rig(&[]).await else { return };
    r.seed().await;
    // Substrings, case-insensitively, including punctuation.
    assert_eq!(r.texts("drop table").await.len(), 1);
    assert_eq!(r.texts("orders_2024").await.len(), 1);
    assert_eq!(r.texts("\"FROM orders WHERE\"").await.len(), 1);
    // Every word must appear.
    assert_eq!(r.texts("select drop").await.len(), 0);
    // The highlighted part is exactly what matched.
    let hit = &r.find(&r.auditor, "drop table").await.expect("search").hits[0];
    assert_eq!(hit.matched, "DROP TABLE");
    assert_eq!(hit.user, DEVELOPER);
    assert_eq!(hit.resource, "orders-prod");
    assert_eq!(hit.kind, "db.query");
    // Closing events aren't indexed.
    assert_eq!(r.texts("must not be indexed").await.len(), 0);
}

#[tokio::test]
async fn filters_narrow_the_search() {
    let Some(r) = rig(&[]).await else { return };
    r.seed().await;
    assert_eq!(r.texts("kind:db.query").await.len(), 3);
    assert_eq!(r.texts("kind:db.query resource:orders-prod").await.len(), 2);
    assert_eq!(
        r.texts(&format!("user:{} kind:db.query", ADMIN.to_uppercase()))
            .await
            .len(),
        1
    );
    assert_eq!(r.texts("outcome:denied").await.len(), 1);
    assert_eq!(r.texts("after:1h drop").await.len(), 1);
    assert_eq!(
        r.texts("before:1h drop").await.len(),
        0,
        "nothing older than an hour"
    );
    assert_eq!(r.texts("after:2020-01-01 kind:auth.denied").await.len(), 1);
}

#[tokio::test]
async fn secrets_are_masked_before_they_are_indexed() {
    let Some(r) = rig(&[]).await else { return };
    r.seed().await;
    assert_eq!(
        r.texts("hunter2").await.len(),
        0,
        "the password is not in the index"
    );
    let found = r.texts("create user x").await;
    assert_eq!(found.len(), 1);
    assert!(found[0].contains("[masked]"), "{found:?}");
}

#[tokio::test]
async fn a_hostile_query_is_just_text() {
    let Some(r) = rig(&[]).await else { return };
    r.seed().await;
    for q in [
        "'; DROP TABLE audit_search; --",
        "\" OR 1=1 --\"",
        "%",
        "\\",
        "a' || (SELECT pg_sleep(5)) || '",
    ] {
        let started = std::time::Instant::now();
        let hits = r.find(&r.auditor, q).await.expect(q).hits;
        assert_eq!(hits.len(), 0, "{q} matched {hits:?}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(3),
            "{q} was slow"
        );
    }
    // Wildcards in the query match themselves, not everything: `_` is in
    // three events' text, not in all five.
    let underscore = r.texts("_").await.len();
    assert!(underscore > 0 && underscore < 5, "{underscore}");
    assert_eq!(r.texts("100%").await.len(), 0);
    // The table is still there.
    assert_eq!(r.texts("drop table").await.len(), 1);
    // Bad syntax is the caller's mistake, not a crash.
    for q in ["user:", "\"open", "after:sometime", "kind:DB;"] {
        assert_eq!(
            r.find(&r.auditor, q).await.expect_err(q).code(),
            Code::InvalidArgument
        );
    }
    // An empty search would read everything: refused.
    assert_eq!(
        r.find(&r.auditor, "   ").await.expect_err("empty").code(),
        Code::InvalidArgument
    );
}

#[tokio::test]
async fn only_admins_and_auditors_search_and_every_search_is_audited() {
    let Some(r) = rig(&[]).await else { return };
    r.seed().await;
    let err = r
        .find(&r.dev, "drop")
        .await
        .expect_err("developers can't search");
    assert_eq!(err.code(), Code::PermissionDenied);
    r.find(&r.auditor, "drop table user:someone")
        .await
        .expect("auditor");
    r.find(&r.admin, "orders").await.expect("admin");
    let searches: Vec<Event> =
        r.h.audit_events()
            .await
            .into_iter()
            .filter(|e| e.kind == EventKind::AuditSearch)
            .collect();
    assert_eq!(searches.len(), 2, "the refused attempt is not a search");
    assert_eq!(searches[0].user.as_deref(), Some(AUDITOR));
    assert_eq!(searches[0].data["query"], "drop table user:someone");
    assert_eq!(searches[0].data["filters"]["users"][0], "someone");
    // Who looked for what, not what they found.
    assert!(searches[0].data.get("hits").is_none() && searches[0].data.get("results").is_none());
}

#[tokio::test]
async fn searching_is_rate_limited_per_person() {
    let Some(r) = rig(&[]).await else { return };
    let mut refused = 0;
    for _ in 0..25 {
        if let Err(e) = r.find(&r.auditor, "anything").await {
            assert_eq!(e.code(), Code::ResourceExhausted);
            refused += 1;
        }
    }
    assert!(
        refused > 0,
        "25 searches in a moment is more than the limit allows"
    );
    // Someone else has their own budget.
    r.find(&r.admin, "anything")
        .await
        .expect("the admin is not limited by the auditor's use");
}

#[tokio::test]
async fn a_hit_links_to_the_recording_at_that_moment() {
    let Some(r) = rig(&[]).await else { return };
    let session = Uuid::now_v7();
    let started = time::OffsetDateTime::now_utc() - time::Duration::minutes(10);
    let mut start = event(
        EventKind::SessionStart,
        DEVELOPER,
        Some(session),
        json!({ "kind": "postgres", "resource": "orders-prod", "db_role": "limen_read" }),
    );
    start.time = started;
    let mut query = event(
        EventKind::DbQuery,
        DEVELOPER,
        Some(session),
        json!({ "resource": "orders-prod", "statement": "DELETE FROM orders" }),
    );
    query.time = started + time::Duration::seconds(125);
    let mut recorded = event(
        EventKind::SessionRecording,
        DEVELOPER,
        Some(session),
        json!({ "recording_uri": "file:///x" }),
    );
    recorded.time = started + time::Duration::seconds(200);
    project_events(&r.h.state.db, &[start, query, recorded])
        .await
        .expect("project");
    // The session has a recording (projection fills the URI and hash).
    sqlx::query("UPDATE sessions SET recording_uri = 'file:///x', recording_sha256 = 'ab' WHERE session_id = $1")
        .bind(session)
        .execute(&r.h.state.db)
        .await
        .expect("recording");
    let hit = r
        .find(&r.auditor, "delete from orders")
        .await
        .expect("search")
        .hits
        .remove(0);
    assert_eq!(hit.session_id, session.to_string());
    // 125 s in, with a short lead-in so the moment is on screen.
    assert_eq!(hit.recording_offset_secs, 122);
    // A session without a recording has no offset.
    let other = r.seed().await;
    let hit = r
        .find(&r.auditor, "drop table")
        .await
        .expect("search")
        .hits
        .remove(0);
    assert_eq!(hit.session_id, other.to_string());
    assert_eq!(hit.recording_offset_secs, -1);
}

#[tokio::test]
async fn recording_text_is_found_only_when_indexed_and_never_unmasked() {
    let Some(r) = rig(&["--search-recordings".to_owned()]).await else {
        return;
    };
    assert!(r.h.state.config.search_recordings);
    let session = Uuid::now_v7();
    let mut start = event(
        EventKind::SessionStart,
        DEVELOPER,
        Some(session),
        json!({ "kind": "ssh", "resource": "web-prod", "login": "ubuntu" }),
    );
    start.time = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
    project_events(&r.h.state.db, &[start])
        .await
        .expect("project");
    let cast = [
        "{\"version\":3,\"term\":{\"cols\":80,\"rows\":24}}",
        "[0.5,\"o\",\"ubuntu@web:~$ \"]",
        "[1.0,\"i\",\"typed-secret\\r\"]",
        "[0.2,\"o\",\"cat /etc/passwd\\r\\n\"]",
        "[40.0,\"o\",\"export DB_PASSWORD=swordfish\\r\\nrm -rf /var/www/old-site\\r\\n\"]",
    ]
    .join("\n");
    let dir = limen_testkit::temp_dir().expect("dir");
    let file = dir.path().join("s.cast");
    std::fs::write(&file, cast).expect("write");
    search::index::index_recording(&r.h.state.db, session, &file)
        .await
        .expect("index");

    let hits = r.find(&r.auditor, "old-site").await.expect("search").hits;
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].kind, "recording.output");
    assert_eq!(hits[0].session_id, session.to_string());
    // The chunk starts when its first line did (0.5 s in); the lead-in floors at 0.
    assert_eq!(hits[0].recording_offset_secs, 0);
    // Input is never indexed; secrets on screen are masked.
    assert_eq!(r.texts("typed-secret").await.len(), 0);
    assert_eq!(r.texts("swordfish").await.len(), 0);
    // Filters apply to recordings too.
    assert_eq!(r.texts("old-site user:nobody@example.com").await.len(), 0);
    assert_eq!(r.texts("old-site resource:web-prod").await.len(), 1);
    assert_eq!(r.texts("old-site kind:db.query").await.len(), 0);
}

#[tokio::test]
async fn old_events_age_out_of_the_search_window() {
    let Some(r) = rig(&[]).await else { return };
    r.seed().await;
    sqlx::query(
        "UPDATE audit_search SET at = now() - interval '40 days' WHERE text ILIKE '%drop table%'",
    )
    .execute(&r.h.state.db)
    .await
    .expect("age");
    // The server's own trim job may get there first, so count what is left,
    // not what this call deleted.
    search::index::trim(&r.h.state.db, 30).await.expect("trim");
    assert_eq!(r.texts("drop table").await.len(), 0);
    assert_eq!(r.texts("select").await.len(), 1, "recent events stay");
}

#[tokio::test]
async fn the_history_link_is_offered_when_configured() {
    let Some(r) =
        rig(&["--search-history-url=https://athena.example/q?u={user}&q={query}".to_owned()]).await
    else {
        return;
    };
    r.seed().await;
    let resp = r.find(&r.auditor, "user:a@b.c drop").await.expect("search");
    assert_eq!(
        resp.history_url,
        "https://athena.example/q?u=a%40b.c&q=user%3Aa%40b.c+drop"
    );
}
