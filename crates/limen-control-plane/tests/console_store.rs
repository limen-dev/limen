//! The console's `sessions` table is a projection of the audit stream. The
//! stream is delivered at least once and not necessarily in order, so the
//! projection must give the same answer however it arrives.

use limen_audit::{Event, EventKind, Producer};
use limen_control_plane::console::store::{self, SessionFilter};
use limen_testkit::users::{DEVELOPER, GUEST};
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
        DEVELOPER,
        json!({ "kind": "ssh", "resource": "web-1", "login": "ubuntu", "worker_id": "w1", "proxy_id": "p1", "client_addr": "10.0.0.9:5555" }),
    )
}

fn end(session: Uuid) -> Event {
    event(
        EventKind::SessionEnd,
        session,
        DEVELOPER,
        json!({ "kind": "ssh", "resource": "web-1", "login": "ubuntu", "worker_id": "w1", "reason": "user locked", "duration_ms": 1500, "bytes_in": 10, "bytes_out": 20, "recording_sha256": "abc" }),
    )
}

fn recording(session: Uuid) -> Event {
    event(
        EventKind::SessionRecording,
        session,
        DEVELOPER,
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
        assert_eq!(s.username.as_deref(), Some(DEVELOPER));
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
    let mut guest_user = start(other);
    guest_user.user = Some(GUEST.into());
    store::project_events(&db, &[start(open), start(done), end(done), guest_user])
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
            username: Some(GUEST.into()),
            limit: 50,
            ..SessionFilter::default()
        },
    )
    .await
    .expect("guest");
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

/// A database session has no recording; the console lists its statements and
/// how each ended, from the audit events, in any order of arrival.
#[tokio::test(flavor = "multi_thread")]
async fn database_sessions_list_their_statements() {
    let Some(db) = fresh_db().await else { return };
    let s = Uuid::now_v7();
    let query = |text: &str| {
        event(
            EventKind::DbQuery,
            s,
            DEVELOPER,
            json!({ "protocol": "mysql", "phase": "simple", "statement_type": "select", "statement": text, "db_role": "limen_rw", "database": "orders" }),
        )
    };
    let end_of = |q: &Event, status: &str, rows: i64| {
        let mut data = json!({ "protocol": "mysql", "status": status, "rows": rows, "duration_ms": 7, "query_id": q.event_id });
        if status == "error" {
            data["error_code"] = json!("42S02");
            data["error"] = json!("Table 'orders.nope' doesn't exist");
        }
        event(EventKind::DbQueryEnd, s, DEVELOPER, data)
    };
    let (q1, q2, q3) = (
        query("select 1"),
        query("select * from nope"),
        query("select 2"),
    );
    // The second statement's end arrives before the statement itself.
    store::project_events(
        &db,
        &[q1.clone(), end_of(&q1, "ok", 1), end_of(&q2, "error", 0)],
    )
    .await
    .expect("first batch");
    store::project_events(&db, &[q2.clone(), q3.clone(), end_of(&q3, "ok", 1)])
        .await
        .expect("second batch");
    // Redelivery changes nothing.
    store::project_events(&db, &[q1, end_of(&q2, "error", 0)])
        .await
        .expect("redelivery");

    let list = store::db_statements(&db, s, 100).await.expect("statements");
    let texts: Vec<_> = list
        .iter()
        .map(|r| r.statement.as_deref().unwrap_or_default())
        .collect();
    assert_eq!(texts, ["select 1", "select * from nope", "select 2"]);
    assert_eq!(list[1].status.as_deref(), Some("error"));
    assert_eq!(list[1].error_code.as_deref(), Some("42S02"));
    assert_eq!(list[0].rows, Some(1));
    assert_eq!(
        store::db_session_counts(&db, s).await.expect("counts"),
        (3, 1)
    );

    // The audit trail table keeps no statement text.
    let leaked: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE summary LIKE '%select%'")
            .fetch_one(&db)
            .await
            .expect("scan");
    assert_eq!(leaked, 0);
    // Statement text expires with the audit events: after 30 days it is deleted.
    let old = Uuid::now_v7();
    let mut stale = event(
        EventKind::DbQuery,
        old,
        DEVELOPER,
        json!({ "phase": "simple", "statement_type": "select", "statement": "select 'old'" }),
    );
    stale.time = time::OffsetDateTime::now_utc() - time::Duration::days(31);
    store::project_events(&db, &[stale]).await.expect("old");
    assert_eq!(
        store::db_statements(&db, old, 10).await.expect("old").len(),
        1
    );
    limen_control_plane::db::cleanup(&db)
        .await
        .expect("cleanup");
    assert!(
        store::db_statements(&db, old, 10)
            .await
            .expect("gone")
            .is_empty()
    );
    assert_eq!(
        store::db_statements(&db, s, 10)
            .await
            .expect("recent")
            .len(),
        3
    );
    // A session that never ran anything has nothing.
    let none = Uuid::now_v7();
    assert!(
        store::db_statements(&db, none, 10)
            .await
            .expect("none")
            .is_empty()
    );
}

/// A Redis session has no recording; the console lists its commands (keys,
/// never values) and the ones policy refused, whatever order they arrive in.
#[tokio::test(flavor = "multi_thread")]
async fn redis_sessions_list_their_commands() {
    let Some(db) = fresh_db().await else { return };
    let s = Uuid::now_v7();
    let get = event(
        EventKind::RedisCommand,
        s,
        DEVELOPER,
        json!({ "command": "GET", "subcommand": null, "keys": ["app:greeting"], "keys_total": 1, "keys_known": true, "arity": 2, "resource": "cache-staging", "redis_user": "limen-ro" }),
    );
    let del = event(
        EventKind::RedisCommand,
        s,
        DEVELOPER,
        json!({ "command": "DEL", "keys": ["a", "b"], "keys_total": 250, "keys_known": true, "arity": 251 }),
    );
    let refused = event(
        EventKind::AuthDenied,
        s,
        DEVELOPER,
        json!({ "action": "redis", "resource": "cache-staging", "redis_user": "limen-ro", "command": "FLUSHALL", "subcommand": null, "reason": "FLUSHALL is denied unless the role lists it in redis.allow_commands" }),
    );
    // An auth.denied that is not about Redis is not a command.
    let other = event(
        EventKind::AuthDenied,
        s,
        DEVELOPER,
        json!({ "action": "ssh", "resource": "web", "login": "root", "reason": "no" }),
    );
    store::project_events(&db, &[refused.clone(), get.clone()])
        .await
        .expect("first batch");
    store::project_events(&db, &[del, other, get, refused])
        .await
        .expect("second batch and redelivery");

    let list = store::db_statements(&db, s, 100).await.expect("commands");
    let texts: Vec<_> = list
        .iter()
        .map(|r| r.statement.as_deref().unwrap_or_default())
        .collect();
    assert_eq!(texts.len(), 3, "{texts:?}");
    assert!(texts.contains(&"GET app:greeting"));
    assert!(texts.contains(&"FLUSHALL"));
    assert!(texts.contains(&"DEL a b … (+248 more keys)"), "{texts:?}");
    let flush = list
        .iter()
        .find(|r| r.statement.as_deref() == Some("FLUSHALL"))
        .expect("refused command");
    assert_eq!(flush.status.as_deref(), Some("denied"));
    let allowed = list
        .iter()
        .find(|r| r.statement.as_deref() == Some("GET app:greeting"))
        .expect("allowed command");
    assert_eq!(allowed.status.as_deref(), Some("allowed"));
    assert!(
        flush
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("denied")
    );
    assert_eq!(
        store::db_session_counts(&db, s).await.expect("counts"),
        (3, 1)
    );
}

fn kube_request(
    user: &str,
    cluster: &str,
    verb: &str,
    resource: &str,
    name: &str,
    status: u16,
) -> Event {
    let mut e = event(
        EventKind::KubeRequest,
        Uuid::now_v7(),
        user,
        json!({
            "kind": "kube", "resource": cluster, "verb": verb, "k8s_resource": resource,
            "k8s_group": "", "subresource": "", "namespace": "default", "name": name,
            "method": "GET", "status": status, "latency_ms": 12,
            // Not part of the view, and must not be kept.
            "path": "/api/v1/namespaces/default/pods?labelSelector=secret=1", "groups": ["limen:edit"],
        }),
    );
    e.session_id = Some(Uuid::now_v7());
    e
}

/// `GET /version?x=1`: no resource, so the path (without its query) is kept.
fn version_request() -> Event {
    event(
        EventKind::KubeRequest,
        Uuid::now_v7(),
        DEVELOPER,
        json!({ "kind": "kube", "resource": "eks-dev", "verb": "get", "method": "GET",
                "path": "/version?token=hunter2", "status": 200 }),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn kubernetes_requests_are_listed_in_kubectls_terms() {
    let Some(db) = fresh_db().await else { return };
    let events = [
        kube_request(DEVELOPER, "eks-dev", "list", "pods", "", 200),
        kube_request(DEVELOPER, "eks-dev", "delete", "pods", "web", 403),
        kube_request(GUEST, "eks-prod", "get", "secrets", "db", 200),
        version_request(),
    ];
    // Delivered twice: the projection is idempotent.
    store::project_events(&db, &events).await.expect("first");
    store::project_events(&db, &events).await.expect("again");

    let all = store::list_kube_requests(
        &db,
        &store::KubeFilter {
            limit: 50,
            ..store::KubeFilter::default()
        },
    )
    .await
    .expect("list");
    assert_eq!(all.len(), 4);
    let version = all.iter().find(|r| r.resource.is_empty()).expect("version");
    assert_eq!(version.path, "/version");

    let problems = store::list_kube_requests(
        &db,
        &store::KubeFilter {
            problems_only: true,
            limit: 50,
            ..store::KubeFilter::default()
        },
    )
    .await
    .expect("problems");
    assert_eq!(problems.len(), 1);
    assert_eq!(
        (problems[0].verb.as_str(), problems[0].name.as_str()),
        ("delete", "web")
    );
    assert_eq!(problems[0].status, 403);

    let prod = store::list_kube_requests(
        &db,
        &store::KubeFilter {
            cluster: Some("eks-prod".into()),
            username: Some(GUEST.into()),
            limit: 50,
            ..store::KubeFilter::default()
        },
    )
    .await
    .expect("prod");
    assert_eq!(prod.len(), 1);
    assert_eq!(prod[0].resource, "secrets");

    let (clusters, verbs) = store::kube_filter_options(&db).await.expect("options");
    assert_eq!(clusters, ["eks-dev", "eks-prod"]);
    assert_eq!(verbs, ["delete", "get", "list"]);

    // Only the request's shape is kept, never the query string.
    let kept: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM kube_requests WHERE row_to_json(kube_requests)::text LIKE '%secret=1%' OR row_to_json(kube_requests)::text LIKE '%hunter2%'",
    )
    .fetch_one(&db)
    .await
    .expect("count");
    assert_eq!(kept, 0);
}

fn login_request(login: &str, cluster: &str, verb: &str, status: u16, seconds: i64) -> Event {
    let mut e = kube_request(DEVELOPER, cluster, verb, "pods", "web", status);
    e.data["login_id"] = json!(login);
    e.data["worker_id"] = json!("w1");
    e.data["proxy_id"] = json!("p1");
    e.time += time::Duration::seconds(seconds);
    e
}

#[tokio::test(flavor = "multi_thread")]
async fn one_login_on_one_cluster_is_one_kubectl_session() {
    let Some(db) = fresh_db().await else { return };
    let (a0, a1, a2) = (
        login_request("login-a", "eks-dev", "list", 200, 0),
        login_request("login-a", "eks-dev", "get", 200, 30),
        login_request("login-a", "eks-dev", "delete", 403, 90),
    );
    let other_login = login_request("login-b", "eks-dev", "get", 200, 10);
    let other_cluster = login_request("login-a", "eks-prod", "get", 200, 20);
    let no_login = kube_request(DEVELOPER, "eks-dev", "get", "pods", "web", 200);

    // Out of order, and some delivered twice.
    store::project_events(
        &db,
        &[a2.clone(), a0.clone(), other_login, other_cluster, no_login],
    )
    .await
    .expect("first batch");
    store::project_events(&db, &[a1, a0, a2])
        .await
        .expect("second batch");

    let sessions = store::list_sessions(
        &db,
        &SessionFilter {
            limit: 50,
            ..SessionFilter::default()
        },
    )
    .await
    .expect("sessions");
    // login-a/eks-dev, login-b/eks-dev, login-a/eks-prod. The event without a
    // login (from before workers named it) belongs to no session.
    assert_eq!(sessions.len(), 3, "{sessions:#?}");
    assert!(
        sessions
            .iter()
            .all(|s| s.kind.as_deref() == Some("kubectl"))
    );

    let main = sessions
        .iter()
        .find(|s| s.duration_ms == Some(90_000))
        .expect("the 90 second session");
    assert_eq!(main.resource.as_deref(), Some("eks-dev"));
    assert_eq!(main.username.as_deref(), Some(DEVELOPER));
    // The events are from just now, so the session is live.
    assert!(main.active);

    let (total, problems) = store::kube_session_counts(&db, main.session_id)
        .await
        .expect("counts");
    assert_eq!((total, problems), (3, 1));
    let requests = store::list_kube_requests(
        &db,
        &store::KubeFilter {
            login_session: Some(main.session_id),
            limit: 50,
            ..store::KubeFilter::default()
        },
    )
    .await
    .expect("requests");
    let verbs: Vec<_> = requests.iter().map(|r| r.verb.as_str()).collect();
    assert_eq!(verbs, ["list", "get", "delete"], "oldest first");
}

#[tokio::test(flavor = "multi_thread")]
async fn logging_out_ends_the_kubectl_session_at_once() {
    let Some(db) = fresh_db().await else { return };
    store::project_events(
        &db,
        &[
            login_request("login-a", "eks-dev", "list", 200, 0),
            login_request("login-b", "eks-dev", "list", 200, 0),
        ],
    )
    .await
    .expect("project");
    let list = |db: &limen_control_plane::db::Db| {
        let db = db.clone();
        async move {
            store::list_sessions(
                &db,
                &SessionFilter {
                    limit: 50,
                    ..SessionFilter::default()
                },
            )
            .await
            .expect("sessions")
        }
    };
    let before = list(&db).await;
    assert_eq!(before.len(), 2);
    assert!(before.iter().all(|s| s.active && s.logged_out_at.is_none()));
    assert_eq!(store::active_session_count(&db).await.expect("count"), 2);

    assert!(
        limen_control_plane::db::revoke_login(
            &db,
            "login-a",
            DEVELOPER,
            time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        )
        .await
        .expect("logout")
    );
    let after = list(&db).await;
    let active: Vec<_> = after.iter().filter(|s| s.active).collect();
    assert_eq!(active.len(), 1, "only the other login is live");
    let ended = after.iter().find(|s| !s.active).expect("ended");
    assert!(ended.logged_out_at.is_some());
    assert_eq!(store::active_session_count(&db).await.expect("count"), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_logout_is_remembered_as_long_as_the_certificate_lives() {
    let Some(db) = fresh_db().await else { return };
    let now = time::OffsetDateTime::now_utc();
    // A certificate with weeks left (a long configured lifetime) and one that
    // expired days ago.
    for (login, expires) in [
        ("long-lived", now + time::Duration::days(20)),
        ("long-gone", now - time::Duration::days(3)),
    ] {
        assert!(
            limen_control_plane::db::revoke_login(&db, login, DEVELOPER, expires)
                .await
                .expect("logout")
        );
    }
    // Backdate both logouts: a fixed window would have forgotten them.
    sqlx::query("UPDATE login_revocations SET revoked_at = now() - interval '5 days'")
        .execute(&db)
        .await
        .expect("backdate");
    let remembered = limen_control_plane::db::recent_revoked_logins(&db)
        .await
        .expect("recent");
    assert_eq!(remembered, ["long-lived"]);
}
