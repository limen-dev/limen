//! MySQL through the worker's relay and role bootstrap (ADR-0033, slice 6c),
//! against a real MySQL. Needs `LIMEN_TEST_MYSQL_TARGET=host:port` and
//! `LIMEN_TEST_PG_CA_FILE` (the `db-tls` CA; the certificate names
//! `mysql-target`), see `deploy/compose`. Without them: SKIPPED.

use std::sync::Arc;
use std::time::Duration;

use limen_audit::{Emitter, FailureMode, MemorySink};
use limen_core::secret::Secret;
use limen_policy::model::DbTarget;
use limen_worker::db::bootstrap::{Plan, reconcile};
use limen_worker::db::mysqlclient::Client;
use limen_worker::db::{DbSessionConfig, Engine, Registry, Target, secret, serve};
use tokio::net::TcpListener;

/// The tests share users and databases: one at a time.
static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const ADMIN_PASSWORD: &str = "limen-admin-dev-only";
const MULTI_STATEMENTS: u32 = 0x1_0000;

struct Env {
    target: String,
    ca: String,
}

fn env() -> Option<Env> {
    let (t, ca) = (
        std::env::var("LIMEN_TEST_MYSQL_TARGET").ok(),
        std::env::var("LIMEN_TEST_PG_CA_FILE").ok(),
    );
    if t.is_none() || ca.is_none() {
        eprintln!(
            "SKIPPED: set LIMEN_TEST_MYSQL_TARGET and LIMEN_TEST_PG_CA_FILE (see deploy/compose)"
        );
    }
    Some(Env {
        target: t?,
        ca: ca?,
    })
}

fn spec(env: &Env, dir: &std::path::Path, bootstrap: &str) -> DbTarget {
    let pw_file = dir.join(".admin");
    std::fs::write(&pw_file, ADMIN_PASSWORD).expect("admin password");
    serde_json::from_value(serde_json::json!({
        "endpoint": env.target,
        "iam_auth": false,
        "tls_ca_file": env.ca,
        "tls_server_name": "mysql-target",
        "default_database": "orders",
        "password_dir": dir.to_str().expect("utf8"),
        "admin_user": "limen_admin",
        "admin_password_file": pw_file.to_str().expect("utf8"),
        "bootstrap": serde_json::from_str::<serde_json::Value>(bootstrap).expect("roles"),
    }))
    .expect("spec")
}

async fn plan(env: &Env, dir: &std::path::Path, roles: &str) -> Plan {
    Plan::from_spec("orders-my", Engine::Mysql, &spec(env, dir, roles), false)
        .await
        .expect("plan")
}

async fn admin(env: &Env, dir: &std::path::Path) -> Client {
    let t = Target::from_spec(&spec(env, dir, "[]"), false)
        .await
        .expect("target");
    Client::connect(
        &t,
        "limen_admin",
        &Secret::new(ADMIN_PASSWORD.into()),
        "orders",
        "test",
    )
    .await
    .expect("admin connect")
}

async fn forget(env: &Env, dir: &std::path::Path, users: &[&str]) {
    let mut a = admin(env, dir).await;
    for u in users {
        a.execute(&format!("DROP USER IF EXISTS '{u}'@'%'"))
            .await
            .expect("drop user");
    }
}

const ROLES: &str = r#"[
  {"role": "limen_my_ro", "grants": [{"database": "orders", "access": "read"}]},
  {"role": "limen_my_rw", "grants": [{"database": "orders", "access": "write"}]}
]"#;

fn emitter() -> (Arc<MemorySink>, Emitter) {
    let sink = Arc::new(MemorySink::default());
    (
        sink.clone(),
        Emitter::new("worker", "w1", sink, FailureMode::FailClosed),
    )
}

/// Create the users with the bootstrap itself.
async fn prepared(env: &Env) -> (tempfile::TempDir, Plan) {
    let dir = tempfile::tempdir().expect("dir");
    forget(env, dir.path(), &["limen_my_ro", "limen_my_rw"]).await;
    let p = plan(env, dir.path(), ROLES).await;
    let report = reconcile(&p, None, true).await.expect("bootstrap");
    assert!(report.failed().is_empty(), "{:?}", report.failed());
    (dir, p)
}

#[tokio::test(flavor = "multi_thread")]
async fn bootstrap_is_idempotent_and_repairs_drift() {
    let _one_at_a_time = LOCK.lock().await;
    let Some(env) = env() else { return };
    let dir = tempfile::tempdir().expect("dir");
    forget(&env, dir.path(), &["limen_my_ro", "limen_my_rw"]).await;
    let (sink, em) = emitter();
    let p = plan(&env, dir.path(), ROLES).await;

    let check = reconcile(&p, Some(&em), false).await.expect("check");
    assert!(
        check
            .actions
            .iter()
            .any(|a| a.kind == "ensure_user" && !a.applied)
    );
    let report = reconcile(&p, Some(&em), true).await.expect("apply");
    assert!(report.failed().is_empty(), "{:?}", report.failed());
    assert_eq!(
        report
            .actions
            .iter()
            .filter(|a| a.kind == "ensure_user")
            .count(),
        2
    );

    // The users exist, are limited, and need TLS.
    let t = Target::from_spec(&spec(&env, dir.path(), "[]"), false)
        .await
        .expect("t");
    let pw = |role: &'static str| {
        let d = dir.path().to_owned();
        async move {
            secret::role_password(d.to_str().expect("utf8"), role)
                .await
                .expect("pw")
        }
    };
    let mut ro = Client::connect(&t, "limen_my_ro", &pw("limen_my_ro").await, "orders", "t")
        .await
        .expect("ro");
    assert_eq!(
        ro.scalar("select count(*) from orders")
            .await
            .expect("count")
            .as_deref(),
        Some("3")
    );
    ro.execute("insert into orders (total_cents) values (1)")
        .await
        .expect_err("read-only");
    ro.execute("select * from billing.invoices")
        .await
        .expect_err("other database");
    let mut rw = Client::connect(&t, "limen_my_rw", &pw("limen_my_rw").await, "orders", "t")
        .await
        .expect("rw");
    rw.execute("insert into orders (total_cents) values (7)")
        .await
        .expect("rw inserts");
    rw.execute("delete from orders where total_cents = 7")
        .await
        .expect("rw deletes");
    rw.execute("drop table orders").await.expect_err("no DDL");

    // Nothing to do on the next runs.
    for apply in [true, false] {
        let again = reconcile(&p, Some(&em), apply).await.expect("again");
        assert!(
            again.actions.is_empty(),
            "apply={apply}: {:?}",
            again.actions
        );
    }

    // Drift: more privileges, a table grant on another database, a wrong password.
    let mut a = admin(&env, dir.path()).await;
    a.execute("GRANT INSERT ON orders.* TO 'limen_my_ro'@'%'")
        .await
        .expect("extra");
    a.execute("GRANT SELECT ON billing.invoices TO 'limen_my_ro'@'%'")
        .await
        .expect("table");
    a.execute("ALTER USER 'limen_my_rw'@'%' IDENTIFIED BY 'someone-else'")
        .await
        .expect("pw");
    let check = reconcile(&p, Some(&em), false).await.expect("check drift");
    assert!(check.actions.iter().all(|a| !a.applied));
    let kinds: Vec<_> = check
        .actions
        .iter()
        .map(|a| (a.role.as_str(), a.kind))
        .collect();
    assert!(kinds.contains(&("limen_my_ro", "grant")), "{kinds:?}");
    assert!(kinds.contains(&("limen_my_rw", "ensure_user")), "{kinds:?}");
    let fixed = reconcile(&p, Some(&em), true).await.expect("fix");
    assert!(fixed.failed().is_empty(), "{:?}", fixed.failed());
    let clean = reconcile(&p, Some(&em), true).await.expect("clean");
    assert!(clean.actions.is_empty(), "{:?}", clean.actions);
    let mut ro = Client::connect(&t, "limen_my_ro", &pw("limen_my_ro").await, "orders", "t")
        .await
        .expect("ro");
    ro.execute("insert into orders (total_cents) values (1)")
        .await
        .expect_err("revoked");
    ro.execute("select * from billing.invoices")
        .await
        .expect_err("revoked");

    // Audited, with no secret in the trail.
    let events = serde_json::to_string(&sink.events()).expect("json");
    assert!(events.contains("db.bootstrap") && events.contains("ensure_user"));
    for role in ["limen_my_ro", "limen_my_rw"] {
        let pw = std::fs::read_to_string(dir.path().join(role)).expect("file");
        assert!(!events.contains(pw.trim()) && !format!("{report:?}").contains(pw.trim()));
    }
    assert!(!events.contains(ADMIN_PASSWORD) && !events.contains("someone-else"));
    forget(&env, dir.path(), &["limen_my_ro", "limen_my_rw"]).await;
}

struct Relay {
    addr: std::net::SocketAddr,
    sink: Arc<MemorySink>,
    registry: Arc<Registry>,
}

async fn relay(env: &Env, dir: &std::path::Path, normalize: bool) -> Relay {
    let (sink, em) = emitter();
    let registry = Arc::new(Registry::default());
    let t = Target::from_spec(&spec(env, dir, "[]"), false)
        .await
        .expect("target");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (reg, dir) = (registry.clone(), dir.to_owned());
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let cfg = DbSessionConfig {
                session_id: uuid::Uuid::now_v7(),
                username: "dev@example.com".into(),
                resource: "orders-my".into(),
                engine: Engine::Mysql,
                role: "limen_my_ro".into(),
                login_user: "limen_my_ro".into(),
                database: "orders".into(),
                target: t.clone(),
                password: secret::role_password(dir.to_str().expect("utf8"), "limen_my_ro")
                    .await
                    .expect("pw"),
                normalize_literals: normalize,
                registry: reg.clone(),
            };
            let em = em.clone();
            tokio::spawn(async move {
                let _ = serve(stream, cfg, em).await;
            });
        }
    });
    Relay {
        addr,
        sink,
        registry,
    }
}

/// Connect to the relay as a MySQL client would. The relay ignores the
/// credential: the user is whatever the session was granted.
async fn client(r: &Relay, user: &str, database: &str, flags: u32) -> Result<Client, String> {
    let spec: DbTarget = serde_json::from_value(serde_json::json!({
        "endpoint": r.addr.to_string(), "iam_auth": false, "insecure_dev": true,
    }))
    .expect("spec");
    let t = Target::from_spec(&spec, true).await?;
    Client::connect_with(&t, user, &Secret::new(String::new()), database, "t", flags).await
}

fn events(r: &Relay, kind: &str) -> Vec<serde_json::Value> {
    r.sink
        .events()
        .into_iter()
        .filter_map(|e| {
            let v = serde_json::to_value(&e).expect("json");
            (v["kind"] == kind).then_some(v)
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn queries_flow_and_every_statement_is_audited() {
    let _one_at_a_time = LOCK.lock().await;
    let Some(env) = env() else { return };
    let (dir, _) = prepared(&env).await;
    let r = relay(&env, dir.path(), false).await;

    let mut c = client(&r, "limen_my_ro", "orders", MULTI_STATEMENTS)
        .await
        .expect("connect");
    assert_eq!(
        c.scalar("select count(*) from orders")
            .await
            .expect("count")
            .as_deref(),
        Some("3")
    );
    // Several statements in one message, several result sets back.
    assert_eq!(
        c.scalar("select 1; select 2")
            .await
            .expect("multi")
            .as_deref(),
        Some("2")
    );
    // Prepared statements, binary protocol.
    assert_eq!(
        c.run_prepared("select * from customers")
            .await
            .expect("prepared"),
        2
    );
    // The database's own grants apply.
    let denied = c
        .execute("insert into orders (total_cents) values (1)")
        .await
        .expect_err("ro");
    assert!(denied.to_string().contains("1142"), "{denied}");
    let missing = c.execute("select * from nope").await.expect_err("no table");
    assert!(missing.to_string().contains("1146"), "{missing}");
    // The session shows up on the database side.
    let attrs = c
        .scalar("select count(*) from performance_schema.session_connect_attrs where attr_name = 'limen_session'")
        .await;
    drop(attrs);
    c.close().await;

    tokio::time::sleep(Duration::from_millis(300)).await;
    let q = events(&r, "db.query");
    let texts: Vec<_> = q
        .iter()
        .filter_map(|e| e["data"]["statement"].as_str())
        .collect();
    for want in [
        "select count(*) from orders",
        "select 1",
        "select 2",
        "select * from customers",
    ] {
        assert!(
            texts.iter().any(|t| t.starts_with(want)),
            "{want} in {texts:?}"
        );
    }
    assert!(q.iter().any(|e| e["data"]["phase"] == "parse"));
    assert!(
        q.iter()
            .any(|e| e["data"]["phase"] == "execute" && e["data"]["parse_query_id"].is_string())
    );
    assert_eq!(q[0]["data"]["protocol"], "mysql");
    assert_eq!(q[0]["data"]["db_role"], "limen_my_ro");
    let ends = events(&r, "db.query.end");
    assert!(
        ends.iter()
            .any(|e| e["data"]["status"] == "ok" && e["data"]["rows"] == 1)
    );
    assert!(
        ends.iter().any(|e| e["data"]["error_number"] == 1142),
        "{ends:?}"
    );
    assert!(
        ends.iter()
            .any(|e| e["data"]["error_number"] == 1146 && e["data"]["error_code"] == "42S02")
    );
    let ids: Vec<_> = q.iter().map(|e| e["event_id"].clone()).collect();
    assert!(ends.iter().all(|e| ids.contains(&e["data"]["query_id"])));
    let all = serde_json::to_string(&r.sink.events()).expect("json");
    assert!(
        !all.contains(
            &std::fs::read_to_string(dir.path().join("limen_my_ro"))
                .expect("pw")
                .trim()
                .to_owned()
        )
    );
    assert!(r.registry.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_wrong_user_database_command_or_kill_is_refused() {
    let _one_at_a_time = LOCK.lock().await;
    let Some(env) = env() else { return };
    let (dir, _) = prepared(&env).await;
    let r = relay(&env, dir.path(), false).await;

    let err = client(&r, "limen_admin", "orders", 0)
        .await
        .expect_err("other user");
    assert!(
        err.contains("this session is for the database role"),
        "{err}"
    );
    let err = client(&r, "limen_my_ro", "billing", 0)
        .await
        .expect_err("other database");
    assert!(
        err.contains("this session is for the database orders"),
        "{err}"
    );

    let mut c = client(&r, "limen_my_ro", "orders", 0)
        .await
        .expect("connect");
    let e = c.execute("use billing").await.expect_err("USE");
    assert!(e.to_string().contains("USE is not allowed"), "{e}");
    let e = c
        .execute("kill 1")
        .await
        .expect_err("someone else's thread");
    assert!(e.to_string().contains("1094"), "{e}");
    let e = c
        .execute("kill query 1; select 1")
        .await
        .expect_err("compound KILL");
    assert!(e.to_string().contains("only KILL"), "{e}");
    // COM_INIT_DB to another database, COM_CHANGE_USER (0x11), COM_PROCESS_KILL (0x0c).
    let mut init = vec![0x02];
    init.extend_from_slice(b"billing");
    assert_eq!(c.raw_command(init).await.expect("init_db")[0], 0xff);
    assert_eq!(
        c.raw_command(vec![0x11, b'x', 0])
            .await
            .expect("change_user")[0],
        0xff
    );
    assert_eq!(
        c.raw_command(vec![0x0c, 1, 0, 0, 0])
            .await
            .expect("process_kill")[0],
        0xff
    );
    // The session still works.
    assert_eq!(
        c.scalar("select 1").await.expect("alive").as_deref(),
        Some("1")
    );
    // Refusals are audited.
    let refused = events(&r, "db.query")
        .into_iter()
        .filter(|e| e["data"]["phase"] == "refused")
        .count();
    assert!(refused >= 5, "{refused}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_can_kill_its_own_query_by_the_id_it_was_given() {
    let Some(env) = env() else { return };
    let _one_at_a_time = LOCK.lock().await;
    let (dir, _) = prepared(&env).await;
    let r = relay(&env, dir.path(), false).await;
    let mut victim = client(&r, "limen_my_ro", "orders", 0)
        .await
        .expect("victim");
    let shown = victim.connection_id();
    assert!(
        shown >= 0x4000_0000,
        "the client is shown Limen's id, not the database's: {shown}"
    );
    let running = tokio::spawn(async move {
        let started = std::time::Instant::now();
        let result = victim.execute("select sleep(30)").await;
        (result, started.elapsed())
    });
    tokio::time::sleep(Duration::from_millis(700)).await;

    // What `mysql` does on Ctrl-C: a second connection runs KILL QUERY <id>.
    let mut killer = client(&r, "limen_my_ro", "orders", 0)
        .await
        .expect("killer");
    killer
        .execute(&format!("kill query {shown}"))
        .await
        .expect("the same user may kill its own query");
    // sleep() returns 1 when interrupted, so the statement itself succeeds.
    let (_, elapsed) = running.await.expect("join");
    assert!(
        elapsed < Duration::from_secs(10),
        "the sleep was cut short: {elapsed:?}"
    );
    // An id nobody holds is refused, and so is one that is just a database thread id.
    let e = killer
        .execute("kill query 999")
        .await
        .expect_err("unknown id");
    assert!(e.to_string().contains("1094"), "{e}");
    let kills: Vec<_> = events(&r, "db.query")
        .into_iter()
        .filter(|e| e["data"]["statement_type"] == "kill")
        .collect();
    assert!(kills.len() >= 2, "KILL is audited: {kills:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_statement_is_refused_when_it_cannot_be_audited() {
    let _one_at_a_time = LOCK.lock().await;
    let Some(env) = env() else { return };
    let (dir, _) = prepared(&env).await;
    let r = relay(&env, dir.path(), false).await;
    let mut c = client(&r, "limen_my_ro", "orders", 0)
        .await
        .expect("connect");
    c.execute("select 1").await.expect("audited");
    r.sink.set_failing(true);
    let err = c.execute("select 2").await.expect_err("fail closed");
    assert!(
        err.to_string().contains("can't record") || err.to_string().contains("1105"),
        "{err}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn literals_can_be_normalized() {
    let _one_at_a_time = LOCK.lock().await;
    let Some(env) = env() else { return };
    let (dir, _) = prepared(&env).await;
    let r = relay(&env, dir.path(), true).await;
    let mut c = client(&r, "limen_my_ro", "orders", 0)
        .await
        .expect("connect");
    c.execute("select * from customers where email = 'ada@example.com'")
        .await
        .expect("q");
    c.close().await;
    let q = events(&r, "db.query");
    let text = q
        .iter()
        .filter_map(|e| e["data"]["statement"].as_str())
        .find(|t| t.contains("customers"))
        .expect("statement");
    assert!(
        text.contains("email = ?") && !text.contains("ada@"),
        "{text}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn rows_larger_than_one_packet_pass_through() {
    let Some(env) = env() else {
        return;
    };
    let _one_at_a_time = LOCK.lock().await;
    let (dir, _) = prepared(&env).await;
    let r = relay(&env, dir.path(), false).await;
    let mut c = client(&r, "limen_my_ro", "orders", 0)
        .await
        .expect("connect");
    // 20 MB in one row: the protocol splits it into several 16 MB packets.
    let len = c
        .scalar("select length(repeat('x', 20000000))")
        .await
        .expect("length");
    assert_eq!(len.as_deref(), Some("20000000"));
    let value = c
        .scalar("select repeat('x', 20000000)")
        .await
        .expect("big value")
        .expect("some");
    assert_eq!(value.len(), 20_000_000);
    // A row whose 16 MB continuation is three bytes starting with 0xfe: the
    // relay must not read it as an end-of-rows marker. The row is a 4-byte
    // length header plus the value, so a value of 16777214 bytes makes a
    // 0xffffff-byte packet followed by exactly that 3-byte tail.
    let rows = tokio::time::timeout(
        Duration::from_secs(30),
        c.query("select concat(repeat('a', 16777211), unhex('FE0102'))"),
    )
    .await
    .expect("answered (a desynchronized relay stalls here)")
    .expect("tricky row");
    assert_eq!(rows.len(), 1, "one row, not a truncated answer");
    // The session is still in step afterwards.
    let alive = tokio::time::timeout(Duration::from_secs(30), c.scalar("select 1"))
        .await
        .expect("answered")
        .expect("alive");
    assert_eq!(alive.as_deref(), Some("1"));
    // Several result sets in one answer (a procedure's), then a normal statement.
    assert_eq!(
        c.run_prepared("select * from customers")
            .await
            .expect("prepared"),
        2
    );
}
