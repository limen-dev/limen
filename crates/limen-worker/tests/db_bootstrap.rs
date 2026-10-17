//! Role bootstrap against a real PostgreSQL (ADR-0033 section 6). Needs
//! `LIMEN_TEST_PG_TARGET=host:port` as for `db_pg.rs`; otherwise SKIPPED.

use std::sync::Arc;

use limen_audit::{Emitter, FailureMode, MemorySink};
use limen_policy::model::DbTarget;
use limen_worker::db::bootstrap::{Plan, reconcile};
use limen_worker::db::{Engine, pgclient::Client, secret};
use sqlx::postgres::{PgConnectOptions, PgSslMode};
use sqlx::{Connection, Executor, PgConnection, Row};

/// The tests change the same roles and default privileges: one at a time.
static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const ADMIN_PASSWORD: &str = "limen-admin-dev-only";

fn target_addr() -> Option<String> {
    let v = std::env::var("LIMEN_TEST_PG_TARGET").ok();
    if v.is_none() {
        eprintln!("SKIPPED: set LIMEN_TEST_PG_TARGET=host:port (see deploy/compose)");
    }
    v
}

async fn admin(target: &str, db: &str) -> PgConnection {
    let (host, port) = target.rsplit_once(':').expect("host:port");
    PgConnection::connect_with(
        &PgConnectOptions::new()
            .host(host)
            .port(port.parse().expect("port"))
            .username("limen_admin")
            .password(ADMIN_PASSWORD)
            .database(db)
            .ssl_mode(PgSslMode::Disable),
    )
    .await
    .expect("admin connect")
}

async fn plan(target: &str, dir: &std::path::Path, roles: &str) -> Plan {
    let pw_file = dir.join(".admin");
    std::fs::write(&pw_file, ADMIN_PASSWORD).expect("admin password");
    let spec: DbTarget = serde_json::from_value(serde_json::json!({
        "endpoint": target,
        "iam_auth": false,
        "insecure_dev": true,
        "default_database": "orders",
        "password_dir": dir.to_str().expect("utf8"),
        "admin_user": "limen_admin",
        "admin_password_file": pw_file.to_str().expect("utf8"),
        "bootstrap": serde_json::from_str::<serde_json::Value>(roles).expect("roles"),
    }))
    .expect("spec");
    Plan::from_spec("orders-test", Engine::Postgres, &spec, true)
        .await
        .expect("plan")
}

async fn forget(target: &str, roles: &[&str]) {
    let mut c = admin(target, "orders").await;
    for r in roles {
        // Static SQL per role keeps sqlx's literal-SQL rule; the names are fixed.
        let (grant, drop_owned, drop_role) = match *r {
            "limen_bs_ro" => (
                "GRANT limen_bs_ro TO limen_admin WITH INHERIT TRUE, SET TRUE",
                "DROP OWNED BY limen_bs_ro",
                "DROP ROLE limen_bs_ro",
            ),
            "limen_bs_rw" => (
                "GRANT limen_bs_rw TO limen_admin WITH INHERIT TRUE, SET TRUE",
                "DROP OWNED BY limen_bs_rw",
                "DROP ROLE limen_bs_rw",
            ),
            _ => (
                "GRANT limen_bs_fc TO limen_admin WITH INHERIT TRUE, SET TRUE",
                "DROP OWNED BY limen_bs_fc",
                "DROP ROLE limen_bs_fc",
            ),
        };
        let exists = sqlx::query("SELECT 1 FROM pg_roles WHERE rolname = $1")
            .bind(*r)
            .fetch_optional(&mut c)
            .await
            .expect("lookup")
            .is_some();
        if exists {
            for sql in [grant, drop_owned, drop_role] {
                c.execute(sqlx::raw_sql(sql)).await.expect(sql);
            }
        }
    }
}

const ROLES: &str = r#"[
  {"role": "limen_bs_ro", "grants": [{"database": "orders", "access": "read"}]},
  {"role": "limen_bs_rw", "grants": [{"database": "orders", "access": "write"}]}
]"#;

fn emitter() -> (Arc<MemorySink>, Emitter) {
    let sink = Arc::new(MemorySink::default());
    let em = Emitter::new("worker", "w1", sink.clone(), FailureMode::FailClosed);
    (sink, em)
}

async fn login(target: &str, dir: &std::path::Path, role: &str) -> Result<Client, String> {
    let pw = secret::role_password(dir.to_str().expect("utf8"), role).await?;
    let plan = plan(target, dir, ROLES).await;
    let _ = plan;
    let spec: DbTarget = serde_json::from_value(serde_json::json!({
        "endpoint": target, "iam_auth": false, "insecure_dev": true,
    }))
    .expect("spec");
    let t = limen_worker::db::Target::from_spec(&spec, true).await?;
    Client::connect(&t, role, &pw, "orders", "test").await
}

#[tokio::test(flavor = "multi_thread")]
async fn bootstrap_creates_roles_idempotently_and_repairs_drift() {
    let _one_at_a_time = LOCK.lock().await;
    let Some(target) = target_addr() else { return };
    forget(&target, &["limen_bs_ro", "limen_bs_rw"]).await;
    let dir = tempfile::tempdir().expect("dir");
    let (sink, em) = emitter();
    let p = plan(&target, dir.path(), ROLES).await;

    // Check mode on an empty database reports and changes nothing.
    let report = reconcile(&p, Some(&em), false).await.expect("check");
    assert!(
        report
            .actions
            .iter()
            .any(|a| a.kind == "create_role" && !a.applied)
    );
    assert!(login(&target, dir.path(), "limen_bs_ro").await.is_err());

    // First apply creates roles, passwords, and grants.
    let report = reconcile(&p, Some(&em), true).await.expect("apply");
    assert!(report.failed().is_empty(), "{:?}", report.failed());
    assert_eq!(
        report
            .actions
            .iter()
            .filter(|a| a.kind == "create_role")
            .count(),
        2
    );
    assert!(
        report.actions.iter().all(|a| a.applied),
        "{:?}",
        report.actions
    );

    let mut ro = login(&target, dir.path(), "limen_bs_ro")
        .await
        .expect("ro login");
    assert_eq!(
        ro.scalar("select count(*) from orders")
            .await
            .expect("select")
            .as_deref(),
        Some("3")
    );
    ro.execute("insert into orders (total_cents) values (1)")
        .await
        .expect_err("read role can't write");
    // No other role to escalate to.
    assert_eq!(
        ro.scalar("select count(*) from pg_auth_members m join pg_roles u on u.oid = m.member where u.rolname = current_user")
            .await
            .expect("members")
            .as_deref(),
        Some("0")
    );
    let mut rw = login(&target, dir.path(), "limen_bs_rw")
        .await
        .expect("rw login");
    rw.execute("insert into orders (total_cents) values (7)")
        .await
        .expect("rw can write");
    rw.execute("delete from orders where total_cents = 7")
        .await
        .expect("rw can delete");

    // The second run changes nothing, in either mode.
    for apply in [true, false] {
        let again = reconcile(&p, Some(&em), apply).await.expect("again");
        assert!(
            again.actions.is_empty(),
            "apply={apply}: {:?}",
            again.actions
        );
    }

    // Tables created later are covered by default privileges.
    let mut a = admin(&target, "orders").await;
    a.execute(sqlx::raw_sql("CREATE TABLE IF NOT EXISTS later (id int)"))
        .await
        .expect("create");
    a.execute(sqlx::raw_sql("INSERT INTO later VALUES (1)"))
        .await
        .expect("insert");
    assert_eq!(
        ro.scalar("select count(*) from later")
            .await
            .expect("later")
            .as_deref(),
        Some("1")
    );
    a.execute(sqlx::raw_sql("DROP TABLE later"))
        .await
        .expect("drop");

    // Drift: extra membership, extra privilege, wrong password.
    a.execute(sqlx::raw_sql("GRANT limen_bs_rw TO limen_bs_ro"))
        .await
        .expect("membership");
    a.execute(sqlx::raw_sql("GRANT INSERT ON orders TO limen_bs_ro"))
        .await
        .expect("privilege");
    a.execute(sqlx::raw_sql(
        "ALTER ROLE limen_bs_ro PASSWORD 'someone-else'",
    ))
    .await
    .expect("password");
    let check = reconcile(&p, Some(&em), false).await.expect("check drift");
    let kinds: Vec<_> = check.actions.iter().map(|a| a.kind).collect();
    assert!(kinds.contains(&"revoke_membership"), "{kinds:?}");
    assert!(kinds.contains(&"grant"), "{kinds:?}");
    assert!(kinds.contains(&"reset_password"), "{kinds:?}");
    assert!(
        check.actions.iter().all(|a| !a.applied),
        "check mode changes nothing"
    );
    let fixed = reconcile(&p, Some(&em), true).await.expect("fix drift");
    assert!(fixed.failed().is_empty(), "{:?}", fixed.failed());
    let clean = reconcile(&p, Some(&em), true).await.expect("clean");
    assert!(clean.actions.is_empty(), "{:?}", clean.actions);
    let mut ro = login(&target, dir.path(), "limen_bs_ro")
        .await
        .expect("ro login again");
    ro.execute("insert into orders (total_cents) values (1)")
        .await
        .expect_err("privilege revoked");

    // Every change was audited, and no secret is in the trail or the report.
    let events = serde_json::to_string(&sink.events()).expect("json");
    assert!(events.contains("db.bootstrap") && events.contains("create_role"));
    for role in ["limen_bs_ro", "limen_bs_rw"] {
        let pw = std::fs::read_to_string(dir.path().join(role)).expect("pw file");
        assert!(!events.contains(pw.trim()));
        assert!(!format!("{report:?}{fixed:?}").contains(pw.trim()));
    }
    assert!(!events.contains(ADMIN_PASSWORD) && !events.contains("someone-else"));
    forget(&target, &["limen_bs_ro", "limen_bs_rw"]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn nothing_changes_when_the_change_cannot_be_audited() {
    let _one_at_a_time = LOCK.lock().await;
    let Some(target) = target_addr() else { return };
    forget(&target, &["limen_bs_fc"]).await;
    let dir = tempfile::tempdir().expect("dir");
    let (sink, em) = emitter();
    sink.set_failing(true);
    let p = plan(
        &target,
        dir.path(),
        r#"[{"role": "limen_bs_fc", "grants": [{"database": "orders", "access": "read"}]}]"#,
    )
    .await;
    let err = reconcile(&p, Some(&em), true)
        .await
        .expect_err("fail closed");
    assert!(err.contains("audit unavailable"), "{err}");
    let mut c = admin(&target, "orders").await;
    let n: i64 = sqlx::query("SELECT count(*) FROM pg_roles WHERE rolname = 'limen_bs_fc'")
        .fetch_one(&mut c)
        .await
        .expect("count")
        .get(0);
    assert_eq!(n, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn only_limen_roles_are_ever_touched() {
    let _one_at_a_time = LOCK.lock().await;
    let Some(target) = target_addr() else { return };
    let dir = tempfile::tempdir().expect("dir");
    let mut p = plan(&target, dir.path(), "[]").await;
    p.roles = vec![
        serde_json::from_value(serde_json::json!({"role": "postgres", "grants": []}))
            .expect("role"),
    ];
    let err = reconcile(&p, None, true).await.expect_err("refused");
    assert!(err.contains("not a limen_* role"), "{err}");
}

/// IAM mode on a server that has no `rds_iam` role: a stub stands in for it.
/// Only the SQL shape is exercised; the real IAM plugin is *unverified against
/// the real service*.
#[tokio::test(flavor = "multi_thread")]
async fn iam_mode_grants_rds_iam_and_nothing_else() {
    let _one_at_a_time = LOCK.lock().await;
    let Some(target) = target_addr() else { return };
    forget(&target, &["limen_bs_fc"]).await;
    let mut a = admin(&target, "orders").await;
    sqlx::raw_sql("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rds_iam') THEN CREATE ROLE rds_iam; END IF; END $$")
        .execute(&mut a)
        .await
        .ok();
    let dir = tempfile::tempdir().expect("dir");
    let mut p = plan(
        &target,
        dir.path(),
        r#"[{"role": "limen_bs_fc", "grants": [{"database": "orders", "access": "read"}]}]"#,
    )
    .await;
    p.iam = true;
    p.password_dir = None;
    let report = reconcile(&p, None, true).await.expect("iam bootstrap");
    assert!(report.failed().is_empty(), "{:?}", report.failed());
    assert!(
        report
            .actions
            .iter()
            .any(|x| x.kind == "create_role" && x.detail.contains("IAM"))
    );
    let member: i64 = sqlx::query(
        "select count(*) from pg_auth_members m join pg_roles u on u.oid = m.member join pg_roles r on r.oid = m.roleid where u.rolname = 'limen_bs_fc' and r.rolname = 'rds_iam'",
    )
    .fetch_one(&mut a)
    .await
    .expect("membership")
    .get(0);
    assert_eq!(member, 1);
    let again = reconcile(&p, None, true).await.expect("again");
    assert!(again.actions.is_empty(), "{:?}", again.actions);
    forget(&target, &["limen_bs_fc"]).await;
}
