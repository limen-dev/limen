//! Phase 6 end to end: `psql`-style clients reach a PostgreSQL target through
//! the proxy and the worker, with no password, audit for every statement, and
//! the denials and locks of the earlier phases (ADR-0033).
//!
//! Needs `LIMEN_TEST_DATABASE_URL` (control plane state) and
//! `LIMEN_TEST_PG_TARGET=host:port` (see `deploy/compose/config/targets/postgres`).

use std::collections::HashMap;
use std::time::Duration;

use limen_e2e::{Deployment, db_client, eventually};
use limen_proto::v1::admin_client::AdminClient;
use limen_proto::v1::{ApplyPolicyRequest, CreateJoinTokenRequest, LockUserRequest, PolicySource};
use limen_testkit::users::{ADMIN, DEVELOPER};
use sqlx::postgres::{PgConnectOptions, PgSslMode};
use sqlx::{Connection, Executor, PgConnection, Row};

const ROLE: &str = "limen_e2e_ro";

fn policy(target: &str, secrets: &str) -> Vec<PolicySource> {
    let yaml = format!(
        r#"
kind: role
version: v1
metadata: {{ name: analysts }}
spec:
  allow:
    - resources: {{ kind: [postgres], labels: {{ env: [test] }} }}
      db: {{ roles: [{ROLE}], databases: [orders] }}
---
kind: role_mapping
version: v1
metadata: {{ name: idp }}
spec:
  - {{ idp_group: analysts, roles: [analysts] }}
---
kind: resource
version: v1
metadata: {{ name: orders-test, labels: {{ env: test }} }}
spec:
  postgres:
    endpoint: "{target}"
    iam_auth: false
    insecure_dev: true
    default_database: orders
    password_dir: "{secrets}"
  worker_selector: {{ pool: dev }}
"#
    );
    vec![PolicySource {
        name: "policy.yaml".into(),
        content: yaml,
    }]
}

fn opts(addr: std::net::SocketAddr, user: &str, db: &str) -> PgConnectOptions {
    PgConnectOptions::new()
        .host("127.0.0.1")
        .port(addr.port())
        .username(user)
        .database(db)
        .ssl_mode(PgSslMode::Disable)
}

fn read_jsonl(d: &Deployment) -> Vec<serde_json::Value> {
    std::fs::read_to_string(d.dir.path().join("audit/control-plane.jsonl"))
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).expect("json"))
        .collect()
}

#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread")]
async fn postgres_through_limen() {
    let Ok(target) = std::env::var("LIMEN_TEST_PG_TARGET") else {
        eprintln!("SKIPPED: set LIMEN_TEST_PG_TARGET=host:port");
        return;
    };
    let Some(d) = Deployment::start().await else {
        return;
    };
    // A login role with its password in a file, as secret mode expects.
    let (host, port) = target.rsplit_once(':').expect("host:port");
    let mut admin_db = PgConnection::connect_with(
        &PgConnectOptions::new()
            .host(host)
            .port(port.parse().expect("port"))
            .username("limen_admin")
            .password("limen-admin-dev-only")
            .database("orders")
            .ssl_mode(PgSslMode::Disable),
    )
    .await
    .expect("admin connect");
    admin_db
        .execute(sqlx::raw_sql(
            "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'limen_e2e_ro') THEN CREATE ROLE limen_e2e_ro LOGIN; END IF; END $$; ALTER ROLE limen_e2e_ro PASSWORD 'e2e-pw'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO limen_e2e_ro",
        ))
        .await
        .expect("role");
    let secrets = d.dir.path().join("db-secrets");
    std::fs::create_dir_all(&secrets).expect("dir");
    std::fs::write(secrets.join(ROLE), "e2e-pw\n").expect("secret");

    let ca_pem = std::fs::read_to_string(d.ca_file()).expect("ca");
    let proxy_addr = d.proxy_addr.to_string();
    let admin_user = d.login(ADMIN, &["admins"]).await.expect("admin");
    let mut admin = AdminClient::new(d.proxy_channel(Some(admin_user)));
    let applied = admin
        .apply_policy(ApplyPolicyRequest {
            sources: policy(&target, secrets.to_str().expect("utf8")),
            dry_run: false,
            source_ref: String::new(),
        })
        .await
        .expect("apply")
        .into_inner();
    let token = admin
        .create_join_token(CreateJoinTokenRequest {
            kind: "worker".into(),
            ttl_seconds: 600,
            labels: HashMap::from([("pool".to_owned(), "dev".to_owned())]),
            dns_names: vec![],
            name: String::new(),
        })
        .await
        .expect("token")
        .into_inner()
        .token;
    let worker = d
        .start_worker_with(&token, "worker", &["--allow-insecure-db-targets"])
        .await;
    eventually(Duration::from_secs(15), "worker tunnels", || async {
        d.proxy().tunnels.summaries().len() == 2
    })
    .await;
    eventually(Duration::from_secs(15), "policy everywhere", || async {
        d.proxy().policy_version() == Some(applied.version)
            && worker.worker.policy_version() == Some(applied.version)
    })
    .await;

    // An analyst connects with no password and queries.
    let analyst = d.login(DEVELOPER, &["analysts"]).await.expect("analyst");
    let (addr, refused) = db_client::listen(
        &proxy_addr,
        &ca_pem,
        analyst.clone(),
        "orders-test",
        ROLE,
        "",
    )
    .await;
    let mut c = PgConnection::connect_with(&opts(addr, ROLE, ROLE))
        .await
        .expect("connect through Limen");
    let total: i64 = sqlx::query("select sum(total_cents)::bigint from orders")
        .fetch_one(&mut c)
        .await
        .expect("sum")
        .get(0);
    assert_eq!(total, 6440);
    c.execute("insert into orders (total_cents) values (1)")
        .await
        .expect_err("the database role is read-only");
    assert!(refused.lock().expect("lock").is_empty());

    // A second connection is a second session; both are audited and linked.
    let mut c2 = PgConnection::connect_with(&opts(addr, ROLE, "orders"))
        .await
        .expect("second");
    c2.execute("select 42").await.expect("select");
    c2.close().await.ok();

    // The database role named in policy only. Another role is refused at the
    // proxy and audited, with nothing sent to the database.
    let (bad_addr, bad_refused) = db_client::listen(
        &proxy_addr,
        &ca_pem,
        analyst.clone(),
        "orders-test",
        "limen_admin",
        "",
    )
    .await;
    let _ = PgConnection::connect_with(&opts(bad_addr, "limen_admin", "orders")).await;
    // Nor is another database.
    let (other_addr, other_refused) = db_client::listen(
        &proxy_addr,
        &ca_pem,
        analyst.clone(),
        "orders-test",
        ROLE,
        "billing",
    )
    .await;
    let _ = PgConnection::connect_with(&opts(other_addr, ROLE, "billing")).await;
    eventually(Duration::from_secs(5), "refusals recorded", || async {
        !bad_refused.lock().expect("lock").is_empty()
            && !other_refused.lock().expect("lock").is_empty()
    })
    .await;
    assert!(bad_refused.lock().expect("lock")[0].contains("access denied"));

    // The trail: session.start/end, statements, ends, and denials.
    eventually(
        Duration::from_secs(20),
        "db events in the trail",
        || async {
            let events = read_jsonl(&d);
            events
                .iter()
                .filter(|e| e["kind"] == "db.query.end")
                .count()
                >= 3
                && events.iter().filter(|e| e["kind"] == "auth.denied").count() >= 2
        },
    )
    .await;
    let events = read_jsonl(&d);
    let start = events
        .iter()
        .find(|e| e["kind"] == "session.start" && e["data"]["kind"] == "postgres")
        .expect("session.start");
    assert_eq!(start["user"], DEVELOPER);
    assert_eq!(start["data"]["database"], "orders");
    let statement = events
        .iter()
        .find(|e| e["kind"] == "db.query" && e["data"]["statement"] == "select 42")
        .expect("db.query select 42");
    assert_eq!(statement["producer"]["component"], "worker");
    assert_eq!(statement["data"]["db_role"], ROLE);
    assert!(
        events
            .iter()
            .any(|e| e["kind"] == "session.start" && e["session_id"] == statement["session_id"]),
        "the statement links to a proxy session by id"
    );
    assert!(events.iter().any(|e| e["kind"] == "db.query.end"
        && e["data"]["query_id"] == statement["event_id"]
        && e["data"]["status"] == "ok"));
    assert!(
        events
            .iter()
            .any(|e| e["kind"] == "db.query.end" && e["data"]["error_code"] == "42501")
    );
    let denials: Vec<_> = events
        .iter()
        .filter(|e| e["kind"] == "auth.denied")
        .collect();
    assert!(denials.iter().all(|e| e["data"]["action"] == "db"));
    assert!(
        !serde_json::to_string(&events)
            .expect("json")
            .contains("e2e-pw")
    );

    // Locking the analyst ends the open session at once.
    assert!(
        admin
            .lock_user(LockUserRequest {
                username: DEVELOPER.into(),
                reason: "test".into(),
            })
            .await
            .expect("lock")
            .into_inner()
            .locked
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        if c.execute("select 1").await.is_err() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the open session should end when the user is locked"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    worker.stop().await;
}

/// MySQL through the same stack: proxy, worker, TLS to the database with a
/// verified certificate, a password in a file, audit with the MySQL fields.
/// Needs `LIMEN_TEST_MYSQL_TARGET=host:port` and `LIMEN_TEST_PG_CA_FILE`.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread")]
async fn mysql_through_limen() {
    use limen_core::secret::Secret;
    use limen_policy::model::DbTarget;
    use limen_worker::db::Target;
    use limen_worker::db::mysqlclient::Client;

    let (Ok(target), Ok(ca)) = (
        std::env::var("LIMEN_TEST_MYSQL_TARGET"),
        std::env::var("LIMEN_TEST_PG_CA_FILE"),
    ) else {
        eprintln!("SKIPPED: set LIMEN_TEST_MYSQL_TARGET and LIMEN_TEST_PG_CA_FILE");
        return;
    };
    let Some(d) = Deployment::start().await else {
        return;
    };
    // A MySQL user with its password in a file, created as the admin would.
    let tls_spec = |extra: serde_json::Value| -> DbTarget {
        let mut v = serde_json::json!({
            "endpoint": target, "iam_auth": false,
            "tls_ca_file": ca, "tls_server_name": "mysql-target",
        });
        v.as_object_mut()
            .expect("object")
            .extend(extra.as_object().expect("object").clone());
        serde_json::from_value(v).expect("spec")
    };
    let admin_target = Target::from_spec(&tls_spec(serde_json::json!({})), false)
        .await
        .expect("target");
    let mut admin_db = Client::connect(
        &admin_target,
        "limen_admin",
        &Secret::new("limen-admin-dev-only".into()),
        "orders",
        "e2e",
    )
    .await
    .expect("admin connect");
    for sql in [
        "CREATE USER IF NOT EXISTS 'limen_e2e_my'@'%' IDENTIFIED BY 'e2e-my-pw' REQUIRE SSL",
        "ALTER USER 'limen_e2e_my'@'%' IDENTIFIED BY 'e2e-my-pw' REQUIRE SSL",
        "GRANT SELECT ON orders.* TO 'limen_e2e_my'@'%'",
    ] {
        admin_db.execute(sql).await.expect(sql);
    }
    let secrets = d.dir.path().join("my-secrets");
    std::fs::create_dir_all(&secrets).expect("dir");
    std::fs::write(secrets.join("limen_e2e_my"), "e2e-my-pw").expect("secret");

    let yaml = format!(
        r#"
kind: role
version: v1
metadata: {{ name: analysts }}
spec:
  allow:
    - resources: {{ kind: [mysql], labels: {{ env: [test] }} }}
      db: {{ roles: [limen_e2e_my], databases: [orders] }}
---
kind: role_mapping
version: v1
metadata: {{ name: idp }}
spec:
  - {{ idp_group: analysts, roles: [analysts] }}
---
kind: resource
version: v1
metadata: {{ name: orders-my, labels: {{ env: test }} }}
spec:
  mysql:
    endpoint: "{target}"
    iam_auth: false
    default_database: orders
    tls_ca_file: "{ca}"
    tls_server_name: mysql-target
    password_dir: "{}"
  worker_selector: {{ pool: dev }}
"#,
        secrets.display()
    );
    let ca_pem = std::fs::read_to_string(d.ca_file()).expect("ca");
    let proxy_addr = d.proxy_addr.to_string();
    let admin_user = d.login(ADMIN, &["admins"]).await.expect("admin");
    let mut admin = AdminClient::new(d.proxy_channel(Some(admin_user)));
    let applied = admin
        .apply_policy(ApplyPolicyRequest {
            sources: vec![PolicySource {
                name: "policy.yaml".into(),
                content: yaml,
            }],
            dry_run: false,
            source_ref: String::new(),
        })
        .await
        .expect("apply")
        .into_inner();
    let token = admin
        .create_join_token(CreateJoinTokenRequest {
            kind: "worker".into(),
            ttl_seconds: 600,
            labels: HashMap::from([("pool".to_owned(), "dev".to_owned())]),
            dns_names: vec![],
            name: String::new(),
        })
        .await
        .expect("token")
        .into_inner()
        .token;
    let worker = d.start_worker(&token, "worker").await;
    eventually(Duration::from_secs(15), "worker and policy", || async {
        d.proxy().tunnels.summaries().len() == 2
            && d.proxy().policy_version() == Some(applied.version)
            && worker.worker.policy_version() == Some(applied.version)
    })
    .await;

    let analyst = d.login(DEVELOPER, &["analysts"]).await.expect("analyst");
    let (addr, _) = db_client::listen(
        &proxy_addr,
        &ca_pem,
        analyst,
        "orders-my",
        "limen_e2e_my",
        "",
    )
    .await;
    // A MySQL client of the local listener; the relay ignores its credential.
    let local: DbTarget = serde_json::from_value(serde_json::json!({
        "endpoint": addr.to_string(), "iam_auth": false, "insecure_dev": true,
    }))
    .expect("spec");
    let local = Target::from_spec(&local, true).await.expect("local");
    let mut c = Client::connect(
        &local,
        "limen_e2e_my",
        &Secret::new(String::new()),
        "",
        "e2e",
    )
    .await
    .expect("connect through Limen");
    assert_eq!(
        c.scalar("select sum(total_cents) from orders")
            .await
            .expect("sum")
            .as_deref(),
        Some("6440")
    );
    c.execute("insert into orders (total_cents) values (1)")
        .await
        .expect_err("read-only user");
    c.close().await;

    eventually(
        Duration::from_secs(20),
        "mysql events in the trail",
        || async {
            let events = read_jsonl(&d);
            events
                .iter()
                .any(|e| e["kind"] == "db.query.end" && e["data"]["error_number"] == 1142)
        },
    )
    .await;
    let events = read_jsonl(&d);
    let q = events
        .iter()
        .find(|e| {
            e["kind"] == "db.query"
                && e["data"]["statement"] == "select sum(total_cents) from orders"
        })
        .expect("statement");
    assert_eq!(q["data"]["protocol"], "mysql");
    assert_eq!(q["data"]["db_role"], "limen_e2e_my");
    assert!(events.iter().any(|e| e["kind"] == "session.start"
        && e["session_id"] == q["session_id"]
        && e["data"]["kind"] == "mysql"));
    assert!(
        !serde_json::to_string(&events)
            .expect("json")
            .contains("e2e-my-pw")
    );
    worker.stop().await;
}
