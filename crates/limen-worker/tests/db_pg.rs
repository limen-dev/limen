//! PostgreSQL sessions through the worker's relay (ADR-0033, slice 6a), against
//! a real PostgreSQL. Set `LIMEN_TEST_PG_TARGET=host:port` to a server whose
//! `limen_admin` login (password `limen-admin-dev-only`) owns the `orders` and
//! `billing` databases (`deploy/compose/targets/postgres/init.sql`). Without
//! it the tests print SKIPPED.

use std::sync::Arc;
use std::time::Duration;

use limen_audit::{Emitter, FailureMode, MemorySink};
use limen_core::secret::Secret;
use limen_policy::model::DbTarget;
use limen_worker::db::{DbSessionConfig, Engine, Registry, Target, serve};
use sqlx::postgres::{PgConnectOptions, PgSslMode};
use sqlx::{Connection, Executor, PgConnection, Row};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Role setup changes shared catalogs; concurrent `GRANT`s collide.
static CATALOG: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const ROLE_RO: &str = "limen_test_ro";
const PASSWORD: &str = "ro-pw-for-tests";

struct Harness {
    addr: std::net::SocketAddr,
    sink: Arc<MemorySink>,
    registry: Arc<Registry>,
    target_addr: String,
}

fn target_addr() -> Option<String> {
    let v = std::env::var("LIMEN_TEST_PG_TARGET").ok();
    if v.is_none() {
        eprintln!("SKIPPED: set LIMEN_TEST_PG_TARGET=host:port (see deploy/compose)");
    }
    v
}

async fn admin(target: &str, db: &str) -> PgConnection {
    let (host, port) = target.rsplit_once(':').expect("host:port");
    let opts = PgConnectOptions::new()
        .host(host)
        .port(port.parse().expect("port"))
        .username("limen_admin")
        .password("limen-admin-dev-only")
        .database(db)
        .ssl_mode(PgSslMode::Disable);
    PgConnection::connect_with(&opts)
        .await
        .expect("admin connect")
}

/// A read-only login role with the password in a file, as secret mode expects.
async fn prepare(target: &str) -> &'static tempfile::TempDir {
    static DIR: tokio::sync::OnceCell<tempfile::TempDir> = tokio::sync::OnceCell::const_new();
    DIR.get_or_init(|| create_role(target)).await
}

async fn create_role(target: &str) -> tempfile::TempDir {
    let _catalog = CATALOG.lock().await;
    let mut c = admin(target, "orders").await;
    sqlx::raw_sql(
        "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'limen_test_ro') THEN CREATE ROLE limen_test_ro LOGIN; END IF; END $$; ALTER ROLE limen_test_ro PASSWORD 'ro-pw-for-tests'",
    )
    .execute(&mut c)
    .await
    .expect("create role");
    sqlx::raw_sql("GRANT SELECT ON ALL TABLES IN SCHEMA public TO limen_test_ro")
        .execute(&mut c)
        .await
        .expect("grant");
    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(dir.path().join(ROLE_RO), format!("{PASSWORD}\n")).expect("secret");
    dir
}

async fn harness(target: &str, secrets: &std::path::Path, normalize: bool) -> Harness {
    let sink = Arc::new(MemorySink::default());
    let emitter = Emitter::new("worker", "w1", sink.clone(), FailureMode::FailClosed);
    let registry = Arc::new(Registry::default());
    let spec: DbTarget = serde_json::from_value(serde_json::json!({
        "endpoint": target,
        "iam_auth": false,
        "insecure_dev": true,
        "password_dir": secrets.to_str().expect("utf8"),
    }))
    .expect("target");
    let t = Target::from_spec(&spec, true).await.expect("target");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (reg, em) = (registry.clone(), emitter);
    let secrets = secrets.to_path_buf();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let password =
                limen_worker::db::secret::role_password(secrets.to_str().expect("utf8"), ROLE_RO)
                    .await
                    .expect("pw");
            let cfg = DbSessionConfig {
                session_id: uuid::Uuid::now_v7(),
                username: "dev@example.com".into(),
                resource: "orders-staging".into(),
                engine: Engine::Postgres,
                role: ROLE_RO.into(),
                login_user: ROLE_RO.into(),
                database: "orders".into(),
                target: t.clone(),
                password,
                normalize_literals: normalize,
                registry: reg.clone(),
            };
            let em = em.clone();
            tokio::spawn(async move {
                let _ = serve(stream, cfg, em).await;
            });
        }
    });
    let _ = Secret::new(String::new());
    Harness {
        addr,
        sink,
        registry,
        target_addr: target.to_owned(),
    }
}

fn client_opts(h: &Harness, user: &str, db: &str) -> PgConnectOptions {
    PgConnectOptions::new()
        .host("127.0.0.1")
        .port(h.addr.port())
        .username(user)
        .database(db)
        .ssl_mode(PgSslMode::Disable)
}

fn kinds(h: &Harness, kind: &str) -> Vec<serde_json::Value> {
    h.sink
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
    let Some(target) = target_addr() else { return };
    let secrets = prepare(&target).await;
    let h = harness(&target, secrets.path(), false).await;

    let mut c = PgConnection::connect_with(&client_opts(&h, ROLE_RO, "orders"))
        .await
        .expect("connect without a password");
    // Extended protocol (Parse/Bind/Execute).
    let n: i64 = sqlx::query("select count(*) from orders")
        .fetch_one(&mut c)
        .await
        .expect("count")
        .get(0);
    assert_eq!(n, 3);
    // Simple protocol, two statements in one message.
    c.execute("select 1; select 2").await.expect("simple");
    // The database sees the Limen session.
    let app: String = sqlx::query("show application_name")
        .fetch_one(&mut c)
        .await
        .expect("show")
        .get(0);
    assert!(app.starts_with("limen:"), "{app}");
    // The role is limited by the database's own grants.
    let denied = c
        .execute("insert into orders (customer_id, total_cents) values (1, 1)")
        .await
        .expect_err("read-only role can't insert");
    assert!(denied.to_string().contains("permission denied"), "{denied}");
    // A bad statement is reported as an error.
    c.execute("select * from nope").await.expect_err("no table");
    c.close().await.expect("close");

    tokio::time::sleep(Duration::from_millis(300)).await;
    let queries = kinds(&h, "db.query");
    let texts: Vec<_> = queries
        .iter()
        .filter_map(|q| q["data"]["statement"].as_str())
        .collect();
    assert!(texts.contains(&"select count(*) from orders"), "{texts:?}");
    assert!(
        texts.contains(&"select 1;") || texts.iter().any(|t| t.starts_with("select 1")),
        "{texts:?}"
    );
    assert!(texts.iter().any(|t| t.starts_with("select 2")), "{texts:?}");
    let first = &queries[0];
    assert_eq!(first["user"], "dev@example.com");
    assert_eq!(first["data"]["db_role"], ROLE_RO);
    assert_eq!(first["data"]["database"], "orders");
    assert_eq!(first["data"]["protocol"], "postgres");

    let ends = kinds(&h, "db.query.end");
    let count_end = ends
        .iter()
        .find(|e| e["data"]["rows"] == 1 && e["data"]["status"] == "ok")
        .expect("an ok end event with a row");
    assert!(count_end["data"]["duration_ms"].is_number());
    assert!(
        ends.iter().any(|e| e["data"]["error_code"] == "42501"),
        "permission denied is audited with its SQLSTATE: {ends:?}"
    );
    assert!(ends.iter().any(|e| e["data"]["error_code"] == "42P01"));
    // Every end event points at a query event.
    let ids: Vec<_> = queries.iter().map(|q| q["event_id"].clone()).collect();
    assert!(ends.iter().all(|e| ids.contains(&e["data"]["query_id"])));
    // The password is nowhere in the trail.
    let all = serde_json::to_string(&h.sink.events()).expect("json");
    assert!(!all.contains(PASSWORD));
    assert!(h.registry.is_empty(), "cancel keys are released");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_wrong_user_or_database_is_refused() {
    let Some(target) = target_addr() else { return };
    let secrets = prepare(&target).await;
    let h = harness(&target, secrets.path(), false).await;

    let err = PgConnection::connect_with(&client_opts(&h, "limen_admin", "orders"))
        .await
        .expect_err("other role");
    assert!(
        err.to_string()
            .contains("this session is for the database role"),
        "{err}"
    );
    let err = PgConnection::connect_with(&client_opts(&h, ROLE_RO, "billing"))
        .await
        .expect_err("other database");
    assert!(
        err.to_string()
            .contains("this session is for the database orders"),
        "{err}"
    );
    // libpq's implicit database (the user name) means the granted one.
    let mut c = PgConnection::connect_with(&client_opts(&h, ROLE_RO, ROLE_RO))
        .await
        .expect("implicit database");
    let db: String = sqlx::query("select current_database()")
        .fetch_one(&mut c)
        .await
        .expect("db")
        .get(0);
    assert_eq!(db, "orders");
    // Startup options and replication are refused.
    let err = PgConnection::connect_with(
        &client_opts(&h, ROLE_RO, "orders").options([("search_path", "x")]),
    )
    .await
    .expect_err("options");
    assert!(err.to_string().contains("startup options"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_statement_is_refused_when_it_cannot_be_audited() {
    let Some(target) = target_addr() else { return };
    let secrets = prepare(&target).await;
    let h = harness(&target, secrets.path(), false).await;
    let mut c = PgConnection::connect_with(&client_opts(&h, ROLE_RO, "orders"))
        .await
        .expect("connect");
    c.execute("select 1").await.expect("audited");
    h.sink.set_failing(true);
    let err = c.execute("select 2").await.expect_err("fail closed");
    assert!(
        err.to_string().contains("can't record") || matches!(err, sqlx::Error::Io(_)),
        "{err}"
    );
    h.sink.set_failing(false);
    // The statement never reached the database.
    let mut a = admin(&target, "orders").await;
    let seen: i64 = sqlx::query(
        "select count(*) from pg_stat_activity where application_name like 'limen:%' and query like 'select 2%'",
    )
    .fetch_one(&mut a)
    .await
    .expect("activity")
    .get(0);
    assert_eq!(seen, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn literals_can_be_normalized() {
    let Some(target) = target_addr() else { return };
    let secrets = prepare(&target).await;
    let h = harness(&target, secrets.path(), true).await;
    let mut c = PgConnection::connect_with(&client_opts(&h, ROLE_RO, "orders"))
        .await
        .expect("connect");
    c.execute("select * from customers where email = 'ada@example.com'")
        .await
        .expect("query");
    c.close().await.ok();
    let q = kinds(&h, "db.query");
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
async fn copy_streams_through() {
    let Some(target) = target_addr() else { return };
    let secrets = prepare(&target).await;
    let h = harness(&target, secrets.path(), false).await;
    let mut c = PgConnection::connect_with(&client_opts(&h, ROLE_RO, "orders"))
        .await
        .expect("connect");
    let mut stream = c.copy_out_raw("copy orders to stdout").await.expect("copy");
    let mut bytes = 0;
    while let Some(chunk) = futures::StreamExt::next(&mut stream).await {
        bytes += chunk.expect("chunk").len();
    }
    assert!(bytes > 10);
    drop(stream);
    c.close().await.ok();
    assert!(
        kinds(&h, "db.query")
            .iter()
            .any(|q| q["data"]["statement_type"] == "copy")
    );
}

// ---- raw protocol: cancel and the first-packet guards ----------------------

fn startup(user: &str, db: &str) -> Vec<u8> {
    let mut body = 196_608u32.to_be_bytes().to_vec();
    for (k, v) in [("user", user), ("database", db)] {
        body.extend_from_slice(k.as_bytes());
        body.push(0);
        body.extend_from_slice(v.as_bytes());
        body.push(0);
    }
    body.push(0);
    let mut out = u32::try_from(body.len() + 4)
        .expect("len")
        .to_be_bytes()
        .to_vec();
    out.extend_from_slice(&body);
    out
}

async fn read_frame(s: &mut TcpStream) -> (u8, Vec<u8>) {
    let kind = s.read_u8().await.expect("kind");
    let len = s.read_u32().await.expect("len") as usize;
    let mut body = vec![0; len - 4];
    s.read_exact(&mut body).await.expect("body");
    (kind, body)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_can_cancel_its_own_query_and_nobody_else_can() {
    let Some(target) = target_addr() else { return };
    let secrets = prepare(&target).await;
    let h = harness(&target, secrets.path(), false).await;

    let mut s = TcpStream::connect(h.addr).await.expect("connect");
    s.write_all(&[0, 0, 0, 8, 4, 0xd2, 0x16, 0x2f])
        .await
        .expect("ssl request");
    assert_eq!(
        s.read_u8().await.expect("answer"),
        b'N',
        "TLS is refused: the outer hop has it"
    );
    s.write_all(&startup(ROLE_RO, "orders"))
        .await
        .expect("startup");
    let mut key = None;
    loop {
        let (kind, body) = read_frame(&mut s).await;
        match kind {
            b'K' => key = Some((body[..4].to_vec(), body[4..8].to_vec())),
            b'Z' => break,
            b'E' => panic!("startup failed: {}", String::from_utf8_lossy(&body)),
            _ => {}
        }
    }
    let (pid, secret) = key.expect("a cancel key");
    assert_eq!(h.registry.len(), 1);

    // A query that would run for a minute.
    let mut q = b"select pg_sleep(60)\0".to_vec();
    let mut msg = vec![b'Q'];
    msg.extend_from_slice(&u32::try_from(q.len() + 4).expect("len").to_be_bytes());
    msg.append(&mut q);
    s.write_all(&msg).await.expect("query");
    tokio::time::sleep(Duration::from_millis(500)).await;

    // A cancel request with a wrong secret does nothing.
    let cancel = |pid: &[u8], secret: &[u8]| {
        let mut p = vec![0, 0, 0, 16, 0x04, 0xd2, 0x16, 0x2e];
        p.extend_from_slice(pid);
        p.extend_from_slice(secret);
        p
    };
    let mut other = TcpStream::connect(h.addr).await.expect("connect");
    other
        .write_all(&cancel(&pid, &[0, 0, 0, 0]))
        .await
        .expect("cancel");
    let _ = other.read(&mut [0u8; 1]).await;
    // The real one ends the query.
    let mut other = TcpStream::connect(h.addr).await.expect("connect");
    other
        .write_all(&cancel(&pid, &secret))
        .await
        .expect("cancel");
    let _ = other.read(&mut [0u8; 1]).await;

    let started = std::time::Instant::now();
    let error = loop {
        let (kind, body) = tokio::time::timeout(Duration::from_secs(10), read_frame(&mut s))
            .await
            .expect("an answer within 10 s");
        if kind == b'E' {
            break String::from_utf8_lossy(&body).into_owned();
        }
    };
    assert!(error.contains("57014"), "query_canceled: {error}");
    assert!(started.elapsed() < Duration::from_secs(10));
    drop(h.target_addr.clone());
}

#[tokio::test(flavor = "multi_thread")]
async fn replication_startup_is_refused() {
    let Some(target) = target_addr() else { return };
    let secrets = prepare(&target).await;
    let h = harness(&target, secrets.path(), false).await;
    let mut s = TcpStream::connect(h.addr).await.expect("connect");
    let mut body = 196_608u32.to_be_bytes().to_vec();
    for (k, v) in [
        ("user", ROLE_RO),
        ("database", "orders"),
        ("replication", "database"),
    ] {
        body.extend_from_slice(k.as_bytes());
        body.push(0);
        body.extend_from_slice(v.as_bytes());
        body.push(0);
    }
    body.push(0);
    let mut packet = u32::try_from(body.len() + 4)
        .expect("len")
        .to_be_bytes()
        .to_vec();
    packet.extend_from_slice(&body);
    s.write_all(&packet).await.expect("startup");
    let (kind, body) = read_frame(&mut s).await;
    assert_eq!(kind, b'E');
    assert!(String::from_utf8_lossy(&body).contains("replication"));
}

// ---- TLS to the target -----------------------------------------------------

/// `LIMEN_TEST_PG_CA_FILE` is the CA of the compose `db-tls` volume; the
/// server certificate names `postgres-target`.
fn ca_file() -> Option<String> {
    let v = std::env::var("LIMEN_TEST_PG_CA_FILE").ok();
    if v.is_none() {
        eprintln!("SKIPPED: set LIMEN_TEST_PG_CA_FILE (the db-tls CA, see deploy/compose)");
    }
    v
}

async fn serve_once(
    spec: serde_json::Value,
    secrets: &std::path::Path,
) -> (std::net::SocketAddr, Arc<MemorySink>) {
    serve_as(spec, secrets, ROLE_RO, Engine::Postgres).await
}

async fn serve_as(
    spec: serde_json::Value,
    secrets: &std::path::Path,
    role: &'static str,
    engine: Engine,
) -> (std::net::SocketAddr, Arc<MemorySink>) {
    let spec: DbTarget = serde_json::from_value(spec).expect("spec");
    let t = Target::from_spec(&spec, false).await.expect("target");
    let sink = Arc::new(MemorySink::default());
    let em = Emitter::new("worker", "w1", sink.clone(), FailureMode::FailClosed);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let password = limen_worker::db::secret::role_password(secrets.to_str().expect("utf8"), role)
        .await
        .expect("pw");
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let cfg = DbSessionConfig {
            session_id: uuid::Uuid::now_v7(),
            username: "dev@example.com".into(),
            resource: "orders-staging".into(),
            engine,
            role: role.into(),
            login_user: role.into(),
            database: "orders".into(),
            target: t,
            password,
            normalize_literals: false,
            registry: Arc::default(),
        };
        let _ = serve(stream, cfg, em).await;
    });
    (addr, sink)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_target_certificate_is_verified() {
    let (Some(target), Some(ca)) = (target_addr(), ca_file()) else {
        return;
    };
    let secrets = prepare(&target).await;
    let spec = |name: &str| {
        serde_json::json!({
            "endpoint": target, "iam_auth": false,
            "password_dir": secrets.path().to_str().expect("utf8"),
            "tls_ca_file": ca, "tls_server_name": name,
        })
    };
    let opts = |addr: std::net::SocketAddr| {
        PgConnectOptions::new()
            .host("127.0.0.1")
            .port(addr.port())
            .username(ROLE_RO)
            .database("orders")
            .ssl_mode(PgSslMode::Disable)
    };
    // The right name: the session works, and the database says it is on TLS.
    let (addr, _) = serve_once(spec("postgres-target"), secrets.path()).await;
    let mut c = PgConnection::connect_with(&opts(addr))
        .await
        .expect("verified TLS");
    let ssl: String = sqlx::query("select ssl::text from pg_stat_ssl where pid = pg_backend_pid()")
        .fetch_one(&mut c)
        .await
        .expect("pg_stat_ssl")
        .get(0);
    assert_eq!(ssl, "true");
    // A name the certificate doesn't carry: refused, and the client is told.
    let (addr, _) = serve_once(spec("not-the-database"), secrets.path()).await;
    let err = PgConnection::connect_with(&opts(addr))
        .await
        .expect_err("wrong name");
    assert!(
        err.to_string().contains("couldn't connect to the database"),
        "{err}"
    );
    // No CA configured: the resource can't be used at all.
    let no_ca = serde_json::from_value::<DbTarget>(
        serde_json::json!({"endpoint": target, "iam_auth": false}),
    )
    .expect("spec");
    assert!(
        Target::from_spec(&no_ca, false)
            .await
            .expect_err("needs a CA")
            .contains("tls_ca_file")
    );
    // And plain text needs the worker flag.
    let plain = serde_json::from_value::<DbTarget>(
        serde_json::json!({"endpoint": target, "iam_auth": false, "insecure_dev": true}),
    )
    .expect("spec");
    assert!(
        Target::from_spec(&plain, false)
            .await
            .expect_err("refused")
            .contains("allow-insecure")
    );
}

/// Redshift (and PostgreSQL set up with `md5` in `pg_hba.conf`) logs in with the
/// legacy MD5 exchange. The compose target has one such role, `limen_md5`.
#[tokio::test(flavor = "multi_thread")]
async fn md5_password_login_works() {
    let Some(target) = target_addr() else { return };
    let _catalog = CATALOG.lock().await;
    let mut c = admin(&target, "orders").await;
    sqlx::raw_sql(
        "SET password_encryption = 'md5'; DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'limen_md5') THEN CREATE ROLE limen_md5 LOGIN; END IF; END $$; ALTER ROLE limen_md5 PASSWORD 'md5-pw'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO limen_md5",
    )
    .execute(&mut c)
    .await
    .expect("md5 role");
    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(dir.path().join("limen_md5"), "md5-pw").expect("secret");
    let spec = serde_json::json!({
        "endpoint": target, "iam_auth": false, "insecure_dev": true,
        "password_dir": dir.path().to_str().expect("utf8"),
    });
    let spec: DbTarget = serde_json::from_value(spec).expect("spec");
    let t = Target::from_spec(&spec, true).await.expect("target");
    let sink = Arc::new(MemorySink::default());
    let em = Emitter::new("worker", "w1", sink, FailureMode::FailClosed);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let password =
        limen_worker::db::secret::role_password(dir.path().to_str().expect("utf8"), "limen_md5")
            .await
            .expect("pw");
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let cfg = DbSessionConfig {
            session_id: uuid::Uuid::now_v7(),
            username: "dev@example.com".into(),
            resource: "warehouse".into(),
            engine: Engine::Redshift,
            role: "limen_md5".into(),
            login_user: "limen_md5".into(),
            database: "orders".into(),
            target: t,
            password,
            normalize_literals: false,
            registry: Arc::default(),
        };
        let _ = serve(stream, cfg, em).await;
    });
    let mut client = PgConnection::connect_with(
        &PgConnectOptions::new()
            .host("127.0.0.1")
            .port(addr.port())
            .username("limen_md5")
            .database("orders")
            .ssl_mode(PgSslMode::Disable),
    )
    .await
    .expect("md5 login through the relay");
    let n: i64 = sqlx::query("select count(*) from orders")
        .fetch_one(&mut client)
        .await
        .expect("count")
        .get(0);
    assert_eq!(n, 3);
}
