//! The Resources pages (ADR-0055): what the list and the detail page show to an admin and to
//! someone who only holds a role, and that nothing about other people or hidden resources leaks
//! through sorting, filters, tabs or the palette's suggestions. Set `LIMEN_TEST_DATABASE_URL` to
//! run them.

#![allow(clippy::large_futures)]

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::Harness;
use limen_control_plane::console;
use limen_control_plane::console::store::{ConsoleSession, create_console_session};
use limen_tunnel::tls::Identity;
use tower::ServiceExt as _;
use uuid::Uuid;

const ADMIN: &str = "test-console-token-res-admin";
const DEV: &str = "test-console-token-res-dev";
const ROLES: &str = include_str!("../../../examples/policy/shared/roles.yaml");

const RESOURCES: &str = "\
kind: resource
version: v1
metadata: { name: web-1, labels: { env: staging } }
spec:
  ssh: { address: \"web-1:22\" }
  worker_selector: { pool: dev }
---
kind: resource
version: v1
metadata: { name: db-1, labels: { env: staging } }
spec:
  postgres: { endpoint: \"db-1:5432\", iam_auth: false, default_database: orders, password_dir: /tmp/none, admin_user: limen_admin, admin_password_file: /tmp/none }
  worker_selector: { pool: dev }
---
kind: resource
version: v1
metadata: { name: hidden-prod, labels: { env: prod } }
spec:
  ssh: { address: \"prod-1:22\" }
  worker_selector: { pool: dev }
";

fn get(uri: &str, token: &str, proxy: &Identity) -> Request<Body> {
    let mut request = Request::builder()
        .header(limen_proto::relay::FORWARDED, "1")
        .uri(uri)
        .header("cookie", format!("{}={token}", console::SESSION_COOKIE))
        .header("sec-fetch-site", "same-origin")
        .body(Body::empty())
        .expect("request");
    request.extensions_mut().insert(limen_tunnel::PeerInfo {
        remote_addr: None,
        server_name: None,
        client_certs: proxy.certs.clone(),
    });
    request
}

/// One resource of each kind the command builder covers, and a role that opens each as several
/// identities, so the choices have something to choose from.
const BUILDER_POLICY: &str = "\
kind: resource
version: v1
metadata: { name: db-many, labels: { env: dev } }
spec:
  postgres: { endpoint: \"db-many:5432\", iam_auth: false, default_database: orders, password_dir: /tmp/none, admin_user: limen_admin, admin_password_file: /tmp/none }
  worker_selector: { pool: dev }
---
kind: resource
version: v1
metadata: { name: redis-many, labels: { env: dev } }
spec:
  redis: { endpoint: \"redis-many:6379\", iam_auth: false, tls: false }
  worker_selector: { pool: dev }
---
kind: resource
version: v1
metadata: { name: mongo-many, labels: { env: dev } }
spec:
  mongodb: { endpoint: \"mongo-many:27017\", credentials_dir: /c, tls_ca_file: /ca.pem }
  worker_selector: { pool: dev }
---
kind: resource
version: v1
metadata: { name: search-many, labels: { env: dev } }
spec:
  elasticsearch: { endpoint: \"search-many:9200\", tls: false }
  worker_selector: { pool: dev }
---
kind: resource
version: v1
metadata: { name: mq-many, labels: { env: dev } }
spec:
  rabbitmq: { endpoint: \"mq-many:5672\", tls: false }
  worker_selector: { pool: dev }
---
kind: resource
version: v1
metadata: { name: kafka-many, labels: { env: dev } }
spec:
  kafka: { endpoint: \"kafka-many:9092\", tls: false, sasl: plain }
  worker_selector: { pool: dev }
---
kind: role
version: v1
metadata: { name: builder-many }
spec:
  allow:
    - resources: { kind: [postgres], labels: { env: [dev] } }
      db: { roles: [limen_ro, limen_rw], databases: [orders, billing] }
    - resources: { kind: [redis], labels: { env: [dev] } }
      redis: { users: [cache_ro, cache_rw], keys: [\"app:*\"] }
    - resources: { kind: [mongodb], labels: { env: [dev] } }
      mongo: { roles: [ro, rw], databases: [\"*\"] }
    - resources: { kind: [elasticsearch], labels: { env: [dev] } }
      search: { roles: [r1, r2], classes: [read, write], indices: [\"app-*\"] }
    - resources: { kind: [rabbitmq], labels: { env: [dev] } }
      mq: { users: [w, r], vhosts: [jobs, \"billing-*\"] }
    - resources: { kind: [kafka], labels: { env: [dev] } }
      kafka: { users: [c, p], topics: [\"orders.*\"] }
";

const ERIN: &str = "test-console-token-res-erin";

const ORIGIN: &str = "https://console.test";

fn post(uri: &str, token: &str, form: &str, origin: bool, proxy: &Identity) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .header(limen_proto::relay::FORWARDED, "1")
        .uri(uri)
        .header("cookie", format!("{}={token}", console::SESSION_COOKIE))
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "application/x-www-form-urlencoded");
    if origin {
        b = b.header("origin", ORIGIN);
    }
    let mut request = b.body(Body::from(form.to_owned())).expect("request");
    request.extensions_mut().insert(limen_tunnel::PeerInfo {
        remote_addr: None,
        server_name: None,
        client_certs: proxy.certs.clone(),
    });
    request
}

async fn session(h: &Harness, token: &str, user: &str, roles: &[&str]) {
    create_console_session(
        &h.state.db,
        &console::hash(token),
        &ConsoleSession {
            username: user.into(),
            roles: roles.iter().map(|r| (*r).to_owned()).collect(),
            login_id: format!("l-{user}"),
            csrf: "c".into(),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        },
    )
    .await
    .expect("session");
}

async fn seed(
    h: &Harness,
    user: &str,
    resource: &str,
    kind: &str,
    open: bool,
    ago_secs: i32,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sessions (session_id, username, kind, resource, login, started_at, ended_at, actor_type)
         VALUES ($1, $2, $3, $4, 'ubuntu', now() - make_interval(secs => $5), \
                 CASE WHEN $6 THEN NULL ELSE now() END, 'user')",
    )
    .bind(id)
    .bind(user)
    .bind(kind)
    .bind(resource)
    .bind(f64::from(ago_secs))
    .bind(open)
    .execute(&h.state.db)
    .await
    .expect("seed a session");
    id
}

/// The text of the table row that holds `name`'s link.
fn row_of<'a>(body: &'a str, name: &str) -> &'a str {
    let marker = format!("href=\"/console/resources/{name}\"");
    let at = body
        .find(&marker)
        .unwrap_or_else(|| panic!("no row for {name}"));
    let end = body[at..].find("</tr>").map_or(body.len(), |e| at + e);
    &body[at..end]
}

/// Where `/resources/<name>"` first appears: the order rows come in.
fn pos(body: &str, name: &str) -> usize {
    body.find(&format!("/resources/{name}\""))
        .unwrap_or_else(|| panic!("{name} is not listed"))
}

/// A control plane with three resources, an admin, Dana (a role that opens only the staging ones)
/// and some sessions: Dana is on web-1 now, and root used db-1 twice (Dana must not learn that).
struct Fixture {
    h: Harness,
    proxy: Identity,
}

impl Fixture {
    async fn start() -> Option<Self> {
        Self::start_with(&[]).await
    }

    async fn start_with(extra: &[(&str, &str)]) -> Option<Self> {
        let h = Harness::start_with(&[
            "--console-public-url=https://console.test".to_owned(),
            "--console-oidc-client-secret=s3cr3t".to_owned(),
        ])
        .await?;
        let mut files = vec![("roles.yaml", ROLES), ("resources.yaml", RESOURCES)];
        files.extend_from_slice(extra);
        h.set_policy(&files);
        session(&h, ADMIN, "root", &[limen_core::identity::ADMIN_ROLE]).await;
        session(&h, DEV, "dana", &["dev-readonly"]).await;
        seed(&h, "dana", "web-1", "ssh", true, 120).await;
        seed(&h, "root", "db-1", "postgres", false, 60).await;
        seed(&h, "root", "db-1", "postgres", false, 90).await;
        let (_, proxy) = h.enroll_proxy().await;
        Some(Self { h, proxy })
    }

    /// A POST with the right origin and the session's CSRF token (`c`) added to `form`.
    async fn act(&self, uri: &str, token: &str, form: &str) -> (StatusCode, Option<String>) {
        let response = console::router(self.h.state.clone())
            .oneshot(post(
                uri,
                token,
                &format!("csrf=c&{form}"),
                true,
                &self.proxy,
            ))
            .await
            .expect("response");
        let location = response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        (response.status(), location)
    }

    async fn page(&self, uri: &str, token: &str) -> (StatusCode, String) {
        let response = console::router(self.h.state.clone())
            .oneshot(get(uri, token, &self.proxy))
            .await
            .expect("response");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("body");
        (status, String::from_utf8_lossy(&body).into_owned())
    }
}

#[tokio::test]
async fn the_admins_list_shows_status_sorts_and_filters() {
    let Some(f) = Fixture::start().await else {
        return;
    };
    let (status, body) = f.page("/console/resources", ADMIN).await;
    assert_eq!(status, StatusCode::OK);
    for name in ["web-1", "db-1", "hidden-prod"] {
        assert!(
            body.contains(&format!("/console/resources/{name}\"")),
            "{name}"
        );
    }
    assert!(
        row_of(&body, "web-1").contains("no worker"),
        "no worker is enrolled, so the admin is told sessions will fail"
    );
    assert!(row_of(&body, "web-1").contains("1 live"));
    assert!(body.contains("Needs attention"), "the filter is offered");
    assert!(
        pos(&body, "db-1") < pos(&body, "web-1"),
        "by name by default"
    );

    let (_, busiest) = f.page("/console/resources?sort=busiest", ADMIN).await;
    assert!(
        pos(&busiest, "web-1") < pos(&busiest, "db-1"),
        "web-1 has a live session, so busiest puts it first"
    );
    assert!(busiest.contains("<option value=\"busiest\" selected>"));

    let (_, attention) = f.page("/console/resources?attention=1", ADMIN).await;
    assert!(
        attention.contains("/resources/hidden-prod\""),
        "no worker is enrolled, so all three need attention"
    );

    let (status, junk) = f
        .page(
            "/console/resources?sort=%27%3Cscript%3E&attention=%00",
            ADMIN,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a junk sort is the default, not an error"
    );
    assert!(!junk.contains("<script>"));
}

#[tokio::test]
async fn a_members_list_has_only_their_resources_and_their_own_use() {
    let Some(f) = Fixture::start().await else {
        return;
    };
    let (status, body) = f.page("/console/resources", DEV).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("hidden-prod"),
        "a resource her roles don't open is not listed"
    );
    assert!(
        row_of(&body, "web-1").contains("data-copy=\"limen ssh web-1\""),
        "a row she can open has its command to copy"
    );
    assert!(
        row_of(&body, "web-1").contains("<time datetime="),
        "she used web-1"
    );
    assert!(
        row_of(&body, "db-1").contains("never"),
        "somebody else's session on db-1 is not Dana's last use"
    );
    for leak in [
        "no worker",
        "live",
        "Needs attention",
        "Roles with access",
        "web-1:22",
    ] {
        assert!(!body.contains(leak), "{leak:?} is for admins");
    }

    // Admin-only sorts and filters are ignored for her: never an error, never a leak.
    let (status, same) = f
        .page("/console/resources?sort=busiest&attention=1", DEV)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        pos(&same, "db-1") < pos(&same, "web-1"),
        "she gets the default order, not the busiest-first one"
    );
    let (_, recent) = f.page("/console/resources?sort=recent", DEV).await;
    assert!(
        pos(&recent, "web-1") < pos(&recent, "db-1"),
        "recently used puts web-1 (hers) before db-1 (never used by her)"
    );
}

#[tokio::test]
async fn the_detail_page_leads_with_how_to_connect_and_keeps_admin_things_back() {
    let Some(f) = Fixture::start().await else {
        return;
    };
    let (status, body) = f.page("/console/resources/web-1", DEV).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("limen ssh ubuntu@web-1"),
        "the command names her login"
    );
    assert!(body.contains("limen login"));
    for leak in [
        "Workers that can serve it",
        "web-1:22",
        "Who can reach it",
        "On it now",
        ">Access</a>",
    ] {
        assert!(!body.contains(leak), "{leak:?} is not for Dana");
    }
    let (_, body) = f.page("/console/resources/web-1?tab=access", DEV).await;
    assert!(
        !body.contains("Who can reach it"),
        "the access tab is not hers, whatever the address says"
    );
    for hidden in [
        "/console/resources/hidden-prod",
        "/console/resources/hidden-prod?tab=access",
    ] {
        let (status, _) = f.page(hidden, DEV).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{hidden}: no hint that it exists"
        );
    }

    let (_, body) = f.page("/console/resources/web-1", ADMIN).await;
    assert!(
        body.contains("no worker"),
        "the status strip says why sessions would fail"
    );
    assert!(
        body.contains("On it now") && body.contains("dana"),
        "the live session is listed"
    );
    assert!(body.contains("/console/audit?q=web-1"));
    let (_, body) = f.page("/console/resources/web-1?tab=access", ADMIN).await;
    assert!(body.contains("Who can reach it"));
    let (_, body) = f.page("/console/resources/web-1?tab=activity", ADMIN).await;
    assert!(body.contains("Filter and search"));
    let (status, body) = f.page("/console/resources/db-1", ADMIN).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("--db-role"),
        "an admin without a role on it has no principal to connect as"
    );
}

#[tokio::test]
async fn the_palette_and_the_overview_follow_the_same_access_rules() {
    let Some(f) = Fixture::start().await else {
        return;
    };
    let (status, body) = f.page("/console/suggest/resources?q=web", DEV).await;
    assert_eq!(status, StatusCode::OK);
    let found: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(found[0]["name"], "web-1");
    assert_eq!(found[0]["href"], "/console/resources/web-1");
    let (_, body) = f.page("/console/suggest/resources?q=prod", DEV).await;
    assert_eq!(body.trim(), "[]", "Dana is not told a prod resource exists");
    let (_, body) = f.page("/console/suggest/resources?q=prod", ADMIN).await;
    assert!(body.contains("hidden-prod"));

    let (status, body) = f.page("/console/", DEV).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Continue where you left off") && body.contains("limen ssh web-1"));
    assert!(!body.contains("Needs you"), "nothing is waiting on Dana");
    let (_, body) = f.page("/console/", ADMIN).await;
    assert!(
        body.contains("Needs you"),
        "resources with no worker are called out"
    );
    let link = body
        .split("href=\"")
        .filter_map(|s| s.split('"').next())
        .find(|h| h.starts_with("/console/resources?sort=attention"))
        .expect("the card links to the attention view");
    assert!(link.contains("attention=1"), "{link}");
}

#[tokio::test]
async fn pins_and_saved_views_are_per_person_checked_and_bounded() {
    let Some(f) = Fixture::start().await else {
        return;
    };
    // Dana pins a resource she can open, and comes back to where she was.
    let (status, to) = f
        .act(
            "/console/pins",
            DEV,
            "kind=resource&target=web-1&action=add&back=%2Fconsole%2Fresources",
        )
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(to.as_deref(), Some("/console/resources"));
    let (_, body) = f.page("/console/resources", DEV).await;
    assert!(row_of(&body, "web-1").contains("aria-pressed=\"true\""));
    assert!(row_of(&body, "db-1").contains("aria-pressed=\"false\""));
    let (_, body) = f.page("/console/", DEV).await;
    assert!(body.contains("Pinned") && body.contains("limen ssh web-1"));
    // Not anyone else's: the admin's row for the same resource is not pinned.
    let (_, body) = f.page("/console/resources", ADMIN).await;
    assert!(row_of(&body, "web-1").contains("aria-pressed=\"false\""));

    // A resource she can't see: no pin, and no hint it exists.
    let (status, _) = f
        .act(
            "/console/pins",
            DEV,
            "kind=resource&target=hidden-prod&action=add",
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // An admin may pin it; a member may not save a page they can't open.
    let (status, _) = f
        .act(
            "/console/pins",
            ADMIN,
            "kind=resource&target=hidden-prod&action=add",
        )
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    // The admin sees it on the Overview even though no role of theirs opens it; Dana does not.
    let (_, body) = f.page("/console/", ADMIN).await;
    assert!(body.contains("hidden-prod") && body.contains("Not opened by your own roles"));
    let (_, body) = f.page("/console/", DEV).await;
    assert!(!body.contains("hidden-prod"));
    for (who, form, want) in [
        (
            ADMIN,
            "kind=view&action=add&label=Denials&target=%2Fconsole%2Fdashboards%3Fp%3Ddenials",
            StatusCode::SEE_OTHER,
        ),
        (
            DEV,
            "kind=view&action=add&label=x&target=%2Fconsole%2Fdashboards",
            StatusCode::FORBIDDEN,
        ),
        (
            DEV,
            "kind=view&action=add&label=x&target=%2Fconsole%2Faudit",
            StatusCode::FORBIDDEN,
        ),
        (
            DEV,
            "kind=view&action=add&label=x&target=%2Fconsole%2Fusers",
            StatusCode::BAD_REQUEST,
        ),
        (
            DEV,
            "kind=view&action=add&label=x&target=https%3A%2F%2Fevil.example%2F",
            StatusCode::BAD_REQUEST,
        ),
        (
            DEV,
            "kind=view&action=add&label=x&target=%2Fconsole%2Fresources%2Fweb-1",
            StatusCode::BAD_REQUEST,
        ),
        (
            DEV,
            "kind=nonsense&action=add&target=x",
            StatusCode::BAD_REQUEST,
        ),
        (
            DEV,
            "kind=resource&target=web-1&action=toggle",
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let (status, _) = f.act("/console/pins", who, form).await;
        assert_eq!(status, want, "{form}");
    }
    // A saved view shows on the Overview and on its own page; the admin's does not reach Dana.
    let (status, _) = f
        .act(
            "/console/pins",
            DEV,
            "kind=view&action=add&label=Staging+ssh&target=%2Fconsole%2Fresources%3Fkind%3Dssh&back=%2Fconsole%2Fresources",
        )
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, body) = f.page("/console/resources", DEV).await;
    assert!(body.contains("Staging ssh") && !body.contains("Denials"));
    let (_, body) = f.page("/console/", ADMIN).await;
    assert!(body.contains("Denials") && !body.contains("Staging ssh"));
}

#[tokio::test]
async fn a_pin_post_needs_the_token_never_redirects_off_site_and_can_always_remove() {
    let Some(f) = Fixture::start().await else {
        return;
    };
    // The way back is only ever a console address.
    for back in [
        "https%3A%2F%2Fevil.example%2F",
        "%2F%2Fevil.example",
        "%2Fconsole%2F%0D%0Aset-cookie%3Ax",
    ] {
        let (status, to) = f
            .act(
                "/console/pins",
                DEV,
                &format!("kind=resource&target=web-1&action=add&back={back}"),
            )
            .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(to.as_deref(), Some("/console/"), "{back}");
    }

    // No token, or another origin: nothing changes.
    let app = console::router(f.h.state.clone());
    for (form, origin) in [
        ("kind=resource&target=db-1&action=add", true),
        ("csrf=wrong&kind=resource&target=db-1&action=add", true),
        ("csrf=c&kind=resource&target=db-1&action=add", false),
    ] {
        let r = app
            .clone()
            .oneshot(post("/console/pins", DEV, form, origin, &f.proxy))
            .await
            .expect("response");
        assert_ne!(r.status(), StatusCode::SEE_OTHER, "{form} origin={origin}");
    }
    let held: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM console_pins WHERE username = 'dana' AND target = 'db-1'",
    )
    .fetch_one(&f.h.state.db)
    .await
    .expect("count");
    assert_eq!(held, 0);

    // Taking a pin off works even when the resource has gone, or been hidden since.
    sqlx::query("INSERT INTO console_pins (username, kind, target, label) VALUES ('dana', 'resource', 'gone', 'gone')")
        .execute(&f.h.state.db)
        .await
        .expect("seed");
    let (status, _) = f
        .act(
            "/console/pins",
            DEV,
            "kind=resource&target=gone&action=remove",
        )
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM console_pins WHERE target = 'gone'")
        .fetch_one(&f.h.state.db)
        .await
        .expect("count");
    assert_eq!(left, 0);

    // A person keeps at most 50.
    sqlx::query(
        "INSERT INTO console_pins (username, kind, target, label)
         SELECT 'dana', 'view', '/console/sessions?n=' || g, 'v' || g FROM generate_series(1, 60) g
          WHERE (SELECT count(*) FROM console_pins WHERE username = 'dana') + g <= 50",
    )
    .execute(&f.h.state.db)
    .await
    .expect("fill");
    let (status, _) = f
        .act("/console/pins", DEV, "kind=resource&target=db-1&action=add")
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn ending_several_sessions_is_admin_only_and_each_one_is_audited() {
    let Some(f) = Fixture::start().await else {
        return;
    };
    let a = seed(&f.h, "dana", "web-1", "ssh", true, 30).await;
    let b = seed(&f.h, "dana", "web-1", "ssh", true, 20).await;
    let (_, body) = f.page("/console/sessions?filter=active", ADMIN).await;
    assert!(body.contains("End several sessions"));
    let (_, body) = f.page("/console/sessions?filter=active", DEV).await;
    assert!(
        !body.contains("End several sessions"),
        "a member can't end sessions"
    );

    let form = format!("reason=cleanup&id={a}&id={b}");
    let (status, _) = f.act("/console/sessions/kill", DEV, &form).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    for bad in ["reason=x", &format!("reason=&id={a}")] {
        let (status, _) = f.act("/console/sessions/kill", ADMIN, bad).await;
        assert_ne!(status, StatusCode::SEE_OTHER, "{bad}");
    }
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM session_kills")
        .fetch_one(&f.h.state.db)
        .await
        .expect("count");
    assert_eq!(before, 0, "nothing was ended by a refused request");

    let (status, to) = f.act("/console/sessions/kill", ADMIN, &form).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        to.as_deref(),
        Some("/console/sessions?filter=active&done=killed_many")
    );
    let kills =
        f.h.audit_events()
            .await
            .iter()
            .filter(|e| e.kind == limen_audit::EventKind::SessionKill)
            .count();
    assert_eq!(
        kills, 2,
        "one audit event per session, not one for the batch"
    );
    // Ending the same ones again ends nothing new and says so.
    let (status, to) = f.act("/console/sessions/kill", ADMIN, &form).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        to.as_deref(),
        Some("/console/sessions?filter=active&done=killed_some")
    );
}

#[tokio::test]
async fn errors_on_a_resource_are_counted_for_admins_only_and_by_exact_name() {
    let Some(f) = Fixture::start().await else {
        return;
    };
    for (n, resource) in [("web-1", 2), ("web-10", 1)] {
        for _ in 0..resource {
            sqlx::query(
                "INSERT INTO audit_events (event_id, at, kind, username, summary)
                 VALUES ($1, now(), 'auth.denied', 'mallory', $2)",
            )
            .bind(Uuid::new_v4())
            .bind(format!("resource={n}  reason=no role"))
            .execute(&f.h.state.db)
            .await
            .expect("seed");
        }
    }
    let (_, body) = f.page("/console/resources", ADMIN).await;
    assert!(
        row_of(&body, "web-1").contains("title=\"2 refused\""),
        "web-10's refusals are not web-1's"
    );
    assert!(row_of(&body, "db-1").contains("<span class=\"muted\">0</span>"));
    let (_, body) = f
        .page("/console/resources?attention=1&sort=attention", ADMIN)
        .await;
    assert!(body.contains("/resources/web-1\""));
    let (_, body) = f.page("/console/resources", DEV).await;
    assert!(!body.contains("Errors 24 h") && !body.contains("refused"));
    let (_, body) = f.page("/console/resources/web-1", ADMIN).await;
    assert!(
        body.contains("2 refused") && body.contains("/console/audit?kind=auth.denied&amp;q=web-1")
            || body.contains("2 refused")
    );
    let (_, body) = f.page("/console/resources/web-1", DEV).await;
    assert!(!body.contains("refused"));
}

#[tokio::test]
async fn the_overview_warns_of_an_ending_session_and_pages_link_onward() {
    let Some(f) = Fixture::start().await else {
        return;
    };
    sqlx::query("UPDATE console_sessions SET expires_at = now() + interval '10 minutes' WHERE username = 'dana'")
        .execute(&f.h.state.db)
        .await
        .expect("shorten");
    let (_, body) = f.page("/console/", DEV).await;
    assert!(body.contains("Your console session ends in"), "{body}");
    let (_, body) = f.page("/console/", ADMIN).await;
    assert!(!body.contains("Your console session ends in"));

    let id = seed(&f.h, "dana", "web-1", "ssh", true, 5).await;
    let (status, body) = f.page(&format!("/console/sessions/{id}"), ADMIN).await;
    assert_eq!(status, StatusCode::OK);
    for want in [
        "Similar sessions",
        "Audit trail of this session",
        "data-copy-link",
        "data-refresh=\"5\"",
        "class=\"crumbs\"",
    ] {
        assert!(body.contains(want), "{want}");
    }
    let (_, body) = f.page(&format!("/console/sessions/{id}"), DEV).await;
    assert!(
        !body.contains("Audit trail of this session"),
        "the audit trail is not Dana's"
    );

    // A failure says what to do next.
    let (status, body) = f.page("/console/resources/hidden-prod", DEV).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body.contains("Check the address"));
}

#[tokio::test]
async fn the_command_builder_offers_only_what_access_allows_and_never_a_bad_value() {
    let Some(f) = Fixture::start_with(&[("builder.yaml", BUILDER_POLICY)]).await else {
        return;
    };
    session(&f.h, ERIN, "erin", &["builder-many"]).await;
    let page = |uri: &'static str| {
        let f = &f;
        async move { f.page(uri, ERIN).await }
    };

    // Several identities: nothing to run until one is chosen, and the choice is listed.
    let (status, body) = page("/console/resources/db-many").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Build your command"));
    assert!(body.contains("Choose a database role to see the command."));
    assert!(body.contains("<option value=\"limen_rw\">limen_rw</option>"));
    assert!(
        body.contains("limen db connect db-many --db-role limen_ro"),
        "the quick commands name each role"
    );

    // A role and one of its databases.
    let (_, body) =
        page("/console/resources/db-many?who=limen_rw&database=billing&port=6543").await;
    assert!(
        body.contains(
            "<code>limen db connect db-many --db-role limen_rw --database billing --listen 127.0.0.1:6543</code>"
        ),
        "{body}"
    );
    assert!(body.contains("Databases") && body.contains("billing, orders"));

    // A database the role may not open, a name that is not plain, and a bad port: no command.
    for (uri, says) in [
        (
            "/console/resources/db-many?who=limen_rw&database=secret",
            "may not open secret",
        ),
        (
            "/console/resources/db-many?who=limen_rw&database=a%20b%3Brm%20-rf",
            "letters, digits",
        ),
        (
            "/console/resources/db-many?who=limen_rw&port=80",
            "number from 1024",
        ),
        (
            "/console/resources/db-many?who=root",
            "include root as a database role",
        ),
    ] {
        let (status, body) = f.page(uri, ERIN).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert!(body.contains(says), "{uri}: {says}");
        assert!(
            !body.contains("<div class=\"built\">"),
            "{uri}: a refused choice gives no command"
        );
    }
    // What was typed is escaped when it is echoed.
    let (_, body) = page("/console/resources/db-many?who=%3Cscript%3Ealert(1)%3C/script%3E").await;
    assert!(!body.contains("<script>alert(1)"));
    assert!(body.contains("&#60;script&#62;alert(1)"), "{body}");

    // Each protocol has its own flag.
    for (uri, command) in [
        (
            "/console/resources/redis-many?who=cache_rw",
            "limen redis connect redis-many --user cache_rw",
        ),
        (
            "/console/resources/mongo-many?who=rw&database=orders",
            "limen mongo connect mongo-many --role rw --database orders",
        ),
        (
            "/console/resources/search-many?who=r2",
            "limen search connect search-many --role r2",
        ),
        (
            "/console/resources/mq-many?who=w&vhost=billing-eu",
            "limen mq connect mq-many --user w --vhost billing-eu",
        ),
        (
            "/console/resources/kafka-many?who=c&port=9199",
            "limen kafka connect kafka-many --user c --listen 127.0.0.1:9199",
        ),
    ] {
        let (status, body) = f.page(uri, ERIN).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert!(body.contains(&format!("<code>{command}</code>")), "{uri}");
    }
    // The quick commands use the same flags.
    let (_, body) = page("/console/resources/mongo-many").await;
    assert!(body.contains("limen mongo connect mongo-many --role ro"));
    // What each identity may do is shown.
    let (_, body) = page("/console/resources/search-many?who=r1").await;
    assert!(body.contains("read, write") && body.contains("app-*"));
    let (_, body) = page("/console/resources/kafka-many?who=p").await;
    assert!(body.contains("orders.*") && body.contains("Consumer groups"));
    let (_, body) = page("/console/resources/mq-many?who=r").await;
    assert!(body.contains("billing-*, jobs"));

    // Not for people who hold none of it: a member without the role gets a 404, and an admin sees
    // no builder for access they don't hold themselves.
    let (status, _) = f.page("/console/resources/db-many?who=limen_rw", DEV).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, body) = f
        .page("/console/resources/db-many?who=limen_rw", ADMIN)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.contains("Build your command"));
    assert!(!body.contains("--db-role limen_rw"));

    // Dana's single identity needs no flag; the wildcard database is a text box.
    let (_, body) = f.page("/console/resources/db-1", DEV).await;
    assert!(body.contains("<code>limen db connect db-1</code>"));
    assert!(body.contains("any database"));
}
