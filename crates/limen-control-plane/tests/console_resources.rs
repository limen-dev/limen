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

async fn seed(h: &Harness, user: &str, resource: &str, kind: &str, open: bool, ago_secs: i32) {
    sqlx::query(
        "INSERT INTO sessions (session_id, username, kind, resource, login, started_at, ended_at, actor_type)
         VALUES ($1, $2, $3, $4, 'ubuntu', now() - make_interval(secs => $5), \
                 CASE WHEN $6 THEN NULL ELSE now() END, 'user')",
    )
    .bind(Uuid::new_v4())
    .bind(user)
    .bind(kind)
    .bind(resource)
    .bind(f64::from(ago_secs))
    .bind(open)
    .execute(&h.state.db)
    .await
    .expect("seed a session");
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
        let h = Harness::start_with(&[
            "--console-public-url=https://console.test".to_owned(),
            "--console-oidc-client-secret=s3cr3t".to_owned(),
        ])
        .await?;
        h.set_policy(&[("roles.yaml", ROLES), ("resources.yaml", RESOURCES)]);
        session(&h, ADMIN, "root", &[limen_core::identity::ADMIN_ROLE]).await;
        session(&h, DEV, "dana", &["dev-readonly"]).await;
        seed(&h, "dana", "web-1", "ssh", true, 120).await;
        seed(&h, "root", "db-1", "postgres", false, 60).await;
        seed(&h, "root", "db-1", "postgres", false, 90).await;
        let (_, proxy) = h.enroll_proxy().await;
        Some(Self { h, proxy })
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
