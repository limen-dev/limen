//! The console Controls page (ADR-0053): readers see it, only admins start a
//! run, and a POST needs the console's own origin and CSRF token. Set
//! `LIMEN_TEST_DATABASE_URL` to run them.

#![allow(clippy::large_futures)]

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::Harness;
use limen_control_plane::console;
use limen_control_plane::console::store::{ConsoleSession, create_console_session};
use limen_tunnel::tls::Identity;
use tower::ServiceExt as _;

const ORIGIN: &str = "https://console.test";

fn token(name: &str) -> String {
    format!("console-token-{name}")
}

fn request(
    method: &str,
    uri: &str,
    who: &str,
    proxy: &Identity,
    form: Option<&str>,
    origin: bool,
) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .header(limen_proto::relay::FORWARDED, "1")
        .uri(uri)
        .header(
            "cookie",
            format!("{}={}", console::SESSION_COOKIE, token(who)),
        )
        .header("sec-fetch-site", "same-origin");
    if origin {
        b = b.header("origin", ORIGIN);
    }
    if form.is_some() {
        b = b.header("content-type", "application/x-www-form-urlencoded");
    }
    let mut r = b
        .body(Body::from(form.unwrap_or_default().to_owned()))
        .expect("request");
    r.extensions_mut().insert(limen_tunnel::PeerInfo {
        remote_addr: None,
        server_name: None,
        client_certs: proxy.certs.clone(),
    });
    r
}

async fn session(h: &Harness, who: &str, role: &str) {
    create_console_session(
        &h.state.db,
        &console::hash(&token(who)),
        &ConsoleSession {
            username: who.into(),
            roles: vec![role.to_owned()],
            login_id: format!("login-{who}"),
            csrf: "csrf-token".into(),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        },
    )
    .await
    .expect("session");
}

#[tokio::test]
async fn readers_see_the_page_and_only_admins_start_a_run_with_a_csrf_token() {
    let Some(h) = Harness::start_with(&[
        format!("--console-public-url={ORIGIN}"),
        "--console-oidc-client-secret=s3cr3t".to_owned(),
    ])
    .await
    else {
        return;
    };
    session(&h, "root", limen_core::identity::ADMIN_ROLE).await;
    session(&h, "audit", limen_core::identity::AUDITOR_ROLE).await;
    session(&h, "dev", "some-role").await;
    let (_, proxy) = h.enroll_proxy().await;
    let app = console::router(h.state.clone());
    let send = |r: Request<Body>| {
        let app = app.clone();
        async move { app.oneshot(r).await.expect("response") }
    };

    // An auditor reads; a developer does not.
    let page = send(request(
        "GET",
        "/console/controls",
        "audit",
        &proxy,
        None,
        false,
    ))
    .await;
    assert_eq!(page.status(), StatusCode::OK);
    let body = axum::body::to_bytes(page.into_body(), 1 << 20)
        .await
        .expect("body");
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("Controls"), "{html}");
    assert!(
        !html.contains("Run a self-test now"),
        "an auditor can't start a run"
    );
    let denied = send(request(
        "GET",
        "/console/controls",
        "dev",
        &proxy,
        None,
        false,
    ))
    .await;
    assert_ne!(denied.status(), StatusCode::OK);

    // A POST needs the admin, the origin and the token.
    let run = "/console/controls/run";
    for (who, form, origin) in [
        ("audit", "csrf=csrf-token", true),
        ("dev", "csrf=csrf-token", true),
        ("root", "csrf=wrong", true),
        ("root", "csrf=csrf-token", false),
    ] {
        let r = send(request("POST", run, who, &proxy, Some(form), origin)).await;
        assert_ne!(
            r.status(),
            StatusCode::SEE_OTHER,
            "{who} {form} origin={origin} must be refused"
        );
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM selftest_runs")
        .fetch_one(&h.state.db)
        .await
        .expect("count");
    assert_eq!(count, 0, "no refused request started a run");

    let ok = send(request(
        "POST",
        run,
        "root",
        &proxy,
        Some("csrf=csrf-token"),
        true,
    ))
    .await;
    assert_eq!(ok.status(), StatusCode::SEE_OTHER);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM selftest_runs")
        .fetch_one(&h.state.db)
        .await
        .expect("count");
    assert_eq!(count, 1);

    // The download is named for when the run started, so reports saved over time sort and never
    // overwrite each other.
    let (id, started): (uuid::Uuid, time::OffsetDateTime) = {
        let mut found = None;
        for _ in 0..200 {
            found = sqlx::query_as(
                "SELECT id, started_at FROM selftest_runs WHERE report IS NOT NULL LIMIT 1",
            )
            .fetch_optional(&h.state.db)
            .await
            .expect("run");
            if found.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        found.expect("the run produced a report")
    };
    let dl = send(request(
        "GET",
        &format!("/console/controls/{id}/report"),
        "audit",
        &proxy,
        None,
        false,
    ))
    .await;
    assert_eq!(dl.status(), StatusCode::OK);
    let disposition = dl
        .headers()
        .get("content-disposition")
        .and_then(|v| v.to_str().ok())
        .expect("a content-disposition")
        .to_owned();
    assert_eq!(
        disposition,
        format!(
            "attachment; filename=\"{}\"",
            limen_verify::controls::report_file_name(started.unix_timestamp())
        )
    );
    assert!(
        disposition.contains("limen-controls-report-20"),
        "{disposition}"
    );
}

/// The sidebar groups (ADR-0053): what each role is offered, and nothing that
/// would answer 403. Audit trail and Controls are for admins and auditors;
/// Dashboards and everything under Administration are for admins.
#[tokio::test]
async fn the_sidebar_offers_each_role_only_what_it_can_open() {
    let Some(h) = Harness::start_with(&[
        format!("--console-public-url={ORIGIN}"),
        "--console-oidc-client-secret=s3cr3t".to_owned(),
    ])
    .await
    else {
        return;
    };
    session(&h, "root", limen_core::identity::ADMIN_ROLE).await;
    session(&h, "audit", limen_core::identity::AUDITOR_ROLE).await;
    session(&h, "dev", "some-role").await;
    let (_, proxy) = h.enroll_proxy().await;
    let app = console::router(h.state.clone());
    let sidebar = |who: &'static str| {
        let app = app.clone();
        let proxy = proxy.clone();
        async move {
            let r = app
                .oneshot(request("GET", "/console/", who, &proxy, None, false))
                .await
                .expect("response");
            assert_eq!(r.status(), StatusCode::OK, "{who}");
            let body = axum::body::to_bytes(r.into_body(), 1 << 20)
                .await
                .expect("body");
            let html = String::from_utf8_lossy(&body).into_owned();
            html.split("<nav class=\"nav\"")
                .nth(1)
                .and_then(|n| n.split("</nav>").next())
                .expect("a sidebar")
                .to_owned()
        }
    };
    let links = |nav: &str, path: &str| nav.contains(&format!("href=\"{path}\""));
    let all_admin = [
        "/console/users",
        "/console/bots",
        "/console/workers",
        "/console/policy",
        "/console/simulator",
        "/console/integrations",
    ];

    let admin = sidebar("root").await;
    assert!(admin.contains("Record") && admin.contains("Administration"));
    // Each group has a button that controls its own list of links.
    for group in ["record", "administration"] {
        assert!(
            admin.contains(&format!("aria-controls=\"nav-{group}\"")),
            "{group}"
        );
        assert!(admin.contains(&format!("id=\"nav-{group}\"")), "{group}");
    }
    for p in ["/console/audit", "/console/controls", "/console/dashboards"] {
        assert!(links(&admin, p), "admin: {p}");
    }
    for p in all_admin {
        assert!(links(&admin, p), "admin: {p}");
    }
    // One Audit trail link, not one per group.
    assert_eq!(admin.matches("href=\"/console/audit\"").count(), 1);

    let auditor = sidebar("audit").await;
    assert!(auditor.contains("Record") && !auditor.contains("Administration"));
    assert!(links(&auditor, "/console/audit") && links(&auditor, "/console/controls"));
    assert!(
        !links(&auditor, "/console/dashboards"),
        "dashboards are admin-only"
    );
    for p in all_admin {
        assert!(!links(&auditor, p), "auditor must not be offered {p}");
    }

    let person = sidebar("dev").await;
    assert!(!person.contains("Record") && !person.contains("Administration"));
    for p in ["/console/audit", "/console/controls", "/console/dashboards"] {
        assert!(!links(&person, p), "person must not be offered {p}");
    }
    for p in all_admin {
        assert!(!links(&person, p), "person must not be offered {p}");
    }
}
