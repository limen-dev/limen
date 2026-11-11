//! The console Controls page (ADR-0051): readers see it, only admins start a
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
}
