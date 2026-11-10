//! Every link the console draws to a user has a page behind it: a person, a bot that policy
//! defines but that never logged in, and an actor that only the audit trail knows
//! (`system:idp-check`). A name nothing knows is still a 404. Set `LIMEN_TEST_DATABASE_URL`
//! to run them.

#![allow(clippy::large_futures)]

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::Harness;
use limen_control_plane::console;
use limen_control_plane::console::store::{ConsoleSession, create_console_session};
use limen_tunnel::tls::Identity;
use tower::ServiceExt as _;

const TOKEN: &str = "test-console-token-users";
const ROLES: &str = include_str!("../../../examples/policy/shared/roles.yaml");

fn get(uri: &str, proxy: &Identity) -> Request<Body> {
    let mut request = Request::builder()
        .header(limen_proto::relay::FORWARDED, "1")
        .uri(uri)
        .header("cookie", format!("{}={TOKEN}", console::SESSION_COOKIE))
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

#[tokio::test]
async fn user_links_resolve_for_bots_and_audit_only_actors() {
    let Some(h) = Harness::start_with(&[
        "--console-public-url=https://console.test".to_owned(),
        "--console-oidc-client-secret=s3cr3t".to_owned(),
        "--bot-allow-insecure-issuers".to_owned(),
    ])
    .await
    else {
        return;
    };
    let bot = format!(
        "kind: role\nversion: v1\nmetadata: {{ name: deployer }}\nspec:\n  allow:\n    - resources: {{ kind: [ssh], labels: {{ env: [staging] }} }}\n      ssh: {{ logins: [ubuntu] }}\n---\n\
kind: bot\nversion: v1\nmetadata: {{ name: never-ran }}\nspec:\n  join:\n    method: github_actions\n    issuer: {}\n    match:\n      repository: acme/infra\n      ref: refs/heads/main\n  roles: [deployer]\n",
        h.idp.issuer
    );
    h.set_policy(&[("roles.yaml", ROLES), ("bots.yaml", &bot)]);
    create_console_session(
        &h.state.db,
        &console::hash(TOKEN),
        &ConsoleSession {
            username: "root".into(),
            roles: vec![limen_core::identity::ADMIN_ROLE.to_owned()],
            login_id: "l-users".into(),
            csrf: "c".into(),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        },
    )
    .await
    .expect("session");
    let mut event = limen_audit::Event::new(
        limen_audit::EventKind::AuthLogin,
        limen_audit::Producer {
            component: "control-plane".into(),
            instance_id: "cp".into(),
            seq: 0,
        },
        serde_json::json!({}),
    );
    event.user = Some("system:idp-check".into());
    console::store::project_events(&h.state.db, &[event])
        .await
        .expect("project");
    let (_, proxy) = h.enroll_proxy().await;
    let app = console::router(h.state.clone());

    let page = |uri: &'static str| {
        let app = app.clone();
        let proxy = proxy.clone();
        async move {
            let response = app.oneshot(get(uri, &proxy)).await.expect("response");
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .expect("body");
            (status, String::from_utf8_lossy(&body).into_owned())
        }
    };

    let (status, body) = page("/console/users/bot%3Anever-ran").await;
    assert_eq!(status, StatusCode::OK, "a bot policy defines has a page");
    assert!(body.contains("All bots"), "it links back to the bots");
    assert!(
        !body.contains("IdP groups"),
        "IdP rows don't apply to a bot"
    );

    let (status, body) = page("/console/users/system%3Aidp-check").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an actor in the audit trail has a page"
    );
    assert!(body.contains("audit trail only"));
    assert!(
        !body.contains("/lock\""),
        "there is no account to disable for it"
    );

    let (status, _) = page("/console/users/system").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a prefix of a known name is not that name"
    );

    let (status, _) = page("/console/users/nobody-at-all").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an unknown name is still 404"
    );
}
