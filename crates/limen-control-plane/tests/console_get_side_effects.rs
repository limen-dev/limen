//! Console GETs that do something (export the record, start a watch) refuse a
//! request that did not come from the console. Set `LIMEN_TEST_DATABASE_URL`
//! to run them.

#![allow(clippy::large_futures)]

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::Harness;
use limen_audit::EventKind;
use limen_control_plane::console;
use limen_control_plane::console::store::{ConsoleSession, create_console_session};
use limen_tunnel::tls::Identity;
use tower::ServiceExt as _;

const TOKEN: &str = "test-console-token";

fn get(uri: &str, site: Option<&str>, proxy: &Identity) -> Request<Body> {
    let mut b = Request::builder()
        .header(limen_proto::relay::FORWARDED, "1")
        .uri(uri)
        .header("cookie", format!("{}={TOKEN}", console::SESSION_COOKIE));
    if let Some(site) = site {
        b = b.header("sec-fetch-site", site);
    }
    let mut request = b.body(Body::empty()).expect("request");
    // The console answers only a proxy forwarding a browser's request.
    request.extensions_mut().insert(limen_tunnel::PeerInfo {
        remote_addr: None,
        server_name: None,
        client_certs: proxy.certs.clone(),
    });
    request
}

#[tokio::test]
async fn evidence_export_and_watch_need_a_same_origin_request() {
    let Some(h) = Harness::start_with(&[
        "--console-public-url=https://console.test".to_owned(),
        "--console-oidc-client-secret=s3cr3t".to_owned(),
    ])
    .await
    else {
        return;
    };
    create_console_session(
        &h.state.db,
        &console::hash(TOKEN),
        &ConsoleSession {
            username: "root".into(),
            roles: vec![limen_core::identity::ADMIN_ROLE.to_owned()],
            login_id: "l1".into(),
            csrf: "c".into(),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        },
    )
    .await
    .expect("session");
    let (_, proxy) = h.enroll_proxy().await;
    let app = console::router(h.state.clone());
    let export = "/console/reviews/evidence?from=2026-01-01&to=2026-01-31";
    let watch = "/console/sessions/00000000-0000-0000-0000-000000000001/watch/stream";

    for uri in [export, watch] {
        for site in [Some("cross-site"), Some("same-site"), None] {
            let status = app
                .clone()
                .oneshot(get(uri, site, &proxy))
                .await
                .expect("response")
                .status();
            assert_eq!(status, StatusCode::FORBIDDEN, "{uri} {site:?}");
        }
    }
    assert!(
        !h.audit_kinds().await.contains(&EventKind::EvidenceExport),
        "a refused request exports nothing"
    );

    let ok = app
        .clone()
        .oneshot(get(export, Some("same-origin"), &proxy))
        .await
        .expect("response");
    let status = ok.status();
    let body = axum::body::to_bytes(ok.into_body(), 1 << 20)
        .await
        .expect("body");
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert!(h.audit_kinds().await.contains(&EventKind::EvidenceExport));
}
