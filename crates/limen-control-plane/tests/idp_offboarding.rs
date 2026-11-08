//! IdP-driven offboarding (ADR-0046) against a real PostgreSQL and a mock IdP
//! that issues refresh tokens. Set `LIMEN_TEST_DATABASE_URL` to run them.
//! Everything here is *unverified against a real IdP* (Okta: #64).

mod common;

use std::time::Duration;

use common::{Harness, forwarded};
use limen_audit::EventKind;
use limen_proto::v1::ListResourcesRequest;
use limen_proto::v1::resources_client::ResourcesClient;
use limen_testkit::users::ADMIN;
use limen_tunnel::tls::Identity;
use rustls_pki_types::CertificateDer;

fn key_flag() -> String {
    use base64::Engine as _;
    format!(
        "--idp-token-key={}",
        base64::engine::general_purpose::STANDARD.encode([9u8; 32])
    )
}

async fn start(extra: &[&str]) -> Option<Harness> {
    let mut flags = vec![key_flag(), "--idp-check-interval=1s".to_owned()];
    flags.extend(extra.iter().map(|s| (*s).to_owned()));
    Harness::start_with(&flags).await
}

async fn alive(h: &Harness, proxy: &Identity, cert: &CertificateDer<'static>) -> bool {
    // `WhoAmI` only checks the certificate; listing resources also asks the
    // database whether the login has ended.
    ResourcesClient::new(h.channel(Some(proxy.clone())))
        .list_resources(forwarded(ListResourcesRequest::default(), Some(cert)))
        .await
        .is_ok()
}

async fn status(h: &Harness) -> String {
    sqlx::query_scalar("SELECT idp_status FROM users WHERE username = $1")
        .bind(ADMIN)
        .fetch_one(&h.state.db)
        .await
        .expect("user row")
}

/// Poll until `f` holds, or fail after a generous 20 seconds.
async fn eventually<F, Fut>(what: &str, f: F)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..80 {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("timed out waiting for: {what}");
}

async fn events(h: &Harness, kind: EventKind) -> Vec<limen_audit::Event> {
    h.audit_events()
        .await
        .into_iter()
        .filter(|e| e.kind == kind)
        .collect()
}

#[tokio::test]
async fn a_deactivated_person_loses_their_login() {
    let Some(h) = start(&[]).await else { return };
    let (_, proxy) = h.enroll_proxy().await;
    let refresh = h.idp.issue_refresh_token(ADMIN, &["admins"]);
    let (_, cert) = h
        .login_with_refresh(ADMIN, &["admins"], &refresh)
        .await
        .expect("login");
    assert!(alive(&h, &proxy, &cert).await);
    assert_eq!(status(&h).await, "ok");

    h.idp.deactivate(ADMIN);

    eventually("the login to be ended", || async {
        !alive(&h, &proxy, &cert).await
    })
    .await;
    let ended = events(&h, EventKind::IdpOffboard).await;
    assert_eq!(ended.len(), 1);
    assert_eq!(ended[0].data["action"], "revoke_login");
    assert_eq!(ended[0].data["deactivated"], true);
    assert!(
        ended[0].data["reason"]
            .as_str()
            .is_some_and(|r| r.contains("invalid_grant"))
    );
    assert_eq!(status(&h).await, "offboarded");
    let kept: i64 = sqlx::query_scalar("SELECT count(*) FROM idp_logins")
        .fetch_one(&h.state.db)
        .await
        .expect("count");
    assert_eq!(kept, 0, "the sealed token is dropped with the login");
}

#[tokio::test]
async fn losing_a_group_ends_the_login_but_does_not_lock() {
    let Some(h) = start(&[]).await else { return };
    let (_, proxy) = h.enroll_proxy().await;
    let refresh = h.idp.issue_refresh_token(ADMIN, &["admins"]);
    let (_, cert) = h
        .login_with_refresh(ADMIN, &["admins"], &refresh)
        .await
        .expect("login");

    h.idp.set_groups(ADMIN, &[]);

    eventually("the login to be ended", || async {
        !alive(&h, &proxy, &cert).await
    })
    .await;
    let ended = events(&h, EventKind::IdpOffboard).await;
    assert_eq!(ended[0].data["deactivated"], false);
    assert!(
        ended[0].data["reason"]
            .as_str()
            .is_some_and(|r| r.contains("limen:admin"))
    );
    assert!(
        !limen_control_plane::db::is_locked(&h.state.db, ADMIN)
            .await
            .expect("lock check"),
        "a person who is still valid is not locked"
    );
}

#[tokio::test]
async fn a_still_valid_person_keeps_their_login_across_checks() {
    let Some(h) = start(&[]).await else { return };
    let (_, proxy) = h.enroll_proxy().await;
    let refresh = h.idp.issue_refresh_token(ADMIN, &["admins"]);
    let (_, cert) = h
        .login_with_refresh(ADMIN, &["admins"], &refresh)
        .await
        .expect("login");
    // Several checks pass; the rotated token keeps working.
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(alive(&h, &proxy, &cert).await);
    assert_eq!(events(&h, EventKind::IdpOffboard).await.len(), 0);
    assert_eq!(events(&h, EventKind::IdpCheckFailed).await.len(), 0);
}

#[tokio::test]
async fn an_idp_that_is_down_fails_open_and_alerts_once() {
    let Some(h) = start(&[]).await else { return };
    let (_, proxy) = h.enroll_proxy().await;
    let refresh = h.idp.issue_refresh_token(ADMIN, &["admins"]);
    let (_, cert) = h
        .login_with_refresh(ADMIN, &["admins"], &refresh)
        .await
        .expect("login");

    h.idp.set_down(true);
    eventually("the failure to show", || async {
        status(&h).await == "check_failed"
    })
    .await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(alive(&h, &proxy, &cert).await, "sessions are kept");
    assert_eq!(
        events(&h, EventKind::IdpCheckFailed).await.len(),
        1,
        "one event per outage, not one per check"
    );

    h.idp.set_down(false);
    eventually("the status to recover", || async {
        status(&h).await == "ok"
    })
    .await;
}

#[tokio::test]
async fn failing_closed_ends_a_login_the_idp_cannot_confirm() {
    let Some(h) = start(&["--idp-check-failure=closed", "--idp-check-grace=2s"]).await else {
        return;
    };
    let (_, proxy) = h.enroll_proxy().await;
    let refresh = h.idp.issue_refresh_token(ADMIN, &["admins"]);
    let (_, cert) = h
        .login_with_refresh(ADMIN, &["admins"], &refresh)
        .await
        .expect("login");

    h.idp.set_down(true);
    eventually("the login to be ended", || async {
        !alive(&h, &proxy, &cert).await
    })
    .await;
    let ended = events(&h, EventKind::IdpOffboard).await;
    assert!(
        ended[0].data["reason"]
            .as_str()
            .is_some_and(|r| r.contains("grace"))
    );
    assert_eq!(ended[0].data["deactivated"], false);
}

#[tokio::test]
async fn a_login_without_a_refresh_token_is_not_checked() {
    let Some(h) = start(&[]).await else { return };
    let (_, proxy) = h.enroll_proxy().await;
    let (_, cert) = h.login(ADMIN, &["admins"]).await.expect("login");
    assert_eq!(status(&h).await, "unchecked");
    let kept: i64 = sqlx::query_scalar("SELECT count(*) FROM idp_logins")
        .fetch_one(&h.state.db)
        .await
        .expect("count");
    assert_eq!(kept, 0);
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(alive(&h, &proxy, &cert).await);
}

#[tokio::test]
async fn the_refresh_token_is_stored_sealed() {
    let Some(h) = start(&[]).await else { return };
    let refresh = h.idp.issue_refresh_token(ADMIN, &["admins"]);
    h.login_with_refresh(ADMIN, &["admins"], &refresh)
        .await
        .expect("login");
    let stored: Vec<u8> = sqlx::query_scalar("SELECT refresh_token FROM idp_logins")
        .fetch_one(&h.state.db)
        .await
        .expect("row");
    assert!(
        !String::from_utf8_lossy(&stored).contains(&refresh),
        "the token is not in the clear"
    );
    assert!(
        !std::fs::read_to_string(&h.audit_file)
            .unwrap_or_default()
            .contains(&refresh),
        "and not in the audit trail"
    );
}

#[derive(clap::Parser)]
struct Wrapper {
    #[command(flatten)]
    c: limen_control_plane::Config,
}

#[test]
fn a_bad_token_key_is_refused() {
    use clap::Parser as _;
    let parse = |key: &str| {
        Wrapper::try_parse_from([
            "t",
            "--database-url=postgres://x",
            "--oidc-issuer=http://i",
            "--oidc-client-id=c",
            &format!("--idp-token-key={key}"),
        ])
        .expect("parse")
        .c
    };
    assert!(parse("c2hvcnQ=").idp_token_key().is_err(), "too short");
    assert!(parse("not base64!").idp_token_key().is_err());
    let good = parse("CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=");
    assert!(matches!(good.idp_token_key(), Ok(Some(k)) if k == [9u8; 32]));
}

async fn scopes(h: &Harness) -> Vec<String> {
    limen_proto::v1::auth_client::AuthClient::new(h.channel(None))
        .get_auth_config(limen_proto::v1::GetAuthConfigRequest {})
        .await
        .expect("auth config")
        .into_inner()
        .scopes
}

#[tokio::test]
async fn offline_access_is_asked_for_only_while_the_check_is_on() {
    let Some(on) = start(&[]).await else { return };
    assert!(scopes(&on).await.contains(&"offline_access".to_owned()));
    let Some(off) = Harness::start().await else {
        return;
    };
    assert!(!scopes(&off).await.contains(&"offline_access".to_owned()));
}
