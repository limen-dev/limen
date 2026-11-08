//! Offboarding (ADR-0046) against a real Dex, not the mock IdP: the refresh
//! grant, token rotation, `invalid_grant`, and groups in tokens as Dex sends
//! them. Set `LIMEN_TEST_DEX_REFRESH_URL` and `LIMEN_TEST_DATABASE_URL`:
//!
//! ```sh
//! docker compose --project-directory deploy/compose -f deploy/compose/stacks/dex-refresh.yml up -d --force-recreate
//! LIMEN_TEST_DEX_REFRESH_URL=http://localhost:5558 LIMEN_TEST_DATABASE_URL=... \
//!   cargo test -p limen-control-plane --test dex_offboarding
//! ```
//!
//! Dex's `mockCallback` connector signs in `kilgore@kilgore.trout`, group
//! `authors`. (Dex's built-in password users cannot be used: a refresh grant for
//! them never returns in Dex v2.46.0.) Not verified against Okta (#64).

mod common;

use std::time::Duration;

use base64::Engine as _;
use common::{Harness, csr, forwarded, new_key};
use limen_audit::EventKind;
use limen_proto::v1::ListResourcesRequest;
use limen_proto::v1::resources_client::ResourcesClient;
use limen_tunnel::tls::Identity;
use rcgen::PublicKeyData;
use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256};

/// Dex keeps one offline session per person and refuses concurrent updates of
/// it, so these tests (one person, one Dex) run one at a time.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const PERSON: &str = "kilgore@kilgore.trout";

const POLICY: &str = "kind: role\nversion: v1\nmetadata: { name: writers }\nspec:\n  allow:\n    - resources: { kind: [ssh] }\n      ssh: { logins: [ubuntu] }\n---\nkind: role_mapping\nversion: v1\nmetadata: { name: m }\nspec:\n  - { idp_group: authors, roles: [writers] }\n";

struct Tokens {
    id_token: String,
    refresh_token: String,
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Sign in at Dex the way the CLI does (authorization code, PKCE, loopback
/// redirect) with the browser's part played by following redirects.
async fn dex_login(dex: &str, nonce: &str) -> Tokens {
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");
    let verifier = b64(&rand::random::<[u8; 32]>());
    let challenge = b64(&Sha256::digest(verifier.as_bytes()));
    let redirect = "http://127.0.0.1:9/callback";
    let mut url = reqwest::Url::parse(&format!("{dex}/dex/auth")).expect("url");
    url.query_pairs_mut()
        .append_pair("client_id", "limen-cli")
        .append_pair("redirect_uri", redirect)
        .append_pair("response_type", "code")
        .append_pair("scope", "openid email groups offline_access")
        .append_pair("state", "s")
        .append_pair("nonce", nonce)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    let mut code = None;
    for _ in 0..8 {
        let resp = http.get(url.clone()).send().await.expect("dex auth");
        let location = resp
            .headers()
            .get("location")
            .and_then(|l| l.to_str().ok())
            .unwrap_or_else(|| panic!("dex answered {} without a redirect", resp.status()))
            .to_owned();
        let next = url.join(&location).expect("location");
        if location.starts_with(redirect) {
            code = next
                .query_pairs()
                .find(|(k, _)| k == "code")
                .map(|(_, v)| v.into_owned());
            break;
        }
        url = next;
    }
    let code = code.expect("an authorization code");
    let body: serde_json::Value = http
        .post(format!("{dex}/dex/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect),
            ("client_id", "limen-cli"),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await
        .expect("token")
        .json()
        .await
        .expect("token json");
    Tokens {
        id_token: body["id_token"].as_str().expect("id_token").to_owned(),
        refresh_token: body["refresh_token"]
            .as_str()
            .expect("a refresh token (offline_access)")
            .to_owned(),
    }
}

/// Redeem a refresh token at Dex, as the control plane's check does.
async fn dex_refresh(dex: &str, refresh_token: &str) -> (u16, serde_json::Value) {
    let resp = reqwest::Client::new()
        .post(format!("{dex}/dex/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", "limen-cli"),
            ("refresh_token", refresh_token),
        ])
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .expect("refresh");
    (
        resp.status().as_u16(),
        resp.json().await.unwrap_or_default(),
    )
}

async fn start(dex: &str, interval: &str) -> Option<Harness> {
    use base64::engine::general_purpose::STANDARD;
    let flags = [
        format!("--oidc-issuer={dex}/dex"),
        format!("--idp-token-key={}", STANDARD.encode([9u8; 32])),
        format!("--idp-check-interval={interval}"),
        "--bootstrap-admin-group=nobody".to_owned(),
    ];
    let h = Harness::start_with(&flags).await?;
    h.set_policy(&[("policy.yaml", POLICY)]);
    Some(h)
}

/// Sign in to Limen with a fresh Dex login.
async fn limen_login(
    h: &Harness,
    dex: &str,
    refresh_override: Option<&str>,
) -> (
    limen_proto::v1::LoginResponse,
    CertificateDer<'static>,
    Tokens,
) {
    let key = new_key();
    let salt = [3u8; 32];
    let nonce =
        limen_control_plane::services::auth::expected_nonce(&key.subject_public_key_info(), &salt);
    let tokens = dex_login(dex, &nonce).await;
    let resp = h
        .login_raw_with_refresh(
            tokens.id_token.clone(),
            csr(&key),
            salt.to_vec(),
            limen_proto::v1::LoginFlow::Pkce,
            refresh_override.unwrap_or(&tokens.refresh_token),
        )
        .await
        .expect("limen login with a Dex ID token");
    let der = limen_tunnel::tls::certs_from_pem(&resp.cert_pem)
        .expect("cert")
        .remove(0);
    (resp, der, tokens)
}

async fn alive(h: &Harness, proxy: &Identity, cert: &CertificateDer<'static>) -> bool {
    ResourcesClient::new(h.channel(Some(proxy.clone())))
        .list_resources(forwarded(ListResourcesRequest::default(), Some(cert)))
        .await
        .is_ok()
}

async fn eventually<F, Fut>(what: &str, f: F)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..120 {
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

async fn stored_token(h: &Harness) -> Vec<u8> {
    sqlx::query_scalar("SELECT refresh_token FROM idp_logins")
        .fetch_one(&h.state.db)
        .await
        .expect("a tracked login")
}

#[tokio::test]
async fn groups_from_dex_become_roles_and_the_login_survives_real_rotation() {
    let Some(dex) = limen_testkit::dex_refresh_url() else {
        return;
    };
    let _one = ONE_AT_A_TIME.lock().await;
    let Some(h) = start(&dex, "1s").await else {
        return;
    };
    let (_, proxy) = h.enroll_proxy().await;
    let (resp, cert, _) = limen_login(&h, &dex, None).await;

    // Onboarding: the person was never created in Limen; their IdP group gave
    // them the mapped role.
    assert_eq!(resp.username, PERSON);
    assert_eq!(resp.roles, ["writers"]);

    // Offboarding checks run against Dex, which rotates the token each time.
    let first = stored_token(&h).await;
    eventually("Dex to rotate the stored token", || async {
        stored_token(&h).await != first
    })
    .await;
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(alive(&h, &proxy, &cert).await, "still signed in");
    assert_eq!(events(&h, EventKind::IdpOffboard).await.len(), 0);
    assert_eq!(events(&h, EventKind::IdpCheckFailed).await.len(), 0);
    let status: String = sqlx::query_scalar("SELECT idp_status FROM users WHERE username = $1")
        .bind(PERSON)
        .fetch_one(&h.state.db)
        .await
        .expect("user");
    assert_eq!(status, "ok");
}

#[tokio::test]
async fn a_token_dex_refuses_ends_the_login_and_locks_until_the_next_sign_in() {
    let Some(dex) = limen_testkit::dex_refresh_url() else {
        return;
    };
    let _one = ONE_AT_A_TIME.lock().await;
    let Some(h) = start(&dex, "8s").await else {
        return;
    };
    let (_, proxy) = h.enroll_proxy().await;
    let (_, cert, tokens) = limen_login(&h, &dex, None).await;
    assert!(alive(&h, &proxy, &cert).await);

    // Spend the token at Dex ourselves, and let Dex's reuse window pass: the
    // control plane then presents a token Dex has already rotated, which Dex
    // answers as it does for a session it has ended.
    let (status, _) = dex_refresh(&dex, &tokens.refresh_token).await;
    assert_eq!(status, 200, "the first redemption works");
    // Past Dex's reuse window (3 seconds by default).
    tokio::time::sleep(Duration::from_secs(4)).await;
    let (status, body) = dex_refresh(&dex, &tokens.refresh_token).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_grant", "{body}");

    eventually("the login to be ended", || async {
        !alive(&h, &proxy, &cert).await
    })
    .await;
    let ended = events(&h, EventKind::IdpOffboard).await;
    assert_eq!(ended[0].data["deactivated"], true);
    assert!(
        ended[0].data["reason"]
            .as_str()
            .is_some_and(|r| r.contains("invalid_grant")),
        "{:?}",
        ended[0].data
    );
    assert!(
        limen_control_plane::db::is_locked(&h.state.db, PERSON)
            .await
            .expect("lock")
    );

    // Signing in at Dex again is the IdP vouching for them: the lock lifts.
    limen_login(&h, &dex, None).await;
    assert!(
        !limen_control_plane::db::is_locked(&h.state.db, PERSON)
            .await
            .expect("lock")
    );
}

#[tokio::test]
async fn a_refresh_token_dex_never_issued_is_refused_like_a_revoked_session() {
    let Some(dex) = limen_testkit::dex_refresh_url() else {
        return;
    };
    let _one = ONE_AT_A_TIME.lock().await;
    let Some(h) = start(&dex, "1s").await else {
        return;
    };
    let (_, proxy) = h.enroll_proxy().await;
    let (_, cert, _) = limen_login(&h, &dex, Some("not-a-token-dex-issued")).await;
    eventually("the login to be ended", || async {
        !alive(&h, &proxy, &cert).await
    })
    .await;
    let ended = events(&h, EventKind::IdpOffboard).await;
    assert!(
        ended[0].data["reason"]
            .as_str()
            .is_some_and(|r| r.contains("invalid_grant")),
        "{:?}",
        ended[0].data
    );
}

#[tokio::test]
async fn a_login_without_a_refresh_token_works_against_dex_and_is_not_checked() {
    let Some(dex) = limen_testkit::dex_refresh_url() else {
        return;
    };
    let _one = ONE_AT_A_TIME.lock().await;
    let Some(h) = start(&dex, "1s").await else {
        return;
    };
    let (_, proxy) = h.enroll_proxy().await;
    let (_, cert, _) = limen_login(&h, &dex, Some("")).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(alive(&h, &proxy, &cert).await);
    let tracked: i64 = sqlx::query_scalar("SELECT count(*) FROM idp_logins")
        .fetch_one(&h.state.db)
        .await
        .expect("count");
    assert_eq!(tracked, 0);
}
