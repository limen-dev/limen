//! IdP-driven offboarding (ADR-0047) against a real PostgreSQL and a mock IdP
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
    eventually("the status to show it", || async {
        status(&h).await == "offboarded"
    })
    .await;
    // Deactivated means locked too, so what a login does not cover ends as well.
    assert!(
        limen_control_plane::db::is_locked(&h.state.db, ADMIN)
            .await
            .expect("lock check")
    );
    let lock = limen_control_plane::db::active_lock(&h.state.db, ADMIN)
        .await
        .expect("lock")
        .expect("locked");
    assert_eq!(lock.locked_by, "system:idp-check");

    // The IdP vouching for them again lifts that lock by itself, audited.
    h.login(ADMIN, &["admins"]).await.expect("signs in again");
    assert!(
        !limen_control_plane::db::is_locked(&h.state.db, ADMIN)
            .await
            .expect("lock check")
    );
    assert_eq!(events(&h, EventKind::UserUnlock).await.len(), 1);
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

    // Still in some group, just not the one that gave the role.
    h.idp.set_groups(ADMIN, &["interns"]);

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
async fn a_token_without_the_groups_claim_is_not_read_as_no_groups() {
    let Some(h) = start(&[]).await else { return };
    let (_, proxy) = h.enroll_proxy().await;
    let refresh = h.idp.issue_refresh_token(ADMIN, &["admins"]);
    let (_, cert) = h
        .login_with_refresh(ADMIN, &["admins"], &refresh)
        .await
        .expect("login");

    // The mock leaves the claim out for an empty list, as an IdP with a
    // group filter does for someone in none of the filtered groups.
    h.idp.set_groups(ADMIN, &[]);

    eventually("the alert to show", || async {
        status(&h).await == "check_failed"
    })
    .await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(alive(&h, &proxy, &cert).await, "the login is kept");
    assert_eq!(events(&h, EventKind::IdpOffboard).await.len(), 0);
    let alerts = events(&h, EventKind::IdpCheckFailed).await;
    assert_eq!(alerts.len(), 1, "one alert, not one per check");
    assert!(
        alerts[0].data["reason"]
            .as_str()
            .is_some_and(|r| r.contains("no groups claim"))
    );

    // Deactivation is still caught.
    h.idp.deactivate(ADMIN);
    eventually("the login to be ended", || async {
        !alive(&h, &proxy, &cert).await
    })
    .await;
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
async fn a_refreshed_id_token_that_fails_keeps_the_rotated_refresh_token() {
    let Some(h) = start(&[]).await else { return };
    let (_, proxy) = h.enroll_proxy().await;
    let refresh = h.idp.issue_refresh_token(ADMIN, &["admins"]);
    let (_, cert) = h
        .login_with_refresh(ADMIN, &["admins"], &refresh)
        .await
        .expect("login");

    // The IdP rotates the token on every refresh, but its ID token does not
    // verify (a signing key the control plane has not seen yet).
    h.idp.set_unverifiable_refreshed_tokens(true);
    eventually("the failure to show", || async {
        status(&h).await == "check_failed"
    })
    .await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    h.idp.set_unverifiable_refreshed_tokens(false);

    // The next check must use the rotated token: the old one is spent, and
    // using it would read as a deactivation.
    eventually("the status to recover", || async {
        status(&h).await == "ok"
    })
    .await;
    assert!(alive(&h, &proxy, &cert).await);
    assert_eq!(events(&h, EventKind::IdpOffboard).await.len(), 0);
    assert!(
        !limen_control_plane::db::is_locked(&h.state.db, ADMIN)
            .await
            .expect("lock check"),
        "nobody is locked for an ID token that would not verify"
    );
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

#[tokio::test]
async fn an_admins_lock_is_never_lifted_by_signing_in() {
    let Some(h) = start(&[]).await else { return };
    h.login(ADMIN, &["admins"]).await.expect("login");
    assert!(
        limen_control_plane::db::lock_user(&h.state.db, ADMIN, "stolen laptop", "root@example.com")
            .await
            .expect("lock")
    );
    let err = h.login(ADMIN, &["admins"]).await.expect_err("still locked");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

const MAPPING: &str = "kind: role\nversion: v1\nmetadata: { name: dev }\nspec:\n  allow:\n    - resources: { kind: [ssh] }\n      ssh: { logins: [ubuntu] }\n---\nkind: role_mapping\nversion: v1\nmetadata: { name: m }\nspec:\n  - { idp_group: developers, roles: [dev] }\n  - { idp_group: extra, roles: [dev] }\n";

#[tokio::test]
async fn a_group_gained_and_lost_after_login_does_not_end_the_login() {
    let Some(h) = start(&[]).await else { return };
    h.set_policy(&[("m.yaml", MAPPING)]);
    let (_, proxy) = h.enroll_proxy().await;
    let refresh = h.idp.issue_refresh_token(ADMIN, &["developers"]);
    let (_, cert) = h
        .login_with_refresh(ADMIN, &["developers"], &refresh)
        .await
        .expect("login");
    // Gains `extra` (same role), the login keeps working; then loses it again.
    h.idp.set_groups(ADMIN, &["developers", "extra"]);
    tokio::time::sleep(Duration::from_secs(3)).await;
    h.idp.set_groups(ADMIN, &["developers"]);
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(alive(&h, &proxy, &cert).await);
    assert_eq!(events(&h, EventKind::IdpOffboard).await.len(), 0);
}

const TWO_ROLES: &str = "kind: role\nversion: v1\nmetadata: { name: dev }\nspec:\n  allow:\n    - resources: { kind: [ssh] }\n      ssh: { logins: [ubuntu] }\n---\nkind: role\nversion: v1\nmetadata: { name: ops }\nspec:\n  allow:\n    - resources: { kind: [postgres] }\n      db: { roles: [limen_read] }\n---\nkind: role_mapping\nversion: v1\nmetadata: { name: m }\nspec:\n  - { idp_group: developers, roles: [dev] }\n  - { idp_group: sre, roles: [ops] }\n";

/// A group gained after sign-in is seen at the next check and shown, but roles
/// stay those of the login: nothing changes until the person signs in again.
#[tokio::test]
async fn a_gained_group_is_shown_but_not_applied_before_the_next_sign_in() {
    let Some(h) = start(&[]).await else { return };
    h.set_policy(&[("m.yaml", TWO_ROLES)]);
    let (_, proxy) = h.enroll_proxy().await;
    let refresh = h.idp.issue_refresh_token(ADMIN, &["developers"]);
    let (_, cert) = h
        .login_with_refresh(ADMIN, &["developers"], &refresh)
        .await
        .expect("login");

    h.idp.set_groups(ADMIN, &["developers", "sre"]);
    eventually("the new group to be seen", || async {
        let seen: Option<Vec<String>> =
            sqlx::query_scalar("SELECT idp_groups FROM users WHERE username = $1")
                .bind(ADMIN)
                .fetch_one(&h.state.db)
                .await
                .expect("row");
        seen.is_some_and(|g| g.iter().any(|x| x == "sre"))
    })
    .await;
    let (roles, groups): (Vec<String>, Vec<String>) =
        sqlx::query_as("SELECT roles, groups FROM users WHERE username = $1")
            .bind(ADMIN)
            .fetch_one(&h.state.db)
            .await
            .expect("row");
    assert_eq!(roles, ["dev"], "roles are those of the sign-in");
    assert_eq!(groups, ["developers"]);
    let seen = vec!["developers".to_owned(), "sre".to_owned()];
    let (gained, lost) =
        limen_control_plane::idp_check::pending_roles(&h.state, &roles, Some(&seen));
    assert_eq!(gained, ["ops"]);
    assert_eq!(lost.len(), 0);
    assert!(alive(&h, &proxy, &cert).await, "the login is not disturbed");

    // At the next sign-in it applies.
    let (resp, _) = h.login(ADMIN, &["developers", "sre"]).await.expect("login");
    assert_eq!(resp.roles, ["dev", "ops"]);
}

/// Onboarding is the IdP's: nobody is created in Limen, and the roles a person
/// gets follow the groups the IdP puts in their ID token.
#[tokio::test]
async fn a_person_inherits_the_roles_of_their_idp_groups_without_any_setup() {
    let Some(h) = start(&[]).await else { return };
    h.set_policy(&[("m.yaml", TWO_ROLES)]);
    let users_before: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&h.state.db)
        .await
        .expect("count");
    assert_eq!(users_before, 0, "nobody exists in Limen beforehand");

    // First sign-in: the group gives the predefined role.
    let (resp, _) = h
        .login("new.hire@example.com", &["developers"])
        .await
        .expect("login");
    assert_eq!(resp.roles, ["dev"]);

    // Added to another group in the IdP: picked up at the next sign-in.
    let (resp, _) = h
        .login("new.hire@example.com", &["developers", "sre"])
        .await
        .expect("login");
    assert_eq!(resp.roles, ["dev", "ops"]);

    // A group no mapping names gives nothing; with no mapped group at all, no
    // sign-in (nothing to inherit).
    let (resp, _) = h
        .login("new.hire@example.com", &["developers", "book-club"])
        .await
        .expect("login");
    assert_eq!(resp.roles, ["dev"]);
    let err = h
        .login("outsider@example.com", &["book-club"])
        .await
        .expect_err("no mapped group");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

// ---- purge and delete (ADR-0047) -------------------------------------------------

async fn person(h: &Harness, name: &str, locked_by: Option<&str>, days: i32) {
    sqlx::query("INSERT INTO users (username, subject) VALUES ($1, $1)")
        .bind(name)
        .execute(&h.state.db)
        .await
        .expect("user");
    sqlx::query("INSERT INTO idp_logins (login_id, username, refresh_token, groups, expires_at, next_check_at) VALUES ($1, $2, '\\x00', '{}', now() + interval '1 day', now() + interval '1 day')")
        .bind(format!("login-{name}"))
        .bind(name)
        .execute(&h.state.db)
        .await
        .expect("stored token");
    if let Some(by) = locked_by {
        limen_control_plane::db::lock_user(&h.state.db, name, "gone", by)
            .await
            .expect("lock");
        sqlx::query("UPDATE user_locks SET locked_at = now() - make_interval(days => $2) WHERE username = $1")
            .bind(name)
            .bind(days)
            .execute(&h.state.db)
            .await
            .expect("backdate");
    }
}

async fn exists(h: &Harness, name: &str) -> bool {
    sqlx::query_scalar("SELECT count(*) > 0 FROM users WHERE username = $1")
        .bind(name)
        .fetch_one(&h.state.db)
        .await
        .expect("exists")
}

#[tokio::test]
async fn people_the_idp_disabled_are_purged_after_the_window_and_only_them() {
    // The window is the default, 90 days. The IdP check runs, but with no
    // logins to check it never touches these.
    let Some(h) = start(&[]).await else { return };
    person(&h, "old.idp@example.com", Some("system:idp-check"), 91).await;
    person(&h, "old.scim@example.com", Some("system:scim"), 91).await;
    person(&h, "recent.idp@example.com", Some("system:idp-check"), 89).await;
    person(&h, "old.admin@example.com", Some("admin@example.com"), 400).await;
    person(&h, "enabled@example.com", None, 0).await;

    assert_eq!(
        limen_control_plane::idp_check::purge_disabled(&h.state).await,
        2
    );
    assert!(!exists(&h, "old.idp@example.com").await);
    assert!(
        !exists(&h, "old.scim@example.com").await,
        "SCIM never sends a delete for a user, so its deactivations are purged too"
    );
    assert!(exists(&h, "recent.idp@example.com").await, "89 days: kept");
    assert!(
        exists(&h, "old.admin@example.com").await,
        "an admin's lock never purges"
    );
    assert!(
        exists(&h, "enabled@example.com").await,
        "enabled people are never purged"
    );

    // Its stored token went too; the IdP lock is released (the IdP decides if they return).
    let tokens: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM idp_logins WHERE username = 'old.idp@example.com'",
    )
    .fetch_one(&h.state.db)
    .await
    .expect("count");
    assert_eq!(tokens, 0);
    assert!(
        !limen_control_plane::db::is_locked(&h.state.db, "old.idp@example.com")
            .await
            .expect("lock check")
    );
    let deletes = events(&h, EventKind::UserDelete).await;
    assert_eq!(deletes.len(), 2, "each deletion is audited");
    let one = deletes
        .iter()
        .find(|e| e.data["target_user"] == "old.idp@example.com")
        .expect("the IdP check's deletion");
    assert_eq!(one.data["disabled_by"], "system:idp-check");
    let deletes = [one.clone()];
    assert_eq!(deletes[0].data["via"], "idp");
}

#[tokio::test]
async fn the_purge_can_be_turned_off() {
    let Some(h) = start(&["--idp-purge-after=0s"]).await else {
        return;
    };
    person(&h, "old.idp@example.com", Some("system:idp-check"), 1000).await;
    assert_eq!(
        limen_control_plane::idp_check::purge_disabled(&h.state).await,
        0
    );
    assert!(exists(&h, "old.idp@example.com").await);
}

#[tokio::test]
async fn only_a_disabled_person_can_be_deleted_by_hand() {
    use limen_control_plane::services::ops::{self, Actor, DeleteRefused};
    let Some(h) = start(&[]).await else { return };
    person(&h, "live@example.com", None, 0).await;
    person(&h, "by.admin@example.com", Some("admin@example.com"), 1).await;
    person(&h, "by.idp@example.com", Some("system:idp-check"), 1).await;
    let me = Actor {
        username: ADMIN,
        via: "console",
    };

    let r = ops::delete_disabled_user(&h.state, me, "live@example.com", "tidy")
        .await
        .expect("ok");
    assert_eq!(r, Err(DeleteRefused::NotDisabled));
    assert!(
        exists(&h, "live@example.com").await,
        "an enabled person is untouched"
    );
    let r = ops::delete_disabled_user(&h.state, me, "bot:deploy", "tidy")
        .await
        .expect("ok");
    assert_eq!(r, Err(DeleteRefused::Bot));
    let e = ops::delete_disabled_user(&h.state, me, "by.idp@example.com", "")
        .await
        .expect_err("a reason is required");
    assert_eq!(e.code(), tonic::Code::InvalidArgument);

    // An admin's lock survives the deletion, so a return sign-in is still refused.
    let r = ops::delete_disabled_user(&h.state, me, "by.admin@example.com", "left the company")
        .await
        .expect("ok");
    assert_eq!(r, Ok(()));
    assert!(!exists(&h, "by.admin@example.com").await);
    assert!(
        limen_control_plane::db::is_locked(&h.state.db, "by.admin@example.com")
            .await
            .expect("lock check"),
        "the admin's decision stands"
    );
    // The IdP's lock does not: the IdP decides if they come back.
    let r = ops::delete_disabled_user(&h.state, me, "by.idp@example.com", "left the company")
        .await
        .expect("ok");
    assert_eq!(r, Ok(()));
    assert!(
        !limen_control_plane::db::is_locked(&h.state.db, "by.idp@example.com")
            .await
            .expect("lock check")
    );
    // Deleting twice finds nothing disabled.
    let r = ops::delete_disabled_user(&h.state, me, "by.idp@example.com", "again")
        .await
        .expect("ok");
    assert_eq!(r, Err(DeleteRefused::NotDisabled));

    let deletes = events(&h, EventKind::UserDelete).await;
    assert_eq!(deletes.len(), 2);
    assert!(
        deletes
            .iter()
            .all(|e| e.data["reason"] == "left the company")
    );
}
