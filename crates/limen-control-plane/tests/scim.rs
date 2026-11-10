//! SCIM 2.0 provisioning (ADR-0048) against a real PostgreSQL and a mock IdP.
//! Set `LIMEN_TEST_DATABASE_URL` to run them. Requests are shaped like the ones
//! Okta's provisioning agent sends; **unverified against a real Okta (#64)**.

mod common;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::Harness;
use limen_audit::EventKind;
use limen_proto::v1::ListResourcesRequest;
use limen_proto::v1::resources_client::ResourcesClient;
use serde_json::{Value, json};
use tower::ServiceExt as _;

/// Built at run time so no token literal sits in the source.
fn token() -> String {
    "scim-test-token-".to_owned() + &"x".repeat(24)
}

async fn start(with_token: bool) -> Option<Harness> {
    use base64::Engine as _;
    let mut flags = Vec::new();
    if with_token {
        flags.push(format!("--scim-token={}", token()));
    }
    flags.push(format!(
        "--idp-token-key={}",
        base64::engine::general_purpose::STANDARD.encode([9u8; 32])
    ));
    flags.push("--idp-check-interval=1s".to_owned());
    Harness::start_with(&flags).await
}

async fn call(
    h: &Harness,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(t) = bearer {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let body = match body {
        Some(b) => {
            req = req.header("content-type", "application/scim+json");
            Body::from(b.to_string())
        }
        None => Body::empty(),
    };
    let response = limen_control_plane::scim::router(h.state.clone())
        .oneshot(req.body(body).expect("request"))
        .await
        .expect("response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn scim(h: &Harness, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
    call(h, method, path, Some(&token()), body).await
}

async fn create_user(h: &Harness, name: &str) -> String {
    let (status, user) = scim(
        h,
        "POST",
        "/scim/v2/Users",
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": name, "active": true,
            "name": { "givenName": "A", "familyName": "B" },
            "emails": [{ "primary": true, "value": name, "type": "work" }],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{user}");
    user["id"].as_str().expect("an id").to_owned()
}

/// The groups the console compares with a person's roles.
async fn effective(h: &Harness, name: &str) -> Option<Vec<String>> {
    limen_control_plane::console::store::user(&h.state.db, name)
        .await
        .expect("query")
        .expect("a user")
        .idp_groups
}

async fn events(h: &Harness, kind: EventKind) -> Vec<limen_audit::Event> {
    h.audit_events()
        .await
        .into_iter()
        .filter(|e| e.kind == kind)
        .collect()
}

#[tokio::test]
async fn the_endpoint_needs_a_token_and_is_off_without_one() {
    let Some(h) = start(false).await else { return };
    let (status, _) = call(&h, "GET", "/scim/v2/Users", Some(&token()), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "no token configured: off");
    drop(h);

    let Some(h) = start(true).await else { return };
    let (status, body) = call(&h, "GET", "/scim/v2/Users", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["status"], "401");
    let (status, _) = call(&h, "GET", "/scim/v2/Users", Some("not-the-token"), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, body) = scim(&h, "GET", "/scim/v2/Users", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["totalResults"], 0);
}

#[tokio::test]
async fn a_person_is_provisioned_before_they_ever_sign_in() {
    let Some(h) = start(true).await else { return };
    let id = create_user(&h, "new.hire@example.com").await;

    let (source, count, subject): (String, i64, Option<String>) = sqlx::query_as(
        "SELECT source, login_count, subject FROM users WHERE username = 'new.hire@example.com'",
    )
    .fetch_one(&h.state.db)
    .await
    .expect("row");
    assert_eq!(source, "scim");
    assert_eq!(count, 0, "provisioning is not a sign-in");
    assert_eq!(subject, None);
    let made = events(&h, EventKind::UserProvision).await;
    assert_eq!(made.len(), 1);
    assert_eq!(made[0].data["target_user"], "new.hire@example.com");

    // The same person again is a conflict; Okta then looks them up by name.
    let (status, _) = scim(
        &h,
        "POST",
        "/scim/v2/Users",
        Some(json!({ "userName": "New.Hire@example.com" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, found) = scim(
        &h,
        "GET",
        "/scim/v2/Users?filter=userName%20eq%20%22New.Hire%40example.com%22&startIndex=1&count=100",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(found["totalResults"], 1);
    assert_eq!(found["Resources"][0]["id"], id);
    assert_eq!(found["Resources"][0]["active"], true);
    let (status, found) = scim(
        &h,
        "GET",
        "/scim/v2/Users?filter=userName%20eq%20%22nobody%40example.com%22",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(found["totalResults"], 0);
    assert_eq!(found["Resources"], json!([]));

    // Their first sign-in fills the record in and it stays one person.
    h.login("new.hire@example.com", &["admins"])
        .await
        .expect("signs in");
    let (source, count, subject): (String, i64, Option<String>) = sqlx::query_as(
        "SELECT source, login_count, subject FROM users WHERE username = 'new.hire@example.com'",
    )
    .fetch_one(&h.state.db)
    .await
    .expect("row");
    assert_eq!((source.as_str(), count), ("scim", 1));
    assert!(subject.is_some());
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&h.state.db)
        .await
        .expect("count");
    assert_eq!(total, 1);
}

#[tokio::test]
async fn a_deactivation_is_instant_and_only_scim_lifts_it() {
    let Some(h) = start(true).await else { return };
    let id = create_user(&h, "leaver@example.com").await;
    let path = format!("/scim/v2/Users/{id}");

    // Okta's deactivation: a pathless replace.
    let (status, user) = scim(
        &h,
        "PATCH",
        &path,
        Some(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{ "op": "replace", "value": { "active": false } }],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(user["active"], false);
    let lock = limen_control_plane::db::active_lock(&h.state.db, "leaver@example.com")
        .await
        .expect("lock")
        .expect("locked");
    assert_eq!(lock.locked_by, "system:scim");

    // Signing in does not lift a SCIM lock: only the IdP's SCIM does.
    let err = h
        .login("leaver@example.com", &["admins"])
        .await
        .expect_err("refused");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    let (_, user) = scim(
        &h,
        "PATCH",
        &path,
        Some(json!({ "Operations": [{ "op": "replace", "path": "active", "value": true }] })),
    )
    .await;
    assert_eq!(user["active"], true);
    h.login("leaver@example.com", &["admins"])
        .await
        .expect("signs in again");

    // An admin's lock is not SCIM's to lift.
    limen_control_plane::db::lock_user(
        &h.state.db,
        "leaver@example.com",
        "under investigation",
        "an-admin@example.com",
    )
    .await
    .expect("lock");
    let (_, user) = scim(
        &h,
        "PUT",
        &path,
        Some(json!({ "userName": "leaver@example.com", "active": true })),
    )
    .await;
    assert_eq!(user["active"], false, "the admin's lock stays");
}

#[tokio::test]
async fn a_name_change_and_an_unknown_person_are_refused() {
    let Some(h) = start(true).await else { return };
    let id = create_user(&h, "stay@example.com").await;
    let (status, _) = scim(
        &h,
        "PUT",
        &format!("/scim/v2/Users/{id}"),
        Some(json!({ "userName": "other@example.com", "active": true })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = scim(
        &h,
        "GET",
        "/scim/v2/Users/00000000-0000-0000-0000-000000000000",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = scim(&h, "GET", "/scim/v2/Users/not-an-id", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = scim(
        &h,
        "POST",
        "/scim/v2/Users",
        Some(json!({ "userName": "bot:ci" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_delete_removes_the_record_and_audits_it() {
    let Some(h) = start(true).await else { return };
    let id = create_user(&h, "gone@example.com").await;
    let (status, _) = scim(&h, "DELETE", &format!("/scim/v2/Users/{id}"), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&h.state.db)
        .await
        .expect("count");
    assert_eq!(left, 0);
    assert_eq!(events(&h, EventKind::UserDelete).await.len(), 1);
    assert!(
        !limen_control_plane::db::is_locked(&h.state.db, "gone@example.com")
            .await
            .expect("lock check"),
        "SCIM's own lock goes with the record"
    );
}

const MAPPING: &str = "kind: role\nversion: v1\nmetadata: { name: dev }\nspec:\n  allow:\n    - resources: { kind: [ssh] }\n      ssh: { logins: [ubuntu] }\n---\nkind: role_mapping\nversion: v1\nmetadata: { name: m }\nspec:\n  - { idp_group: limen-engineering, roles: [dev] }\n";

#[tokio::test]
async fn pushed_groups_show_pending_access_and_removal_ends_the_login() {
    let Some(h) = start(true).await else { return };
    h.set_policy(&[("m.yaml", MAPPING)]);
    let id = create_user(&h, "eng@example.com").await;

    let (status, group) = scim(
        &h,
        "POST",
        "/scim/v2/Groups",
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "limen-engineering",
            "members": [{ "value": id, "display": "eng@example.com" }],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{group}");
    let gid = group["id"].as_str().expect("id").to_owned();
    assert_eq!(group["members"][0]["value"], id);

    let (status, again) = scim(
        &h,
        "POST",
        "/scim/v2/Groups",
        Some(json!({ "displayName": "Limen-Engineering" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{again}");

    // Before any sign-in: the groups are known, and the console can show the
    // access they will give.
    let groups = effective(&h, "eng@example.com").await;
    assert_eq!(groups, Some(vec!["limen-engineering".to_owned()]));
    let (gained, lost) =
        limen_control_plane::idp_check::pending_roles(&h.state, &[], groups.as_deref());
    assert_eq!(gained, ["dev"]);
    assert_eq!(lost.len(), 0);

    // They sign in, with a refresh token, and have the role.
    let (_, proxy) = h.enroll_proxy().await;
    let refresh = h
        .idp
        .issue_refresh_token("eng@example.com", &["limen-engineering"]);
    let (resp, cert) = h
        .login_with_refresh("eng@example.com", &["limen-engineering"], &refresh)
        .await
        .expect("login");
    assert_eq!(resp.roles, ["dev"]);
    let alive = || async {
        ResourcesClient::new(h.channel(Some(proxy.clone())))
            .list_resources(common::forwarded(
                ListResourcesRequest::default(),
                Some(&cert),
            ))
            .await
            .is_ok()
    };
    assert!(alive().await);

    // Okta removes them from the group: the login ends at once, no lock.
    let (status, _) = scim(
        &h,
        "PATCH",
        &format!("/scim/v2/Groups/{gid}"),
        Some(json!({ "Operations": [{
            "op": "remove",
            "path": format!("members[value eq \"{id}\"]"),
        }] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let mut ended = false;
    for _ in 0..40 {
        if !alive().await {
            ended = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(ended, "the login that relied on the group ended");
    assert!(
        !limen_control_plane::db::is_locked(&h.state.db, "eng@example.com")
            .await
            .expect("lock check")
    );
    assert_eq!(events(&h, EventKind::UserGroupsChange).await.len(), 2);

    // Add them back (Okta's add form) and delete the group.
    let (status, group) = scim(
        &h,
        "PATCH",
        &format!("/scim/v2/Groups/{gid}"),
        Some(json!({ "Operations": [{
            "op": "add", "path": "members",
            "value": [{ "value": id, "display": "eng@example.com" }],
        }] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(group["members"].as_array().map(Vec::len), Some(1));
    let (status, _) = scim(&h, "DELETE", &format!("/scim/v2/Groups/{gid}"), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, remaining) = scim(&h, "GET", "/scim/v2/Groups", None).await;
    assert_eq!(remaining["totalResults"], 0);
    // Unlinking a pushed group does not remove anyone from it in the IdP: SCIM
    // stops speaking for it, and the groups of their last token are theirs again.
    assert_eq!(
        effective(&h, "eng@example.com").await,
        Some(vec!["limen-engineering".to_owned()])
    );
}

#[tokio::test]
async fn a_member_that_is_not_a_user_is_refused() {
    let Some(h) = start(true).await else { return };
    let (status, _) = scim(
        &h,
        "POST",
        "/scim/v2/Groups",
        Some(json!({
            "displayName": "g",
            "members": [{ "value": "00000000-0000-0000-0000-000000000001" }],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let none: i64 = sqlx::query_scalar("SELECT count(*) FROM scim_groups")
        .fetch_one(&h.state.db)
        .await
        .expect("count");
    assert_eq!(none, 0, "nothing was half-made");
}

const TWO_MAPPED: &str = "kind: role\nversion: v1\nmetadata: { name: dev }\nspec:\n  allow:\n    - resources: { kind: [ssh] }\n      ssh: { logins: [ubuntu] }\n---\nkind: role\nversion: v1\nmetadata: { name: ops }\nspec:\n  allow:\n    - resources: { kind: [postgres] }\n      db: { roles: [limen_read] }\n---\nkind: role_mapping\nversion: v1\nmetadata: { name: m }\nspec:\n  - { idp_group: limen-engineering, roles: [dev] }\n  - { idp_group: limen-sre, roles: [ops] }\n";

/// SCIM pushes some of a person's groups, not all. A group it never pushes
/// still counts for them, and being added to a pushed group takes nothing away.
#[tokio::test]
async fn a_group_scim_never_pushes_still_counts_for_the_person() {
    let Some(h) = start(true).await else { return };
    h.set_policy(&[("m.yaml", TWO_MAPPED)]);
    let (_, proxy) = h.enroll_proxy().await;
    let who = "both@example.com";
    let id = create_user(&h, who).await;
    let refresh = h
        .idp
        .issue_refresh_token(who, &["limen-engineering", "limen-sre"]);
    let (resp, cert) = h
        .login_with_refresh(who, &["limen-engineering", "limen-sre"], &refresh)
        .await
        .expect("login");
    assert_eq!(resp.roles, ["dev", "ops"]);
    let alive = || async {
        ResourcesClient::new(h.channel(Some(proxy.clone())))
            .list_resources(common::forwarded(
                ListResourcesRequest::default(),
                Some(&cert),
            ))
            .await
            .is_ok()
    };

    // Only `limen-engineering` is pushed, and they are added to it.
    let (status, group) = scim(
        &h,
        "POST",
        "/scim/v2/Groups",
        Some(json!({ "displayName": "limen-engineering", "members": [{ "value": id }] })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{group}");
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(alive().await, "being added to a group ends nothing");

    // Both groups still count: nothing pending is lost.
    let groups = effective(&h, who).await.expect("groups");
    assert_eq!(groups, ["limen-engineering", "limen-sre"]);
    let (gained, lost) = limen_control_plane::idp_check::pending_roles(
        &h.state,
        &["dev".to_owned(), "ops".to_owned()],
        Some(&groups),
    );
    assert_eq!(gained.len() + lost.len(), 0);

    // Removed from the pushed group: only what it gave goes.
    let gid = group["id"].as_str().expect("id");
    scim(
        &h,
        "PATCH",
        &format!("/scim/v2/Groups/{gid}"),
        Some(json!({ "Operations": [{ "op": "remove", "path": "members", "value": [{ "value": id }] }] })),
    )
    .await;
    let groups = effective(&h, who).await.expect("groups");
    assert_eq!(groups, ["limen-sre"]);
}

/// Two changes to one group at once both land.
#[tokio::test]
async fn concurrent_group_changes_are_not_lost() {
    let Some(h) = start(true).await else { return };
    let (_, group) = scim(
        &h,
        "POST",
        "/scim/v2/Groups",
        Some(json!({ "displayName": "limen-engineering" })),
    )
    .await;
    let gid = group["id"].as_str().expect("id").to_owned();
    let mut people = Vec::new();
    for i in 0..6 {
        people.push(create_user(&h, &format!("p{i}@example.com")).await);
    }
    let path = format!("/scim/v2/Groups/{gid}");
    let adds = people.iter().map(|id| {
        scim(
            &h,
            "PATCH",
            &path,
            Some(json!({ "Operations": [{ "op": "add", "path": "members",
                                           "value": [{ "value": id }] }] })),
        )
    });
    for (status, _) in futures::future::join_all(adds).await {
        assert_eq!(status, StatusCode::OK);
    }
    let (_, group) = scim(&h, "GET", &path, None).await;
    assert_eq!(group["members"].as_array().map(Vec::len), Some(6));
}
