//! Bot login (ADR-0019) against a real PostgreSQL and a mock issuer that mints
//! GitHub-Actions-shaped tokens. Set `LIMEN_TEST_DATABASE_URL` to run them.
//! Everything here is *unverified against real GitHub or GitLab tokens*.

mod common;

use common::Harness;
use limen_audit::EventKind;
use limen_ca::verify::verify_user;
use limen_testkit::idp::WorkloadToken;
use limen_testkit::users::DEVELOPER;
use tonic::Code;

const ROLES: &str = include_str!("../../../examples/policy/roles.yaml");

fn bots_yaml(issuer: &str) -> String {
    format!(
        "kind: role\nversion: v1\nmetadata: {{ name: deployer }}\nspec:\n  allow:\n    - resources: {{ kind: [ssh], labels: {{ env: [staging] }} }}\n      ssh: {{ logins: [ubuntu] }}\n---\n\
kind: bot\nversion: v1\nmetadata: {{ name: deploy-staging }}\nspec:\n  join:\n    method: github_actions\n    issuer: {issuer}\n    match:\n      repository: acme/infra\n      ref: refs/heads/main\n      environment: staging\n  roles: [deployer]\n  max_ttl: 15m\n---\n\
kind: bot\nversion: v1\nmetadata: {{ name: deploy-twin }}\nspec:\n  join:\n    method: github_actions\n    issuer: {issuer}\n    match:\n      repository: acme/twin\n      ref: refs/heads/main\n  roles: [deployer]\n---\n\
kind: bot\nversion: v1\nmetadata: {{ name: deploy-twin-two }}\nspec:\n  join:\n    method: github_actions\n    issuer: {issuer}\n    match:\n      repository: acme/twin\n      ref: [refs/heads/main, refs/heads/release]\n  roles: [deployer]\n---\n\
kind: bot\nversion: v1\nmetadata: {{ name: nightly }}\nspec:\n  join:\n    method: gitlab\n    issuer: {issuer}\n    match:\n      project_path: acme/reports\n      ref: main\n      ref_protected: \"true\"\n  roles: [deployer]\n"
    )
}

async fn start() -> Option<Harness> {
    let h = Harness::start_with(&["--bot-allow-insecure-issuers".to_owned()]).await?;
    h.set_policy(&[
        ("roles.yaml", ROLES),
        ("bots.yaml", &bots_yaml(&h.idp.issuer)),
    ]);
    Some(h)
}

fn good() -> WorkloadToken {
    WorkloadToken::github("acme/infra", "refs/heads/main", Some("staging"))
}

/// Every refusal is audited as `auth.denied` with the `bot_login` action and
/// the facts of the refused run. Returns the latest reason.
async fn last_denial(h: &Harness) -> serde_json::Value {
    h.audit_events()
        .await
        .into_iter()
        .rev()
        .find(|e| e.kind == EventKind::AuthDenied && e.data["action"] == "bot_login")
        .expect("a denied bot login was audited")
        .data
}

#[tokio::test]
async fn a_matching_token_gets_a_short_lived_bot_certificate() {
    let Some(h) = start().await else { return };
    let token = h.idp.workload_token(&good());
    let (resp, der) = h
        .bot_login("github_actions", token, "")
        .await
        .expect("bot login");

    assert_eq!(resp.username, "bot:deploy-staging");
    assert_eq!(resp.roles, ["deployer"]);
    let id = verify_user(&der, h.state.cas.user.cert_der()).expect("certificate verifies");
    assert!(id.bot);
    assert_eq!(id.ci["repository"], "acme/infra");
    assert_eq!(id.ci["run_id"], "424242");
    assert_eq!(id.ci["provider"], "github_actions");
    assert!(!id.ci.contains_key("jti"), "token internals stay out");
    let ttl = resp.expires_at_unix - time::OffsetDateTime::now_utc().unix_timestamp();
    assert!((840..=900).contains(&ttl), "15 minutes, no more: {ttl}s");

    let events = h.audit_events().await;
    let login = events
        .iter()
        .find(|e| e.kind == EventKind::AuthLogin)
        .expect("auth.login");
    assert_eq!(login.user.as_deref(), Some("bot:deploy-staging"));
    assert_eq!(login.data["actor_type"], "bot");
    assert_eq!(login.data["flow"], "bot");
    assert_eq!(login.data["ci"]["repository"], "acme/infra");
    assert_eq!(
        login.data["ci"]["actor"], "octocat",
        "who triggered the run"
    );

    // The bot is a row in `users`, marked as a bot, with its latest run.
    let (kind, repo): (String, Option<serde_json::Value>) = sqlx::query_as(
        "SELECT actor_type, last_ci FROM users WHERE username = 'bot:deploy-staging'",
    )
    .fetch_one(&h.state.db)
    .await
    .expect("bot row");
    assert_eq!(kind, "bot");
    assert_eq!(repo.expect("ci")["repository"], "acme/infra");
}

#[tokio::test]
async fn a_token_works_once() {
    let Some(h) = start().await else { return };
    let token = h.idp.workload_token(&good());
    h.bot_login("github_actions", token.clone(), "")
        .await
        .expect("first use");
    let err = h
        .bot_login("github_actions", token, "")
        .await
        .expect_err("replay");
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(last_denial(&h).await["reason"], "token already used");
}

/// Log in with a token that must be refused, and check the audited reason.
/// (The unauthenticated rate limit allows bursts of 10, so tests stay below it.)
async fn denied(h: &Harness, label: &str, method: &str, token: String, reason: &str) {
    let err = h.bot_login(method, token, "").await.expect_err("refused");
    assert_eq!(err.code(), Code::PermissionDenied, "{label}");
    assert_eq!(last_denial(h).await["reason"], reason, "{label}");
}

#[tokio::test]
async fn tokens_that_no_bot_matches_are_denied_and_audited_with_the_run() {
    let Some(h) = start().await else { return };
    // Wrong branch, wrong repository, a missing claim, and a fork's pull request ref.
    for (label, token) in [
        (
            "other branch",
            WorkloadToken::github("acme/infra", "refs/heads/feature", Some("staging")),
        ),
        (
            "lookalike repository",
            WorkloadToken::github("acme/infra-evil", "refs/heads/main", Some("staging")),
        ),
        (
            "no environment",
            WorkloadToken::github("acme/infra", "refs/heads/main", None),
        ),
        (
            "fork pull request",
            WorkloadToken::github("acme/infra", "refs/pull/9/merge", Some("staging")),
        ),
    ] {
        denied(
            &h,
            label,
            "github_actions",
            h.idp.workload_token(&token),
            "no bot matches this token",
        )
        .await;
    }
    // The audit entry says which run was refused.
    let data = last_denial(&h).await;
    assert_eq!(data["ci"]["repository"], "acme/infra");
    assert_eq!(data["ci"]["ref"], "refs/pull/9/merge");
    assert_eq!(data["actor_type"], "bot");
}

#[tokio::test]
async fn bad_tokens_and_wrong_methods_are_denied() {
    let Some(h) = start().await else { return };
    let github = |t: WorkloadToken| h.idp.workload_token(&t);
    denied(
        &h,
        "wrong audience",
        "github_actions",
        github(WorkloadToken {
            audience: "someone-else".into(),
            ..good()
        }),
        "invalid token",
    )
    .await;
    denied(
        &h,
        "expired",
        "github_actions",
        github(WorkloadToken {
            ttl_secs: -60,
            ..good()
        }),
        "invalid token",
    )
    .await;
    denied(
        &h,
        "minted too long ago",
        "github_actions",
        github(WorkloadToken {
            issued_secs_ago: 20 * 60,
            ttl_secs: 3600,
            ..good()
        }),
        "invalid token",
    )
    .await;
    denied(
        &h,
        "an issuer no bot names",
        "github_actions",
        github(WorkloadToken {
            issuer: Some("https://evil.example.com".into()),
            ..good()
        }),
        "invalid token",
    )
    .await;
    // A GitHub bot's token presented as a GitLab one finds no GitLab bot for it.
    denied(
        &h,
        "wrong method",
        "gitlab",
        github(good()),
        "no bot matches this token",
    )
    .await;
    // No bot takes oidc tokens at all.
    denied(
        &h,
        "method with no bots",
        "oidc",
        github(good()),
        "no bot accepts this kind of token",
    )
    .await;
    denied(
        &h,
        "not a token",
        "github_actions",
        "nope".into(),
        "invalid token",
    )
    .await;
}

#[tokio::test]
async fn a_token_that_two_bots_would_accept_logs_nobody_in() {
    let Some(h) = start().await else { return };
    let token = h
        .idp
        .workload_token(&WorkloadToken::github("acme/twin", "refs/heads/main", None));
    let err = h
        .bot_login("github_actions", token, "")
        .await
        .expect_err("ambiguous");
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(
        last_denial(&h).await["reason"],
        "more than one bot matches this token"
    );

    // Naming the bot resolves it.
    let token = h
        .idp
        .workload_token(&WorkloadToken::github("acme/twin", "refs/heads/main", None));
    let (resp, _) = h
        .bot_login("github_actions", token, "deploy-twin")
        .await
        .expect("named bot");
    assert_eq!(resp.username, "bot:deploy-twin");
}

#[tokio::test]
async fn a_locked_bot_cannot_log_in() {
    let Some(h) = start().await else { return };
    limen_control_plane::db::lock_user(
        &h.state.db,
        "bot:deploy-staging",
        "suspicious run",
        "admin",
    )
    .await
    .expect("lock");
    let err = h
        .bot_login("github_actions", h.idp.workload_token(&good()), "")
        .await
        .expect_err("locked");
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(last_denial(&h).await["reason"], "bot locked");
}

#[tokio::test]
async fn people_cannot_take_the_bot_prefix() {
    let Some(h) = start().await else { return };
    let err = h
        .login("bot:deploy-staging", &["admins"])
        .await
        .expect_err("reserved username");
    assert_eq!(err.code(), Code::PermissionDenied);
    // A normal person still works.
    h.login(DEVELOPER, &["admins"])
        .await
        .expect("person logs in");
}

#[tokio::test]
async fn plain_http_issuers_are_refused_unless_development_allows_them() {
    // The default configuration: no `--bot-allow-insecure-issuers`.
    let Some(h) = Harness::start().await else {
        return;
    };
    h.set_policy(&[
        ("roles.yaml", ROLES),
        ("bots.yaml", &bots_yaml(&h.idp.issuer)),
    ]);
    let err = h
        .bot_login("github_actions", h.idp.workload_token(&good()), "")
        .await
        .expect_err("http issuer");
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(last_denial(&h).await["reason"], "invalid token");
}

#[tokio::test]
async fn the_cli_can_ask_for_the_audience() {
    let Some(h) = start().await else { return };
    let mut client = limen_proto::v1::auth_client::AuthClient::new(h.channel(None));
    let config = client
        .get_auth_config(limen_proto::v1::GetAuthConfigRequest {})
        .await
        .expect("config")
        .into_inner();
    assert_eq!(config.bot_audience, "limen");
}
