//! Bot login (ADR-0019): a CI job exchanges the workload identity token its
//! platform minted for short-lived credentials, with no secret stored anywhere.

use std::collections::BTreeMap;
use std::net::IpAddr;

use limen_audit::{Context, EventKind};
use limen_ca::UserCertRequest;
use limen_policy::bot::{BotDoc, JoinMethod};
use limen_proto::v1::{BotLoginRequest, LoginResponse};
use serde_json::json;
use tonic::Status;
use uuid::Uuid;

use crate::bots::BotTokenError;
use crate::state::{AppState, internal, unix};

/// Claim names that are never copied into the facts of a run: they are the
/// token's own plumbing, or names Limen sets itself.
const RESERVED: [&str; 10] = [
    "provider", "iss", "sub", "aud", "exp", "iat", "nbf", "jti", "nonce", "at_hash",
];

/// The claims worth recording about the run behind a login, by provider.
/// Everything else in the token stays out of the certificate and the audit
/// trail. For a generic provider, which has no known claim names, the facts are
/// the claims the matched rule relied on (`rule_claims`): nothing else is
/// recorded, and nothing a token claims can replace what Limen sets itself.
fn ci_facts(
    method: JoinMethod,
    claims: &BTreeMap<String, String>,
    rule_claims: &[&str],
) -> BTreeMap<String, String> {
    let wanted: &[&str] = match method {
        JoinMethod::GithubActions => &[
            "repository",
            "repository_owner",
            "workflow",
            "job_workflow_ref",
            "run_id",
            "run_attempt",
            "sha",
            "ref",
            "ref_type",
            "event_name",
            "actor",
            "environment",
            "runner_environment",
        ],
        JoinMethod::Gitlab => &[
            "project_path",
            "namespace_path",
            "pipeline_id",
            "pipeline_source",
            "job_id",
            "sha",
            "ref",
            "ref_type",
            "ref_protected",
            "user_login",
            "environment",
        ],
        JoinMethod::Oidc => &[],
    };
    // A rule can name many claims; the certificate carries a fixed few.
    let from_rule = rule_claims.iter().take(limen_ca::MAX_CI_FACTS - 4);
    let mut facts: BTreeMap<String, String> = wanted
        .iter()
        .chain(from_rule)
        .filter(|k| !RESERVED.contains(*k))
        .filter_map(|k| claims.get(*k).map(|v| ((*k).to_owned(), clip(v))))
        .filter(|(_, v)| !v.is_empty())
        .collect();
    // Set last, so nothing above can have replaced them.
    facts.insert("provider".into(), method.as_str().to_owned());
    for key in ["iss", "sub"] {
        if let Some(v) = claims.get(key).map(|v| clip(v)).filter(|v| !v.is_empty()) {
            facts.insert(key.to_owned(), v);
        }
    }
    facts
}

/// Without control characters, and no longer than a certificate carries
/// (in bytes, cut on a character boundary).
fn clip(v: &str) -> String {
    let mut out = String::new();
    for c in v.chars().filter(|c| !c.is_control()) {
        if out.len() + c.len_utf8() > limen_ca::MAX_CI_VALUE {
            break;
        }
        out.push(c);
    }
    out
}

/// Audit a denied bot login and build the error to return. `facts` says which
/// run was refused, so an investigation can tell.
async fn deny(
    state: &AppState,
    addr: Option<IpAddr>,
    method: &str,
    facts: Option<&BTreeMap<String, String>>,
    reason: &'static str,
) -> Status {
    metrics::counter!("limen_logins_total", "outcome" => "denied", "actor" => "bot").increment(1);
    tracing::warn!(method, client_addr = ?addr, reason, "bot login denied");
    let data = json!({
        "action": "bot_login",
        "actor_type": "bot",
        "method": method,
        "reason": reason,
        "ci": facts,
        "client_addr": addr.map(|a| a.to_string()),
    });
    if let Err(e) = state
        .audit
        .emit(EventKind::AuthDenied, Context::default(), data)
        .await
    {
        tracing::error!(error = %e, "failed to audit a denied bot login");
    }
    Status::permission_denied(format!("login denied: {reason}"))
}

/// A free function over owned values for the same reason as `auth::login`.
pub async fn bot_login(
    state: AppState,
    addr: Option<IpAddr>,
    req: BotLoginRequest,
) -> Result<LoginResponse, Status> {
    let Some(method) = JoinMethod::parse(&req.method) else {
        return Err(Status::invalid_argument(
            "method must be github_actions, gitlab, or oidc",
        ));
    };
    let loaded = state.policy.current();
    let allowed = loaded.policy.bot_issuers(method);
    if allowed.is_empty() {
        return Err(deny(
            &state,
            addr,
            &req.method,
            None,
            "no bot accepts this kind of token",
        )
        .await);
    }

    let token = match state.bots.verify(&allowed, &req.token).await {
        Ok(t) => t,
        Err(BotTokenError::Unavailable(e)) => {
            tracing::error!(error = %e, "bot token issuer unavailable");
            return Err(Status::unavailable("identity provider unavailable"));
        }
        Err(BotTokenError::Invalid(e)) => {
            tracing::info!(error = %e, "rejected bot token");
            return Err(deny(&state, addr, &req.method, None, "invalid token").await);
        }
    };
    // What a refusal records about the run, before a bot is chosen.
    let refused_run = ci_facts(method, &token.claims, &[]);

    let named = (!req.bot.is_empty()).then_some(req.bot.as_str());
    let matches = loaded
        .policy
        .match_bots(method, &token.issuer, &token.claims, named);
    let bot: &BotDoc = match matches.as_slice() {
        [one] => one,
        [] => {
            return Err(deny(
                &state,
                addr,
                &req.method,
                Some(&refused_run),
                "no bot matches this token",
            )
            .await);
        }
        _ => {
            return Err(deny(
                &state,
                addr,
                &req.method,
                Some(&refused_run),
                "more than one bot matches this token",
            )
            .await);
        }
    };
    let username = bot.username();
    let rule_claims: Vec<&str> = bot.spec.join.claims.keys().map(String::as_str).collect();
    let facts = ci_facts(method, &token.claims, &rule_claims);

    if crate::db::is_locked(&state.db, &username)
        .await
        .map_err(|e| internal("checking locks", e))?
    {
        return Err(deny(&state, addr, &req.method, Some(&facts), "bot locked").await);
    }
    // A bad key is the caller's mistake: say so before the token is spent.
    super::auth::csr_spki(&req.csr_der)?;

    // One login per token, taken as late as possible: only a login that is
    // about to issue credentials spends it. (A token that matched no bot, named
    // the wrong bot, or came with a bad key stays usable until it expires.)
    let fresh = crate::db::use_nonce(
        state.db.clone(),
        token.replay_key.clone(),
        token.replay_until,
    )
    .await
    .map_err(|e| internal("recording bot token use", e))?;
    if !fresh {
        return Err(deny(
            &state,
            addr,
            &req.method,
            Some(&facts),
            "token already used",
        )
        .await);
    }
    let issued = issue(&state, addr, method, bot, &token, facts, req.csr_der).await;
    if issued.is_err()
        && let Err(e) = crate::db::release_nonce(&state.db, &token.replay_key).await
    {
        // The job will have to mint a new token. Say so.
        tracing::error!(error = %e, "couldn't release a bot token after a failed login");
    }
    issued
}

/// Issue the credentials, record the bot, and audit the login. If this fails
/// nothing was handed out, so the caller releases the token.
async fn issue(
    state: &AppState,
    addr: Option<IpAddr>,
    method: JoinMethod,
    bot: &BotDoc,
    token: &crate::bots::BotToken,
    facts: BTreeMap<String, String>,
    csr_der: Vec<u8>,
) -> Result<LoginResponse, Status> {
    let username = bot.username();
    let roles = bot.spec.roles.clone();
    let ttl = bot.ttl().min(state.config.max_cert_ttl);
    let login_id = Uuid::now_v7();
    let issued = state
        .cas
        .user
        .issue_user(UserCertRequest {
            csr_der,
            username: username.clone(),
            roles: roles.clone(),
            login_id,
            ttl,
            ci: Some(facts.clone()),
        })
        .await
        .map_err(|e| match e {
            limen_ca::CaError::InvalidCsr(m) | limen_ca::CaError::InvalidRequest(m) => {
                Status::invalid_argument(m)
            }
            other => internal("issuing bot certificate", other),
        })?;

    // A bot without a row is missing from the Bots page and its lock would show
    // as an orphan: if it can't be recorded, the login fails.
    match crate::console::store::upsert_bot(&state.db, &username, &token.subject, &roles, &facts)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return Err(internal(
                "recording the bot",
                format!("{username} is already the name of someone who isn't a bot"),
            ));
        }
        Err(e) => return Err(internal("recording the bot", e)),
    }
    // Fail closed: no audit event, no credentials.
    let data = json!({
        "login_id": login_id,
        "flow": "bot",
        "actor_type": "bot",
        "method": method.as_str(),
        "bot": bot.metadata.name,
        "idp_subject": token.subject,
        "issuer": token.issuer,
        "roles": roles,
        "ci": facts,
        "cert_serial": issued.serial_hex,
        "expires_at": unix(issued.not_after),
        "client_addr": addr.map(|a| a.to_string()),
    });
    state
        .audit
        .emit(
            EventKind::AuthLogin,
            Context {
                user: Some(username.clone()),
                session_id: None,
            },
            data,
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "audit unavailable; refusing bot login");
            Status::unavailable("audit unavailable")
        })?;
    metrics::counter!("limen_logins_total", "outcome" => "success", "actor" => "bot").increment(1);
    tracing::info!(bot = %username, ?roles, ttl_secs = ttl.as_secs(), "bot login");

    Ok(LoginResponse {
        username,
        roles,
        login_id: login_id.to_string(),
        cert_pem: issued.pem,
        user_ca_pem: state.cas.user.cert_pem().to_owned(),
        internal_ca_pem: state.cas.internal.cert_pem().to_owned(),
        expires_at_unix: unix(issued.not_after),
        ssh_host_ca_public_key: state
            .cas
            .ssh_host
            .public_key_openssh()
            .map_err(|e| internal("SSH host CA", e))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect()
    }

    #[test]
    fn github_facts_keep_the_run_and_drop_the_rest() {
        let facts = ci_facts(
            JoinMethod::GithubActions,
            &claims(&[
                ("repository", "acme/infra"),
                ("run_id", "42"),
                ("actor", "octocat"),
                ("sub", "repo:acme/infra:ref:refs/heads/main"),
                ("iss", "https://token.actions.githubusercontent.com"),
                ("jti", "abc"),
                ("some_future_claim", "x"),
            ]),
            &["repository"],
        );
        assert_eq!(facts["provider"], "github_actions");
        assert_eq!(facts["repository"], "acme/infra");
        assert_eq!(facts["actor"], "octocat");
        assert!(!facts.contains_key("jti") && !facts.contains_key("some_future_claim"));
    }

    #[test]
    fn generic_providers_record_only_the_claims_the_rule_relied_on() {
        let token = claims(&[
            ("sub", "svc"),
            ("iss", "https://i"),
            ("exp", "1"),
            ("team", "platform"),
            ("unrelated", "x"),
        ]);
        let facts = ci_facts(JoinMethod::Oidc, &token, &["sub", "team", "exp"]);
        assert_eq!(facts["team"], "platform");
        assert!(!facts.contains_key("unrelated"), "not named by the rule");
        assert!(!facts.contains_key("exp"), "token plumbing stays out");
        assert_eq!(facts["provider"], "oidc");
        // Before a bot is chosen (a refusal), nothing but the basics.
        let refused = ci_facts(JoinMethod::Oidc, &token, &[]);
        assert_eq!(refused.len(), 3, "{refused:?}");
    }

    #[test]
    fn a_claim_cannot_overwrite_what_limen_sets() {
        // A generic provider can mint any claim names it likes, `provider`
        // included; the rule can even name it. Neither may win.
        let token = claims(&[
            ("sub", "svc"),
            ("iss", "https://i"),
            ("provider", "github_actions"),
        ]);
        let facts = ci_facts(JoinMethod::Oidc, &token, &["provider", "sub"]);
        assert_eq!(facts["provider"], "oidc");
        assert_eq!(facts["sub"], "svc");
        let facts = ci_facts(JoinMethod::GithubActions, &token, &[]);
        assert_eq!(
            facts["provider"], "github_actions",
            "GitHub's own value is Limen's too"
        );
        assert_eq!(facts["iss"], "https://i");
    }

    #[test]
    fn values_fit_what_a_certificate_carries() {
        // Control characters go; a value is cut by bytes on a character boundary.
        let long = format!("{}\n{}", "a".repeat(500), "b");
        let facts = ci_facts(JoinMethod::Gitlab, &claims(&[("ref", &long)]), &[]);
        assert_eq!(facts["ref"].len(), limen_ca::MAX_CI_VALUE);
        assert!(!facts["ref"].contains('\n'));
        // Two-byte characters: 200 of them are 400 bytes, and the cut must not split one.
        let wide = "é".repeat(200);
        let facts = ci_facts(JoinMethod::Gitlab, &claims(&[("ref", &wide)]), &[]);
        assert!(facts["ref"].len() <= limen_ca::MAX_CI_VALUE);
        assert!(facts["ref"].chars().all(|c| c == 'é'));
        assert_eq!(facts["ref"].len() % 2, 0);
    }

    #[test]
    fn empty_values_are_dropped() {
        let facts = ci_facts(
            JoinMethod::GithubActions,
            &claims(&[
                ("repository", "acme/infra"),
                ("environment", ""),
                ("actor", "\u{7}"),
            ]),
            &[],
        );
        assert!(!facts.contains_key("environment"), "empty");
        assert!(!facts.contains_key("actor"), "only control characters");
        assert!(facts.values().all(|v| !v.is_empty()));
    }

    #[test]
    fn the_facts_never_outgrow_a_certificate() {
        let many: BTreeMap<String, String> = (0..40)
            .map(|i| (format!("claim{i}"), "v".to_owned()))
            .chain([
                ("sub".to_owned(), "s".to_owned()),
                ("iss".to_owned(), "https://i".to_owned()),
            ])
            .collect();
        let names: Vec<String> = (0..40).map(|i| format!("claim{i}")).collect();
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        let facts = ci_facts(JoinMethod::Oidc, &many, &names);
        assert!(facts.len() <= limen_ca::MAX_CI_FACTS, "{}", facts.len());
    }
}
