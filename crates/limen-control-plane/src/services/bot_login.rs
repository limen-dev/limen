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

/// The claims worth recording about the run behind a login, by provider.
/// Everything else in the token stays out of the certificate and the audit
/// trail.
fn ci_facts(method: JoinMethod, claims: &BTreeMap<String, String>) -> BTreeMap<String, String> {
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
    let mut facts: BTreeMap<String, String> = wanted
        .iter()
        .filter_map(|k| claims.get(*k).map(|v| ((*k).to_owned(), clip(v))))
        .collect();
    facts.insert("provider".into(), method.as_str().to_owned());
    for key in ["iss", "sub"] {
        if let Some(v) = claims.get(key) {
            facts.insert(key.to_owned(), clip(v));
        }
    }
    // A generic provider has no known claim names: keep a few scalars.
    if method == JoinMethod::Oidc {
        const SKIP: [&str; 9] = [
            "iss", "sub", "aud", "exp", "iat", "nbf", "jti", "nonce", "at_hash",
        ];
        for (k, v) in claims
            .iter()
            .filter(|(k, _)| !SKIP.contains(&k.as_str()) && k.len() <= 64)
            .take(10)
        {
            facts.insert(k.clone(), clip(v));
        }
    }
    facts
}

fn clip(v: &str) -> String {
    v.chars().filter(|c| !c.is_control()).take(240).collect()
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
    let facts = ci_facts(method, &token.claims);

    // One login per token.
    let fresh = crate::db::use_nonce(state.db.clone(), token.replay_key.clone(), token.expires_at)
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
                Some(&facts),
                "no bot matches this token",
            )
            .await);
        }
        _ => {
            return Err(deny(
                &state,
                addr,
                &req.method,
                Some(&facts),
                "more than one bot matches this token",
            )
            .await);
        }
    };
    let username = bot.username();

    if crate::db::is_locked(&state.db, &username)
        .await
        .map_err(|e| internal("checking locks", e))?
    {
        return Err(deny(&state, addr, &req.method, Some(&facts), "bot locked").await);
    }

    let roles = bot.spec.roles.clone();
    let ttl = bot.ttl().min(state.config.max_cert_ttl);
    let login_id = Uuid::now_v7();
    let issued = state
        .cas
        .user
        .issue_user(UserCertRequest {
            csr_der: req.csr_der,
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

    if let Err(e) =
        crate::console::store::upsert_bot(&state.db, &username, &token.subject, &roles, &facts)
            .await
    {
        tracing::warn!(error = %e, "recording the bot");
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
        );
        assert_eq!(facts["provider"], "github_actions");
        assert_eq!(facts["repository"], "acme/infra");
        assert_eq!(facts["actor"], "octocat");
        assert!(!facts.contains_key("jti") && !facts.contains_key("some_future_claim"));
    }

    #[test]
    fn generic_providers_keep_a_few_scalars_without_the_standard_ones() {
        let facts = ci_facts(
            JoinMethod::Oidc,
            &claims(&[
                ("sub", "svc"),
                ("iss", "https://i"),
                ("exp", "1"),
                ("team", "platform"),
            ]),
        );
        assert_eq!(facts["team"], "platform");
        assert!(!facts.contains_key("exp"));
        assert_eq!(facts["provider"], "oidc");
    }

    #[test]
    fn values_are_clipped_and_stripped_of_control_characters() {
        let long = format!("{}\n{}", "a".repeat(500), "b");
        let facts = ci_facts(JoinMethod::Gitlab, &claims(&[("ref", &long)]));
        assert_eq!(facts["ref"].len(), 240);
        assert!(!facts["ref"].contains('\n'));
    }
}
