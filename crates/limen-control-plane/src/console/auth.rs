//! Browser login (OIDC authorization code with PKCE), callback, and logout.

use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use limen_audit::{Context, EventKind};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use super::store::{self, ConsoleSession};
use super::views::error_page;
use super::{
    Auth, ClientAddr, LOGIN_COOKIE, SESSION_COOKIE, clear_cookie, constant_time_eq, hash,
    new_token, read_cookie, set_cookie, with_cookie,
};
use crate::oidc::OidcError;
use crate::state::AppState;

/// How long a started login may take.
const LOGIN_TTL_SECS: i64 = 600;

fn unavailable() -> Response {
    error_page(
        StatusCode::SERVICE_UNAVAILABLE,
        "Sign-in unavailable",
        "The identity provider or the database can't be reached right now. Try again shortly.",
    )
}

pub async fn login_start(
    State(state): State<AppState>,
    axum::Extension(addr): axum::Extension<ClientAddr>,
) -> Response {
    let Some(console) = &state.console else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if let Err(e) = state.limits.check_console_login(addr.0) {
        return error_page(StatusCode::TOO_MANY_REQUESTS, "Slow down", e.message());
    }
    let (login_state, nonce, verifier) = (new_token(), new_token(), new_token());
    let challenge = crate::services::b64url(&Sha256::digest(verifier.as_bytes()));
    let expires = OffsetDateTime::now_utc() + time::Duration::seconds(LOGIN_TTL_SECS);
    if let Err(e) =
        store::insert_login(&state.db, &hash(&login_state), &nonce, &verifier, expires).await
    {
        tracing::error!(error = %e, "storing console login state");
        return unavailable();
    }
    let url = match console
        .oidc
        .authorization_url(&login_state, &nonce, &challenge)
        .await
    {
        Ok(url) => url,
        Err(e) => {
            tracing::error!(error = %e, "building the authorization URL");
            return unavailable();
        }
    };
    // The cookie ties the callback to this browser (login CSRF).
    with_cookie(
        Redirect::to(&url).into_response(),
        set_cookie(LOGIN_COOKIE, &login_state, LOGIN_TTL_SECS),
    )
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

async fn deny(
    state: &AppState,
    addr: Option<std::net::IpAddr>,
    user: Option<String>,
    reason: &'static str,
    message: &'static str,
) -> Response {
    metrics::counter!("limen_logins_total", "outcome" => "denied").increment(1);
    tracing::warn!(user = user.as_deref(), client_addr = ?addr, reason, "console login denied");
    if let Err(e) = state
        .audit
        .emit(
            EventKind::AuthDenied,
            Context {
                user,
                session_id: None,
            },
            json!({ "action": "console_login", "reason": reason, "client_addr": addr.map(|a| a.to_string()) }),
        )
        .await
    {
        tracing::error!(error = %e, "failed to audit a denied console login");
    }
    with_cookie(
        error_page(StatusCode::FORBIDDEN, "Sign-in refused", message),
        clear_cookie(LOGIN_COOKIE),
    )
}

pub async fn callback(
    State(state): State<AppState>,
    axum::Extension(addr): axum::Extension<ClientAddr>,
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Response {
    let Some(console) = &state.console else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if let Err(e) = state.limits.check_console_login(addr.0) {
        return error_page(StatusCode::TOO_MANY_REQUESTS, "Slow down", e.message());
    }
    if q.error.is_some() {
        // The IdP's description is untrusted text; don't reflect it.
        return deny(
            &state,
            addr.0,
            None,
            "identity provider refused",
            "The identity provider didn't sign you in.",
        )
        .await;
    }
    let (Some(code), Some(login_state)) = (q.code, q.state) else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Bad request",
            "The sign-in response was incomplete. Start again.",
        );
    };
    let cookie_matches =
        read_cookie(&headers, LOGIN_COOKIE).is_some_and(|c| constant_time_eq(&c, &login_state));
    if !cookie_matches {
        return deny(
            &state,
            addr.0,
            None,
            "login state does not match this browser",
            "This sign-in wasn't started in this browser. Start again.",
        )
        .await;
    }
    let (nonce, verifier) = match store::take_login(&state.db, &hash(&login_state)).await {
        Ok(Some(pair)) => pair,
        Ok(None) => {
            return deny(
                &state,
                addr.0,
                None,
                "unknown or expired login",
                "This sign-in expired or was already used. Start again.",
            )
            .await;
        }
        Err(e) => {
            tracing::error!(error = %e, "reading console login state");
            return unavailable();
        }
    };
    let identity = match console.oidc.complete(&code, &verifier, &nonce).await {
        Ok(identity) => identity,
        Err(OidcError::Unavailable(e)) => {
            tracing::error!(error = %e, "identity provider unavailable");
            return unavailable();
        }
        Err(OidcError::Invalid(e)) => {
            tracing::info!(error = %e, "rejected console ID token");
            return deny(
                &state,
                addr.0,
                None,
                "invalid ID token",
                "The identity provider's answer couldn't be verified.",
            )
            .await;
        }
    };
    if limen_core::identity::is_bot(&identity.username) {
        return deny(
            &state,
            addr.0,
            Some(identity.username),
            "reserved username",
            "That user name is reserved for machine identities.",
        )
        .await;
    }
    finish_login(&state, addr.0, identity).await
}

/// A verified identity: check locks and roles, then create the browser session.
async fn finish_login(
    state: &AppState,
    addr: Option<std::net::IpAddr>,
    identity: crate::oidc::VerifiedIdentity,
) -> Response {
    match crate::db::is_locked(&state.db, &identity.username).await {
        Ok(false) => {}
        Ok(true) => {
            return deny(
                state,
                addr,
                Some(identity.username),
                "user locked",
                "An administrator locked this account.",
            )
            .await;
        }
        Err(e) => {
            tracing::error!(error = %e, "checking locks");
            return unavailable();
        }
    }
    let loaded = state.policy.current();
    let roles: Vec<String> = loaded
        .policy
        .roles_for_groups(
            identity.groups.iter().map(String::as_str),
            &state.config.bootstrap_admin_groups,
        )
        .into_iter()
        .collect();
    // Someone who can only ask for access (ADR-0025) still signs in.
    if roles.is_empty() && !crate::access::takes_part(state, &identity.username, &identity.groups) {
        return deny(
            state,
            addr,
            Some(identity.username),
            "no roles are mapped to the user's groups",
            "No Limen roles are mapped to your groups, so there is nothing to show you.",
        )
        .await;
    }
    let ttl = state
        .config
        .console_session_ttl
        .min(state.config.max_cert_ttl);
    let login_id = Uuid::now_v7();
    let session_token = new_token();
    let session = ConsoleSession {
        username: identity.username.clone(),
        roles: roles.clone(),
        login_id: login_id.to_string(),
        csrf: new_token(),
        expires_at: OffsetDateTime::now_utc() + ttl,
    };
    if let Err(e) = store::create_console_session(&state.db, &hash(&session_token), &session).await
    {
        tracing::error!(error = %e, "creating console session");
        return unavailable();
    }
    if let Err(e) = store::upsert_user(
        &state.db,
        &identity.username,
        &identity.subject,
        &roles,
        &identity.groups,
    )
    .await
    {
        tracing::warn!(error = %e, "recording the user");
    }
    // Fail closed: no audit event, no session.
    let audited = state
        .audit
        .emit(
            EventKind::AuthLogin,
            Context {
                user: Some(identity.username.clone()),
                session_id: None,
            },
            json!({
                "login_id": login_id,
                "flow": "console",
                "idp_subject": identity.subject,
                "groups": identity.groups,
                "roles": roles,
                "expires_at": session.expires_at.unix_timestamp(),
                "client_addr": addr.map(|a| a.to_string()),
            }),
        )
        .await;
    if let Err(e) = audited {
        tracing::error!(error = %e, "audit unavailable; refusing console login");
        let _ = store::delete_console_session(&state.db, &hash(&session_token)).await;
        return unavailable();
    }
    metrics::counter!("limen_logins_total", "outcome" => "success").increment(1);
    tracing::info!(user = %identity.username, ?roles, "console login");
    let max_age = i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX);
    let response = with_cookie(
        Redirect::to("/console/").into_response(),
        set_cookie(SESSION_COOKIE, &session_token, max_age),
    );
    with_cookie(response, clear_cookie(LOGIN_COOKIE))
}

#[derive(Deserialize)]
pub struct CsrfForm {
    csrf: String,
}

pub async fn logout(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let Some(console) = &state.console else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if let Err(r) = auth.check_post(console, &headers, &form.csrf) {
        return r;
    }
    let _ = store::delete_console_session(&state.db, &auth.token_hash).await;
    with_cookie(
        error_page(
            StatusCode::OK,
            "Signed out",
            "You're signed out of the console.",
        ),
        clear_cookie(SESSION_COOKIE),
    )
}
