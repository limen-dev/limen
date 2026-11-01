//! Browser SSO and one-use handoffs for host-isolated internal web apps.

use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use base64::Engine as _;
use limen_audit::{Context, EventKind};
use limen_ca::UserCertRequest;
use limen_policy::{AccessRequest, Principal};
use limen_proto::v1::WebAppSession;
use limen_session::envelope::Purpose;
use prost::Message as _;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use super::store::{self, WebAppLogin};
use super::views::error_page;
use super::{
    ClientAddr, LOGIN_COOKIE, clear_cookie, constant_time_eq, hash, new_token, read_cookie,
    set_cookie, with_cookie,
};
use crate::oidc::OidcError;
use crate::state::AppState;

const LOGIN_TTL_SECS: i64 = 600;
const HANDOFF_TTL_SECS: i64 = 60;
const IDENTITY_ISSUER: &str = "urn:limen:control-plane";

#[derive(Debug, Deserialize)]
pub struct StartQuery {
    resource: String,
    host: String,
    return_path: String,
    browser_nonce: String,
}

pub async fn login_start(
    State(state): State<AppState>,
    axum::Extension(addr): axum::Extension<ClientAddr>,
    Query(query): Query<StartQuery>,
) -> Response {
    let Some(console) = &state.console else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if let Err(e) = state.limits.check_console_login(addr.0) {
        return error_page(StatusCode::TOO_MANY_REQUESTS, "Slow down", e.message());
    }
    if !valid_browser_nonce(&query.browser_nonce)
        || !valid_return_path(&query.return_path)
        || state
            .policy
            .current()
            .policy
            .resource(&query.resource)
            .and_then(|r| r.spec.web.as_ref())
            .is_none_or(|w| w.host != query.host)
    {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Bad request",
            "Invalid web app sign-in.",
        );
    }

    let (login_state, nonce, verifier) = (new_token(), new_token(), new_token());
    let challenge = crate::services::b64url(&Sha256::digest(verifier.as_bytes()));
    let expires = OffsetDateTime::now_utc() + time::Duration::seconds(LOGIN_TTL_SECS);
    let login = WebAppLogin {
        resource: query.resource,
        host: query.host,
        return_path: query.return_path,
        browser_nonce_hash: hash(&query.browser_nonce),
        nonce: nonce.clone(),
        pkce_verifier: verifier,
        expires_at: expires,
    };
    if let Err(e) = store::insert_web_app_login(&state.db, &hash(&login_state), &login).await {
        tracing::error!(error = %e, "storing web app login state");
        return unavailable();
    }
    let callback = format!("{}/console/web/callback", console.origin);
    let url = match console
        .oidc
        .authorization_url_with_redirect(&login_state, &nonce, &challenge, &callback)
        .await
    {
        Ok(url) => url,
        Err(e) => {
            tracing::error!(error = %e, "building the web app authorization URL");
            return unavailable();
        }
    };
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

#[allow(clippy::too_many_lines)] // Keep the OIDC callback's checks and fail-closed order visible.
pub async fn login_callback(
    State(state): State<AppState>,
    axum::Extension(addr): axum::Extension<ClientAddr>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let Some(console) = &state.console else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if let Err(e) = state.limits.check_console_login(addr.0) {
        return error_page(StatusCode::TOO_MANY_REQUESTS, "Slow down", e.message());
    }
    if query.error.is_some() {
        return denied(
            &state,
            addr.0,
            None,
            "identity provider refused",
            "The identity provider didn't sign you in.",
        )
        .await;
    }
    let (Some(code), Some(login_state)) = (query.code, query.state) else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Bad request",
            "The sign-in response was incomplete. Start again.",
        );
    };
    let cookie_matches =
        read_cookie(&headers, LOGIN_COOKIE).is_some_and(|c| constant_time_eq(&c, &login_state));
    if !cookie_matches {
        return denied(
            &state,
            addr.0,
            None,
            "login state does not match this browser",
            "This sign-in wasn't started in this browser. Start again.",
        )
        .await;
    }
    let login = match store::take_web_app_login(&state.db, &hash(&login_state)).await {
        Ok(Some(login)) => login,
        Ok(None) => {
            return denied(
                &state,
                addr.0,
                None,
                "unknown or expired web app login",
                "This sign-in expired or was already used. Start again.",
            )
            .await;
        }
        Err(e) => {
            tracing::error!(error = %e, "reading web app login state");
            return unavailable();
        }
    };
    let callback = format!("{}/console/web/callback", console.origin);
    let identity = match console
        .oidc
        .complete_with_redirect(&code, &login.pkce_verifier, &login.nonce, &callback)
        .await
    {
        Ok(identity) => identity,
        Err(OidcError::Unavailable(e)) => {
            tracing::error!(error = %e, "identity provider unavailable");
            return unavailable();
        }
        Err(OidcError::Invalid(e)) => {
            tracing::info!(error = %e, "rejected web app ID token");
            return denied(
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
        return denied(
            &state,
            addr.0,
            Some(identity.username),
            "reserved username",
            "Machine identities cannot use browser sign-in.",
        )
        .await;
    }
    let roles: Vec<String> = state
        .policy
        .current()
        .policy
        .roles_for_groups(
            identity.groups.iter().map(String::as_str),
            &state.config.bootstrap_admin_groups,
        )
        .into_iter()
        .collect();
    if roles.is_empty() && !crate::access::takes_part(&state, &identity.username, &identity.groups)
    {
        return denied(
            &state,
            addr.0,
            Some(identity.username),
            "no roles are mapped to the user's groups",
            "No Limen roles are mapped to your groups.",
        )
        .await;
    }
    match crate::db::is_locked(&state.db, &identity.username).await {
        Ok(false) => {}
        Ok(true) => {
            return denied(
                &state,
                addr.0,
                Some(identity.username),
                "user locked",
                "An administrator locked this account.",
            )
            .await;
        }
        Err(e) => {
            tracing::error!(error = %e, "checking web app user lock");
            return unavailable();
        }
    }
    let loaded = state.policy.current();
    // Roles from approved access requests count (ADR-0025).
    let effective = match crate::access::effective_roles_now(
        &state,
        &identity.username,
        &roles,
        &login.resource,
    )
    .await
    {
        Ok(e) => e,
        Err(e) => {
            tracing::error!(error = %e, "reading access grants");
            return unavailable();
        }
    };
    let grant = loaded.policy.evaluate(&AccessRequest {
        roles: &effective.roles,
        resource: &login.resource,
        principal: Principal::WebAccess,
    });
    if !grant.is_allowed() {
        return denied(
            &state,
            addr.0,
            Some(identity.username),
            "no web app grant",
            "You do not have access to this web app.",
        )
        .await;
    }

    let login_id = Uuid::now_v7();
    let ttl = state
        .config
        .console_session_ttl
        .min(loaded.policy.cert_ttl(
            &roles,
            state.config.default_cert_ttl,
            state.config.max_cert_ttl,
        ))
        .min(std::time::Duration::from_secs(LOGIN_TTL_SECS as u64));
    let key = match KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256) {
        Ok(key) => key,
        Err(e) => {
            tracing::error!(error = %e, "generating web app identity key");
            return unavailable();
        }
    };
    let csr = match CertificateParams::default().serialize_request(&key) {
        Ok(csr) => csr,
        Err(e) => {
            tracing::error!(error = %e, "creating web app identity CSR");
            return unavailable();
        }
    };
    let issued = match state
        .cas
        .user
        .issue_user(UserCertRequest {
            csr_der: csr.der().to_vec(),
            username: identity.username.clone(),
            roles: roles.clone(),
            login_id,
            ttl,
            ci: None,
        })
        .await
    {
        Ok(issued) => issued,
        Err(e) => {
            tracing::error!(error = %e, "issuing web app user identity");
            return unavailable();
        }
    };
    if let Err(e) = store::upsert_user(
        &state.db,
        &identity.username,
        &identity.subject,
        &roles,
        &identity.groups,
    )
    .await
    {
        tracing::warn!(error = %e, "recording web app user");
    }
    let expires_at = issued.not_after;
    if let Err(e) = state
        .audit
        .emit(
            EventKind::AuthLogin,
            Context {
                user: Some(identity.username.clone()),
                session_id: None,
            },
            json!({
                "login_id": login_id,
                "flow": "web_sso",
                "idp_subject": identity.subject,
                "groups": identity.groups,
                "roles": roles,
                "cert_serial": issued.serial_hex,
                "expires_at": expires_at.unix_timestamp(),
                "resource": login.resource,
                "host": login.host,
                "client_addr": addr.0.map(|a| a.to_string()),
            }),
        )
        .await
    {
        tracing::error!(error = %e, "audit unavailable; refusing web app login");
        return unavailable();
    }
    let signer = state
        .snapshot_signer
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let Some(signer) = signer else {
        tracing::error!("web app session signer is not ready");
        return unavailable();
    };
    let identity_headers = loaded
        .policy
        .resource(&login.resource)
        .and_then(|resource| resource.spec.web.as_ref())
        .is_some_and(|web| web.identity_headers);
    let identity_assertion = if identity_headers {
        let now = OffsetDateTime::now_utc();
        let claims = json!({
            "iss": IDENTITY_ISSUER,
            "sub": identity.username,
            "aud": login.host,
            "iat": now.unix_timestamp(),
            "exp": expires_at.unix_timestamp(),
            "roles": roles,
            "login_id": login_id,
        });
        match signer.sign_jwt(&claims) {
            Ok(assertion) => assertion,
            Err(e) => {
                tracing::error!(error = %e, "signing web app identity assertion");
                return unavailable();
            }
        }
    } else {
        String::new()
    };
    let session = WebAppSession {
        username: identity.username,
        roles,
        login_id: login_id.to_string(),
        resource: login.resource.clone(),
        host: login.host.clone(),
        expires_at_unix: expires_at.unix_timestamp(),
        user_cert_der: issued.der.to_vec(),
        identity_assertion,
    };
    let session_envelope = match signer.sign(Purpose::WebAppSession, session.encode_to_vec()) {
        Ok(envelope) => envelope,
        Err(e) => {
            tracing::error!(error = %e, "signing web app session");
            return unavailable();
        }
    };
    let handoff = new_token();
    let handoff_expires = OffsetDateTime::now_utc() + time::Duration::seconds(HANDOFF_TTL_SECS);
    let new_handoff = store::WebAppHandoff {
        token_hash: hash(&handoff),
        resource: login.resource.clone(),
        host: login.host.clone(),
        return_path: login.return_path.clone(),
        browser_nonce_hash: login.browser_nonce_hash,
        session: session_envelope.encode_to_vec(),
        expires_at: handoff_expires,
    };
    if let Err(e) = store::insert_web_app_handoff(&state.db, &new_handoff).await {
        tracing::error!(error = %e, "storing one-use web app handoff");
        return unavailable();
    }
    let app_authority = match Url::parse(&console.origin) {
        Ok(origin) => origin.port().map_or_else(
            || login.host.clone(),
            |port| format!("{}:{port}", login.host),
        ),
        Err(e) => {
            tracing::error!(error = %e, "reading the console's public origin");
            return unavailable();
        }
    };
    let mut destination = match Url::parse(&format!("https://{app_authority}/.limen/callback")) {
        Ok(url) => url,
        Err(e) => {
            tracing::error!(error = %e, "building web app handoff URL");
            return unavailable();
        }
    };
    destination
        .query_pairs_mut()
        .append_pair("handoff", &handoff);
    with_cookie(
        Redirect::to(destination.as_str()).into_response(),
        clear_cookie(LOGIN_COOKIE),
    )
}

pub async fn jwks(State(state): State<AppState>) -> Response {
    match store::web_identity_jwks(&state.db).await {
        Ok(keys) => {
            let mut response = Json(json!({"keys": keys})).into_response();
            response.headers_mut().insert(
                axum::http::header::CACHE_CONTROL,
                axum::http::HeaderValue::from_static("no-cache"),
            );
            response
        }
        Err(e) => {
            tracing::error!(error = %e, "loading web identity JWKS");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

fn valid_browser_nonce(nonce: &str) -> bool {
    nonce.len() <= 128
        && base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(nonce)
            .is_ok_and(|bytes| bytes.len() == 32)
}

fn valid_return_path(path: &str) -> bool {
    let Ok(uri) = http::Uri::try_from(path) else {
        return false;
    };
    let Some(path_and_query) = uri.path_and_query() else {
        return false;
    };
    let route = path_and_query.path();
    path.len() <= 4096
        && uri.authority().is_none()
        && route.starts_with('/')
        && !route.starts_with("//")
        && !route.contains("//")
        && !route.contains(['#', '\\', '%'])
        && route
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-._~".contains(&b))
        && route
            .split('/')
            .all(|segment| segment != "." && segment != "..")
        && path.bytes().all(|b| b.is_ascii_graphic())
        && !path.contains('#')
}

async fn denied(
    state: &AppState,
    addr: Option<std::net::IpAddr>,
    user: Option<String>,
    reason: &'static str,
    message: &'static str,
) -> Response {
    metrics::counter!("limen_logins_total", "outcome" => "denied").increment(1);
    tracing::warn!(user = user.as_deref(), client_addr = ?addr, reason, "web app login denied");
    if let Err(e) = state
        .audit
        .emit(
            EventKind::AuthDenied,
            Context {
                user,
                session_id: None,
            },
            json!({
                "action": "web_sso",
                "reason": reason,
                "client_addr": addr.map(|a| a.to_string()),
            }),
        )
        .await
    {
        tracing::error!(error = %e, "failed to audit a denied web app login");
    }
    with_cookie(
        error_page(StatusCode::FORBIDDEN, "Sign-in refused", message),
        clear_cookie(LOGIN_COOKIE),
    )
}

fn unavailable() -> Response {
    error_page(
        StatusCode::SERVICE_UNAVAILABLE,
        "Sign-in unavailable",
        "The identity provider or database can't be reached right now. Try again shortly.",
    )
}

pub async fn redeem(
    state: &AppState,
    request: tonic::Request<limen_proto::v1::RedeemWebHandoffRequest>,
) -> Result<tonic::Response<limen_proto::v1::RedeemWebHandoffResponse>, tonic::Status> {
    use crate::caller;
    use limen_proto::v1::RedeemWebHandoffResponse;

    let caller = caller::resolve(&request, &state.cas)?;
    caller.direct_proxy()?;
    let request = request.into_inner();
    if request.token.len() > 128
        || request.resource.is_empty()
        || request.host.is_empty()
        || !valid_browser_nonce(&request.browser_nonce)
    {
        return Err(tonic::Status::invalid_argument("invalid web handoff"));
    }
    let Some((session, return_path)) = store::take_web_app_handoff(
        &state.db,
        &hash(&request.token),
        &request.resource,
        &request.host,
        &hash(&request.browser_nonce),
    )
    .await
    .map_err(|e| crate::state::internal("redeeming web app handoff", e))?
    else {
        return Err(tonic::Status::permission_denied(
            "unknown, expired, or already used web handoff",
        ));
    };
    let session = limen_proto::v1::Signed::decode(session.as_slice())
        .map_err(|e| tonic::Status::internal(format!("stored web session is malformed: {e}")))?;
    Ok(tonic::Response::new(RedeemWebHandoffResponse {
        session: Some(session),
        return_path,
    }))
}
