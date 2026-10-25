//! The web console (ADR-0017): server-rendered pages inside the control
//! plane, reached through the proxy under `/console/`.
//!
//! Security model:
//! - Requests only count when they arrive from a proxy over mTLS.
//! - Login is OIDC authorization code with PKCE. The browser gets a random
//!   session token in a `__Host-` cookie (`HttpOnly`, `Secure`, `SameSite=Lax`);
//!   only its hash is stored.
//! - State-changing requests are POSTs with a per-session CSRF token and a
//!   matching `Origin`.
//! - Every response carries a strict CSP (no inline script, no third-party
//!   origins; `'wasm-unsafe-eval'` only because the recording player's
//!   terminal emulator is WebAssembly, and it doesn't allow JS `eval`), frame denial, and `no-store` for pages.

// Handlers return a ready-made `Response` as the error, as axum expects.
#![allow(clippy::result_large_err)]

mod assets;
mod auth;
mod dashboards;
pub mod oidc_flow;
mod pages;
mod query;
pub mod store;
mod views;
pub(crate) mod web_auth;
mod workflows;

use std::net::IpAddr;

use axum::Router;
use axum::extract::{FromRequestParts, Request, State};
use axum::http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, COOKIE, ORIGIN, REFERER, REFERRER_POLICY,
    SET_COOKIE, STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use limen_ca::verify::verify_component;
use limen_core::identity::{ADMIN_ROLE, AUDITOR_ROLE, ComponentKind};
use limen_proto::relay;
use limen_tunnel::PeerInfo;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::state::AppState;

pub use oidc_flow::BrowserOidc;

pub const SESSION_COOKIE: &str = "__Host-limen_console";
pub const LOGIN_COOKIE: &str = "__Host-limen_login";
/// Largest request body any console page accepts.
const MAX_BODY: usize = 1024 * 1024 + 16 * 1024;

const CSP: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; \
style-src-attr 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; \
worker-src blob:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

/// What the console needs beyond the shared state.
#[derive(Debug, Clone)]
pub struct Console {
    /// `https://host[:port]`, no trailing slash. Also the only accepted `Origin`.
    pub origin: String,
    pub oidc: BrowserOidc,
}

/// Where a request really came from, as reported by the proxy.
#[derive(Debug, Clone, Copy)]
pub struct ClientAddr(pub Option<IpAddr>);

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/console", get(|| async { Redirect::to("/console/") }))
        .route("/console/", get(pages::home))
        .route("/console/signin", get(pages::signin))
        .route("/console/login", get(auth::login_start))
        .route("/console/callback", get(auth::callback))
        .route("/console/web/login", get(web_auth::login_start))
        .route("/console/web/callback", get(web_auth::login_callback))
        .route("/console/web/jwks.json", get(web_auth::jwks))
        .route("/console/logout", get(pages::signout).post(auth::logout))
        .route("/console/static/{name}", get(assets::serve))
        .route("/console/resources", get(pages::resources))
        .route("/console/resources/{name}", get(pages::resource_detail))
        .route("/console/sessions", get(pages::sessions))
        .route("/console/sessions/{id}", get(pages::session_detail))
        .route("/console/sessions/{id}/recording", get(pages::recording))
        .route("/console/sessions/{id}/kill", post(pages::kill_session))
        .route("/console/bots", get(pages::bots))
        .route("/console/users", get(pages::users))
        .route("/console/users/{name}", get(pages::user_detail))
        .route("/console/users/{name}/lock", post(pages::lock_user))
        .route("/console/users/{name}/unlock", post(pages::unlock_user))
        .route("/console/workers", get(pages::workers))
        .route("/console/workers/tokens", post(pages::create_token))
        .route("/console/workers/{id}/revoke", post(pages::revoke))
        .route("/console/audit", get(pages::audit))
        .route("/console/audit/kubernetes", get(pages::kube_requests))
        .route("/console/dashboards", get(dashboards::dashboards))
        .route("/console/policy", get(pages::policy))
        .route("/console/policy/dry-run", post(pages::dry_run))
        .route("/console/policy/simulate", post(pages::simulate))
        .route("/console/access", get(workflows::access_page))
        .route("/console/access/request", post(workflows::access_request))
        .route("/console/access/{id}", get(workflows::access_detail))
        .route(
            "/console/access/{id}/decide",
            post(workflows::access_decide),
        )
        .route(
            "/console/access/{id}/cancel",
            post(workflows::access_cancel),
        )
        .route(
            "/console/access/grants/{id}/revoke",
            post(workflows::access_revoke),
        )
        .route("/console/reviews", get(workflows::reviews_page))
        .route("/console/reviews/start", post(workflows::review_start))
        .route("/console/reviews/evidence", get(workflows::evidence))
        .route("/console/reviews/{id}", get(workflows::review_page))
        .route(
            "/console/reviews/items/{id}/decide",
            post(workflows::review_decide),
        )
        .route(
            "/console/reviews/overrides/{id}/lift",
            post(workflows::deny_lift),
        )
        .route("/console/discovered", get(workflows::discovered_page))
        .route(
            "/console/discovered/review",
            post(workflows::discovered_review),
        )
        .route("/console/sessions/{id}/watch", get(workflows::watch_page))
        .route(
            "/console/sessions/{id}/watch/stream",
            get(workflows::watch_stream),
        )
        // Not `.fallback()`: the gRPC router this is merged with has one.
        .route(
            "/console/{*rest}",
            axum::routing::any(|| async {
                views::error_page(
                    StatusCode::NOT_FOUND,
                    "Not found",
                    "There is nothing at this address.",
                )
            }),
        )
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY))
        .layer(middleware::from_fn_with_state(state.clone(), proxy_only))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

/// Only proxies may reach the console, and only on behalf of a browser.
async fn proxy_only(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let verified = req
        .extensions()
        .get::<PeerInfo>()
        .and_then(PeerInfo::leaf)
        .and_then(|leaf| verify_component(leaf, state.cas.internal.cert_der(), false).ok())
        .is_some_and(|id| id.kind == ComponentKind::Proxy)
        && req.headers().contains_key(relay::FORWARDED);
    if !verified {
        return (
            StatusCode::FORBIDDEN,
            "the console is served through the proxy",
        )
            .into_response();
    }
    let addr = req
        .headers()
        .get(relay::CLIENT_ADDR)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<std::net::SocketAddr>().ok())
        .map(|a| a.ip());
    req.extensions_mut().insert(ClientAddr(addr));
    next.run(req).await
}

async fn security_headers(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let h = response.headers_mut();
    h.insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    h.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(REFERRER_POLICY, HeaderValue::from_static("same-origin"));
    h.insert(
        STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000"),
    );
    h.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    // Pages carry session data; static assets set their own caching.
    h.entry(CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
    response
}

// ---- cookies and tokens -------------------------------------------------------

/// A random URL-safe token (256 bits).
#[must_use]
pub fn new_token() -> String {
    crate::services::b64url(&rand::random::<[u8; 32]>())
}

#[must_use]
pub fn hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

#[must_use]
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// # Panics
/// If `name` or `value` hold characters a header can't carry. Callers pass
/// URL-safe random tokens.
#[must_use]
pub fn set_cookie(name: &str, value: &str, max_age_secs: i64) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{name}={value}; Path=/; Max-Age={max_age_secs}; HttpOnly; Secure; SameSite=Lax"
    ))
    .expect("cookie values are URL-safe")
}

#[must_use]
pub fn clear_cookie(name: &str) -> HeaderValue {
    set_cookie(name, "", 0)
}

#[must_use]
pub fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_owned())
}

// ---- the signed-in user -------------------------------------------------------

#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)] // independent flags, not a state machine
pub struct Auth {
    pub username: String,
    pub roles: Vec<String>,
    pub csrf: String,
    pub token_hash: Vec<u8>,
    pub is_admin: bool,
    /// Holds `limen:auditor`: reads the record, changes nothing (ADR-0026).
    pub is_auditor: bool,
    /// Show the Access and Reviews pages in the menu: for people with something there.
    pub sees_access: bool,
    pub sees_reviews: bool,
    pub expires_at: time::OffsetDateTime,
    pub addr: Option<IpAddr>,
}

impl Auth {
    /// Admins and auditors read the whole record: every session, the audit
    /// trail, recordings, search. Only admins change anything.
    #[must_use]
    pub fn reads_record(&self) -> bool {
        self.is_admin || self.is_auditor
    }

    /// 403 page unless the user may read the record.
    pub fn reader(&self) -> Result<(), Response> {
        if self.reads_record() {
            Ok(())
        } else {
            Err(views::error_page(
                StatusCode::FORBIDDEN,
                "Auditors and admins only",
                "You don't have a role that reads the audit record, so this page isn't available to you.",
            ))
        }
    }

    /// 403 page unless the user is an admin.
    pub fn admin(&self) -> Result<(), Response> {
        if self.is_admin {
            Ok(())
        } else {
            Err(views::error_page(
                StatusCode::FORBIDDEN,
                "Admins only",
                "You don't have the admin role, so this page isn't available to you.",
            ))
        }
    }

    /// For POSTs: the CSRF token must match and the request must come from
    /// our own origin.
    pub fn check_post(
        &self,
        console: &Console,
        headers: &HeaderMap,
        csrf: &str,
    ) -> Result<(), Response> {
        let same_origin = headers
            .get(ORIGIN)
            .and_then(|v| v.to_str().ok())
            .map(|o| o == console.origin)
            .or_else(|| {
                headers
                    .get(REFERER)
                    .and_then(|v| v.to_str().ok())
                    .map(|r| r.starts_with(&format!("{}/", console.origin)))
            })
            .unwrap_or(false);
        if same_origin && constant_time_eq(&self.csrf, csrf) {
            Ok(())
        } else {
            Err(views::error_page(
                StatusCode::FORBIDDEN,
                "Request refused",
                "The page that sent this request has expired, or came from somewhere else. Go back, reload it, and try again.",
            ))
        }
    }
}

impl FromRequestParts<AppState> for Auth {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Response> {
        let to_login = || Redirect::to("/console/signin").into_response();
        let Some(token) = read_cookie(&parts.headers, SESSION_COOKIE) else {
            return Err(to_login());
        };
        let token_hash = hash(&token);
        let session = store::console_session(&state.db, &token_hash)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "reading console session");
                views::error_page(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Unavailable",
                    "The console can't reach its database. Try again shortly.",
                )
            })?
            .ok_or_else(to_login)?;
        // A lock ends browser sessions at once.
        let locked = crate::db::is_locked(&state.db, &session.username)
            .await
            .unwrap_or(true);
        if locked {
            let _ = store::delete_console_session(&state.db, &token_hash).await;
            return Err(views::error_page(
                StatusCode::FORBIDDEN,
                "Account locked",
                "An administrator locked this account.",
            ));
        }
        let addr = parts.extensions.get::<ClientAddr>().and_then(|a| a.0);
        let is_admin = session.roles.iter().any(|r| r == ADMIN_ROLE);
        let is_auditor = session.roles.iter().any(|r| r == AUDITOR_ROLE);
        let (sees_access, sees_reviews) = if is_admin || is_auditor {
            (true, true)
        } else {
            store::menu_pages(state, &session.username).await
        };
        Ok(Auth {
            is_admin,
            is_auditor,
            sees_access,
            sees_reviews,
            username: session.username,
            roles: session.roles,
            csrf: session.csrf,
            token_hash,
            expires_at: session.expires_at,
            addr,
        })
    }
}

/// Add a `Set-Cookie` header to a response.
#[must_use]
pub fn with_cookie(mut response: Response, cookie: HeaderValue) -> Response {
    response.headers_mut().append(SET_COOKIE, cookie);
    response
}

pub fn html(body: Result<String, askama::Error>) -> Response {
    match body {
        Ok(body) => ([(CONTENT_TYPE, "text/html; charset=utf-8")], body).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "rendering a console page");
            views::error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong",
                "The page couldn't be rendered.",
            )
        }
    }
}
