//! Login and identity introspection.

use std::net::IpAddr;

use limen_audit::{Context, Emitter, EventKind};
use limen_ca::UserCertRequest;
use limen_proto::v1::auth_server::Auth;
use limen_proto::v1::{
    GetAuthConfigRequest, GetAuthConfigResponse, LoginFlow, LoginRequest, LoginResponse,
    WhoAmIRequest, WhoAmIResponse,
};
use rcgen::CertificateSigningRequestParams;
use rustls_pki_types::CertificateSigningRequestDer;
use serde_json::json;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use super::sha256;
use crate::caller;
use crate::state::{AppState, internal, unix};

#[derive(Debug, Clone)]
pub struct AuthService(pub AppState);

/// Re-exported for tests and tools. See [`limen_core::login::nonce`].
pub use limen_core::login::nonce as expected_nonce;

/// Audit a denied login and build the error to return.
async fn deny(
    audit: Emitter,
    addr: Option<IpAddr>,
    user: Option<String>,
    reason: &'static str,
) -> Status {
    metrics::counter!("limen_logins_total", "outcome" => "denied").increment(1);
    let data =
        json!({ "action": "login", "reason": reason, "client_addr": addr.map(|a| a.to_string()) });
    if let Err(e) = audit
        .emit(
            EventKind::AuthDenied,
            Context {
                user,
                session_id: None,
            },
            data,
        )
        .await
    {
        tracing::error!(error = %e, "failed to audit a denied login");
    }
    Status::permission_denied(format!("login denied: {reason}"))
}

#[tonic::async_trait]
impl Auth for AuthService {
    async fn get_auth_config(
        &self,
        request: Request<GetAuthConfigRequest>,
    ) -> Result<Response<GetAuthConfigResponse>, Status> {
        let caller = caller::resolve(&request, &self.0.cas)?;
        self.0.limits.check_unauthenticated(caller.addr())?;
        let c = &self.0.config;
        Ok(Response::new(GetAuthConfigResponse {
            issuer_url: c.oidc_issuer.clone(),
            client_id: c.oidc_client_id.clone(),
            scopes: c.oidc_scopes.clone(),
            server_version: limen_core::VERSION.to_owned(),
        }))
    }

    async fn login(
        &self,
        request: Request<LoginRequest>,
    ) -> Result<Response<LoginResponse>, Status> {
        let caller = caller::resolve(&request, &self.0.cas)?;
        self.0.limits.check_unauthenticated(caller.addr())?;
        login(self.0.clone(), caller.addr(), request.into_inner())
            .await
            .map(Response::new)
    }

    async fn who_am_i(
        &self,
        request: Request<WhoAmIRequest>,
    ) -> Result<Response<WhoAmIResponse>, Status> {
        let caller = caller::resolve(&request, &self.0.cas)?;
        let user = caller.user()?;
        Ok(Response::new(WhoAmIResponse {
            username: user.username.clone(),
            roles: user.roles.clone(),
            login_id: user.login_id.clone(),
            expires_at_unix: unix(user.not_after),
        }))
    }
}

/// The CSR's SubjectPublicKeyInfo DER. A plain function so the parsed CSR
/// isn't held across awaits in `login`.
fn csr_spki(csr_der: &[u8]) -> Result<Vec<u8>, Status> {
    let csr =
        CertificateSigningRequestParams::from_der(&CertificateSigningRequestDer::from(csr_der))
            .map_err(|e| Status::invalid_argument(format!("invalid CSR: {e}")))?;
    Ok(rcgen::PublicKeyData::subject_public_key_info(
        &csr.public_key,
    ))
}

/// The login flow. A free function over owned values: borrowing `self`
/// across these awaits trips a rustc higher-ranked `Send` inference
/// limitation inside `async_trait`.
async fn login(
    state: AppState,
    addr: Option<IpAddr>,
    req: LoginRequest,
) -> Result<LoginResponse, Status> {
    let flow = LoginFlow::try_from(req.flow).unwrap_or(LoginFlow::Unspecified);
    if flow == LoginFlow::Unspecified {
        return Err(Status::invalid_argument("login flow must be set"));
    }
    if req.nonce_salt.len() < 16 || req.nonce_salt.len() > 64 {
        return Err(Status::invalid_argument("nonce_salt must be 16..=64 bytes"));
    }
    let expected = expected_nonce(&csr_spki(&req.csr_der)?, &req.nonce_salt);

    // Device flow can't carry our nonce (threat model TB0). Replay is
    // still prevented below by recording the token itself.
    let required_nonce = (flow == LoginFlow::Pkce).then(|| expected.clone());
    let identity = match state
        .oidc
        .verify(req.id_token.clone(), required_nonce)
        .await
    {
        Ok(id) => id,
        Err(crate::oidc::OidcError::Unavailable(e)) => {
            tracing::error!(error = %e, "identity provider unavailable");
            return Err(Status::unavailable("identity provider unavailable"));
        }
        Err(crate::oidc::OidcError::Invalid(e)) => {
            tracing::info!(error = %e, "rejected ID token");
            return Err(deny(state.audit.clone(), addr, None, "invalid ID token").await);
        }
    };

    // One login per ID token: record the nonce (PKCE) or the token hash (device).
    let replay_key = match flow {
        LoginFlow::Pkce => sha256(expected.as_bytes()),
        _ => sha256(req.id_token.as_bytes()),
    };
    let fresh = crate::db::use_nonce(state.db.clone(), replay_key, identity.expires_at)
        .await
        .map_err(|e| internal("recording login nonce", e))?;
    if !fresh {
        return Err(deny(
            state.audit.clone(),
            addr,
            Some(identity.username),
            "ID token already used",
        )
        .await);
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
    if roles.is_empty() {
        return Err(deny(
            state.audit.clone(),
            addr,
            Some(identity.username),
            "no roles are mapped to the user's groups",
        )
        .await);
    }
    let ttl = loaded.policy.cert_ttl(&roles, state.config.max_cert_ttl);
    let login_id = Uuid::now_v7();
    let issued = state
        .cas
        .user
        .issue_user(UserCertRequest {
            csr_der: req.csr_der,
            username: identity.username.clone(),
            roles: roles.clone(),
            login_id,
            ttl,
        })
        .await
        .map_err(|e| match e {
            limen_ca::CaError::InvalidCsr(m) | limen_ca::CaError::InvalidRequest(m) => {
                Status::invalid_argument(m)
            }
            other => internal("issuing user certificate", other),
        })?;

    // Fail closed: no audit event, no credentials.
    let data = json!({
        "login_id": login_id,
        "flow": match flow { LoginFlow::Device => "device", _ => "pkce" },
        "idp_subject": identity.subject,
        "groups": identity.groups,
        "roles": roles,
        "cert_serial": issued.serial_hex,
        "expires_at": unix(issued.not_after),
        "client_addr": addr.map(|a| a.to_string()),
    });
    state
        .audit
        .emit(
            EventKind::AuthLogin,
            Context {
                user: Some(identity.username.clone()),
                session_id: None,
            },
            data,
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "audit unavailable; refusing login");
            Status::unavailable("audit unavailable")
        })?;
    metrics::counter!("limen_logins_total", "outcome" => "success").increment(1);
    tracing::info!(user = %identity.username, ?roles, ttl_secs = ttl.as_secs(), "login");

    Ok(LoginResponse {
        username: identity.username,
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
