//! Who is calling: resolved from the TLS peer and, for requests a proxy
//! relays, from the client certificate it forwards (design §3).

use std::net::{IpAddr, SocketAddr};

use base64::Engine as _;
use limen_audit::{Context, EventKind};
use limen_ca::verify::{ComponentIdentity, UserIdentity, verify_component, verify_user};
use limen_core::identity::{ADMIN_ROLE, AUDITOR_ROLE, ComponentKind};
use limen_proto::relay;
use limen_tunnel::PeerInfo;
use rustls_pki_types::CertificateDer;
use serde_json::json;
use tonic::Status;

use crate::ca_store::Cas;
use crate::state::{AppState, internal};

#[derive(Debug, Clone)]
pub enum Caller {
    /// No certificate. Allowed only on login and enrollment.
    Anonymous { addr: Option<IpAddr> },
    User {
        identity: UserIdentity,
        addr: Option<IpAddr>,
    },
    Component {
        identity: ComponentIdentity,
        addr: Option<IpAddr>,
        via_proxy: bool,
    },
}

impl Caller {
    #[must_use]
    pub fn addr(&self) -> Option<IpAddr> {
        match self {
            Caller::Anonymous { addr }
            | Caller::User { addr, .. }
            | Caller::Component { addr, .. } => *addr,
        }
    }

    /// Name for audit events and logs.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Caller::Anonymous { .. } => "anonymous".into(),
            Caller::User { identity, .. } => identity.username.clone(),
            Caller::Component { identity, .. } => format!("{}:{}", identity.kind, identity.id),
        }
    }

    pub fn user(&self) -> Result<&UserIdentity, Status> {
        match self {
            Caller::User { identity, .. } => Ok(identity),
            _ => Err(Status::unauthenticated(
                "a user certificate is required; run `limen login`",
            )),
        }
    }

    pub fn admin(&self) -> Result<&UserIdentity, Status> {
        let user = self.user()?;
        if user.has_role(ADMIN_ROLE) {
            Ok(user)
        } else {
            Err(Status::permission_denied(format!(
                "the {ADMIN_ROLE} role is required"
            )))
        }
    }

    /// An admin or an auditor: someone who may read the record (ADR-0026).
    pub fn reader(&self) -> Result<&UserIdentity, Status> {
        let user = self.user()?;
        if user.has_role(ADMIN_ROLE) || user.has_role(AUDITOR_ROLE) {
            Ok(user)
        } else {
            Err(Status::permission_denied(format!(
                "the {ADMIN_ROLE} or {AUDITOR_ROLE} role is required"
            )))
        }
    }

    pub fn component(&self) -> Result<&ComponentIdentity, Status> {
        match self {
            Caller::Component { identity, .. } => Ok(identity),
            _ => Err(Status::unauthenticated(
                "a component certificate is required",
            )),
        }
    }

    /// A proxy talking to us directly, not on someone's behalf.
    pub fn direct_proxy(&self) -> Result<&ComponentIdentity, Status> {
        match self {
            Caller::Component {
                identity,
                via_proxy: false,
                ..
            } if identity.kind == ComponentKind::Proxy => Ok(identity),
            _ => Err(Status::permission_denied("only proxies may call this")),
        }
    }
}

const MAX_FORWARDED_CERT_LEN: usize = 8 * 1024;

/// Resolve the caller of `request` and refuse a person or bot whose account
/// is locked, or whose login has ended (`limen logout`), while their
/// certificate is still valid. Locks and ended logins are read from the
/// database, so they take effect on the next call. Every service a user
/// calls uses this; [`resolve`] is for login, logout, `WhoAmI`, and
/// component callers.
pub async fn resolve_current<T>(
    request: &tonic::Request<T>,
    state: &AppState,
) -> Result<Caller, Status> {
    let caller = resolve(request, &state.cas)?;
    let Caller::User { identity, addr } = &caller else {
        return Ok(caller);
    };
    let (locked, ended) =
        crate::db::lock_and_logout(&state.db, &identity.username, &identity.login_id)
            .await
            .map_err(|e| internal("checking locks", e))?;
    let (reason, message) = match (locked, ended) {
        (false, false) => return Ok(caller),
        (true, _) => ("user locked", "user locked"),
        (false, true) => ("logged out", "this login has ended; run `limen login`"),
    };
    tracing::warn!(user = %identity.username, client_addr = ?addr, reason, "API call refused");
    let data = json!({
        "action": "api",
        "reason": reason,
        "login_id": identity.login_id,
        "client_addr": addr.map(|a| a.to_string()),
    });
    let context = Context {
        user: Some(identity.username.clone()),
        session_id: None,
    };
    if let Err(e) = state.audit.emit(EventKind::AuthDenied, context, data).await {
        tracing::error!(error = %e, "failed to audit a refused API call");
    }
    Err(Status::permission_denied(message))
}

/// Resolve the caller of `request`.
pub fn resolve<T>(request: &tonic::Request<T>, cas: &Cas) -> Result<Caller, Status> {
    let peer = request
        .extensions()
        .get::<PeerInfo>()
        .ok_or_else(|| Status::internal("missing peer info"))?;
    let direct_addr = peer.remote_addr.map(|a: SocketAddr| a.ip());
    let metadata = request.metadata();
    let forwarded = metadata.get(relay::FORWARDED).is_some();

    let direct = match peer.leaf() {
        // The listener trusts only the internal CA, so any presented cert is a component's.
        Some(leaf) => Some(
            verify_component(leaf, cas.internal.cert_der(), false)
                .map_err(|e| Status::unauthenticated(e.to_string()))?,
        ),
        None => None,
    };

    match (direct, forwarded) {
        (None, false) => Ok(Caller::Anonymous { addr: direct_addr }),
        (None, true) => Err(Status::permission_denied(
            "only proxies may forward requests",
        )),
        (Some(identity), false) => Ok(Caller::Component {
            identity,
            addr: direct_addr,
            via_proxy: false,
        }),
        (Some(proxy), true) => {
            if proxy.kind != ComponentKind::Proxy {
                return Err(Status::permission_denied(
                    "only proxies may forward requests",
                ));
            }
            let addr = metadata
                .get(relay::CLIENT_ADDR)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<SocketAddr>().ok())
                .map(|a| a.ip());
            let Some(encoded) = metadata.get(relay::CLIENT_CERT) else {
                return Ok(Caller::Anonymous { addr });
            };
            let encoded = encoded.as_bytes();
            if encoded.len() > MAX_FORWARDED_CERT_LEN {
                return Err(Status::invalid_argument("forwarded certificate too large"));
            }
            let der = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| Status::invalid_argument("malformed forwarded certificate"))?;
            let cert = CertificateDer::from(der);
            // A forwarded cert is either a user's (user CA) or a worker's (internal CA).
            if let Ok(identity) = verify_user(&cert, cas.user.cert_der()) {
                return Ok(Caller::User { identity, addr });
            }
            match verify_component(&cert, cas.internal.cert_der(), false) {
                Ok(identity) if identity.kind == ComponentKind::Worker => Ok(Caller::Component {
                    identity,
                    addr,
                    via_proxy: true,
                }),
                Ok(_) => Err(Status::permission_denied(
                    "only worker certificates may be forwarded",
                )),
                Err(e) => Err(Status::unauthenticated(format!(
                    "forwarded certificate rejected: {e}"
                ))),
            }
        }
    }
}
