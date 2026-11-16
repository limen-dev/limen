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

/// Why an API call from a person or bot is refused, given what the database
/// says about their account and login: `(audit reason, message)`, or `None`
/// to let it through. A lock wins over an ended login. The scheduled
/// self-test (ADR-0053) checks this very function.
#[must_use]
pub fn refusal(locked: bool, ended: bool) -> Option<(&'static str, &'static str)> {
    match (locked, ended) {
        (false, false) => None,
        (true, _) => Some(("user locked", "user locked")),
        (false, true) => Some(("logged out", "this login has ended; run `limen login`")),
    }
}

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
    let caller = resolve_checked(request, state).await?;
    let Caller::User { identity, addr } = &caller else {
        return Ok(caller);
    };
    let (locked, ended) =
        crate::db::lock_and_logout(&state.db, &identity.username, &identity.login_id)
            .await
            .map_err(|e| internal("checking locks", e))?;
    let Some((reason, message)) = refusal(locked, ended) else {
        return Ok(caller);
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

/// Resolve the caller of `request` and refuse a component (or the proxy
/// relaying for someone) that has been revoked, while its certificate is still
/// valid. Every service a component calls uses this.
pub async fn resolve_checked<T>(
    request: &tonic::Request<T>,
    state: &AppState,
) -> Result<Caller, Status> {
    let (caller, direct) = resolve_with_peer(request, &state.cas)?;
    let mut ids: Vec<&str> = direct.as_deref().into_iter().collect();
    if let Caller::Component { identity, .. } = &caller {
        ids.push(&identity.id);
    }
    for id in ids {
        let revoked = state
            .revoked
            .is_revoked(id, || crate::db::revoked_components(&state.db))
            .await
            .map_err(|e| internal("checking revoked components", e))?;
        if revoked {
            tracing::warn!(component = %id, "API call refused: the component was revoked");
            return Err(Status::permission_denied("this component was revoked"));
        }
    }
    Ok(caller)
}

/// Resolve the caller of `request`.
pub fn resolve<T>(request: &tonic::Request<T>, cas: &Cas) -> Result<Caller, Status> {
    resolve_with_peer(request, cas).map(|(caller, _)| caller)
}

/// [`resolve`], and the id of the component on the other end of the TLS
/// connection (the proxy, when it relays for someone).
fn resolve_with_peer<T>(
    request: &tonic::Request<T>,
    cas: &Cas,
) -> Result<(Caller, Option<String>), Status> {
    let peer = request
        .extensions()
        .get::<PeerInfo>()
        .ok_or_else(|| Status::internal("missing peer info"))?;
    let direct = match peer.leaf() {
        // The listener trusts only the internal CA, so any presented cert is a component's.
        Some(leaf) => Some(
            verify_component(leaf, cas.internal.cert_der(), false)
                .map_err(|e| Status::unauthenticated(e.to_string()))?,
        ),
        None => None,
    };
    let direct_id = direct.as_ref().map(|d| d.id.clone());
    let caller = resolve_caller(peer, request.metadata(), cas, direct)?;
    Ok((caller, direct_id))
}

fn resolve_caller(
    peer: &PeerInfo,
    metadata: &tonic::metadata::MetadataMap,
    cas: &Cas,
    direct: Option<ComponentIdentity>,
) -> Result<Caller, Status> {
    let direct_addr = peer.remote_addr.map(|a: SocketAddr| a.ip());
    let forwarded = metadata.get(relay::FORWARDED).is_some();

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

#[cfg(test)]
mod tests {
    //! Who a request is from, with no database: the forwarding rules a proxy
    //! relays under, and the role gates services call.

    use std::sync::Arc;
    use std::time::Duration;

    use limen_ca::ssh::SshCa;
    use limen_ca::{
        CaPurpose, CertificateAuthority, ComponentCertRequest, FileSigner, UserCertRequest,
    };
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
    use tonic::Code;

    use super::*;

    async fn ca(purpose: CaPurpose) -> CertificateAuthority {
        CertificateAuthority::create_self_signed(
            purpose,
            Arc::new(FileSigner::generate().expect("key")),
        )
        .await
        .expect("ca")
    }

    async fn cas() -> Cas {
        let ssh = |purpose| {
            SshCa::new(purpose, Arc::new(FileSigner::generate().expect("key"))).expect("ssh ca")
        };
        Cas {
            internal: ca(CaPurpose::Internal).await,
            user: ca(CaPurpose::UserX509).await,
            ssh_user: ssh(CaPurpose::UserSsh),
            ssh_host: ssh(CaPurpose::HostSsh),
        }
    }

    fn csr() -> Vec<u8> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
        CertificateParams::default()
            .serialize_request(&key)
            .expect("csr")
            .der()
            .to_vec()
    }

    async fn component(
        ca: &CertificateAuthority,
        kind: ComponentKind,
        id: &str,
    ) -> CertificateDer<'static> {
        ca.issue_component(ComponentCertRequest {
            csr_der: csr(),
            kind,
            id: id.into(),
            dns_names: vec![],
            labels: std::collections::BTreeMap::new(),
            ttl: Duration::from_secs(300),
        })
        .await
        .expect("component cert")
        .der
    }

    async fn user(
        ca: &CertificateAuthority,
        name: &str,
        roles: &[&str],
    ) -> CertificateDer<'static> {
        ca.issue_user(UserCertRequest {
            csr_der: csr(),
            username: name.into(),
            roles: roles.iter().map(|r| (*r).to_owned()).collect(),
            login_id: uuid::Uuid::now_v7(),
            ttl: Duration::from_secs(300),
            ci: None,
        })
        .await
        .expect("user cert")
        .der
    }

    fn b64(cert: &CertificateDer<'_>) -> String {
        base64::engine::general_purpose::STANDARD.encode(cert.as_ref())
    }

    const PEER: &str = "198.51.100.1:443";
    const CLIENT: &str = "203.0.113.7:51000";

    /// A request on a connection whose TLS peer presented `leaf`, optionally
    /// marked as relayed and carrying a forwarded certificate.
    fn request(
        leaf: Option<&CertificateDer<'static>>,
        forwarded: bool,
        client_cert: Option<&str>,
    ) -> tonic::Request<()> {
        let mut req = tonic::Request::new(());
        req.extensions_mut().insert(PeerInfo {
            remote_addr: Some(PEER.parse().expect("addr")),
            server_name: None,
            client_certs: leaf.cloned().into_iter().collect(),
        });
        let md = req.metadata_mut();
        if forwarded {
            md.insert(relay::FORWARDED, "1".parse().expect("ascii"));
            md.insert(relay::CLIENT_ADDR, CLIENT.parse().expect("ascii"));
        }
        if let Some(cert) = client_cert {
            md.insert(relay::CLIENT_CERT, cert.parse().expect("ascii"));
        }
        req
    }

    fn refused(result: Result<Caller, Status>, code: Code, needle: &str) {
        match result {
            Ok(caller) => panic!("expected {code:?} ({needle}), resolved {caller:?}"),
            Err(s) => {
                assert_eq!(s.code(), code, "{s:?}");
                assert!(s.message().contains(needle), "{s:?} lacks {needle:?}");
            }
        }
    }

    #[tokio::test]
    async fn direct_callers_resolve_from_the_tls_peer_only() {
        let cas = cas().await;
        let anon = resolve(&request(None, false, None), &cas).expect("anonymous");
        assert!(matches!(anon, Caller::Anonymous { .. }));
        assert_eq!(
            anon.addr(),
            Some(PEER.parse::<SocketAddr>().expect("a").ip())
        );

        let worker = component(&cas.internal, ComponentKind::Worker, "w1").await;
        let caller = resolve(&request(Some(&worker), false, None), &cas).expect("worker");
        assert!(
            matches!(&caller, Caller::Component { identity, via_proxy: false, .. }
                if identity.kind == ComponentKind::Worker && identity.id == "w1"),
            "{caller:?}"
        );

        // A client certificate the internal CA didn't issue is not a caller,
        // even one from Limen's own user CA.
        let rogue = ca(CaPurpose::Internal).await;
        let stranger = component(&rogue, ComponentKind::Proxy, "p1").await;
        refused(
            resolve(&request(Some(&stranger), false, None), &cas),
            Code::Unauthenticated,
            "",
        );
        let person = user(&cas.user, "ada", &[ADMIN_ROLE]).await;
        refused(
            resolve(&request(Some(&person), false, None), &cas),
            Code::Unauthenticated,
            "",
        );
        // No peer info at all is a server bug, never an anonymous caller.
        refused(
            resolve(&tonic::Request::new(()), &cas),
            Code::Internal,
            "peer info",
        );
    }

    #[tokio::test]
    async fn only_a_direct_proxy_may_forward_a_request() {
        let cas = cas().await;
        let admin = b64(&user(&cas.user, "ada", &[ADMIN_ROLE]).await);
        // No certificate, or a worker's or control plane's: the forwarded
        // admin certificate must not be believed.
        refused(
            resolve(&request(None, true, Some(&admin)), &cas),
            Code::PermissionDenied,
            "only proxies may forward",
        );
        for kind in [ComponentKind::Worker, ComponentKind::ControlPlane] {
            let leaf = component(&cas.internal, kind, "c1").await;
            refused(
                resolve(&request(Some(&leaf), true, Some(&admin)), &cas),
                Code::PermissionDenied,
                "only proxies may forward",
            );
        }
        // The marker alone, without a forwarded certificate, is refused too.
        refused(
            resolve(&request(None, true, None), &cas),
            Code::PermissionDenied,
            "only proxies may forward",
        );
    }

    #[tokio::test]
    async fn a_proxy_forwards_users_and_workers_but_no_other_component() {
        let cas = cas().await;
        let proxy = component(&cas.internal, ComponentKind::Proxy, "p1").await;
        let client_ip = CLIENT.parse::<SocketAddr>().expect("a").ip();

        let person = b64(&user(&cas.user, "ada", &["dev"]).await);
        let caller = resolve(&request(Some(&proxy), true, Some(&person)), &cas).expect("user");
        assert!(
            matches!(&caller, Caller::User { identity, .. } if identity.username == "ada"),
            "{caller:?}"
        );
        assert_eq!(
            caller.addr(),
            Some(client_ip),
            "the client's address, not the proxy's"
        );

        let worker = b64(&component(&cas.internal, ComponentKind::Worker, "w1").await);
        let caller = resolve(&request(Some(&proxy), true, Some(&worker)), &cas).expect("worker");
        assert!(
            matches!(&caller, Caller::Component { identity, via_proxy: true, .. }
                if identity.kind == ComponentKind::Worker),
            "{caller:?}"
        );

        // A proxy can't relay as another proxy or as the control plane.
        for kind in [ComponentKind::Proxy, ComponentKind::ControlPlane] {
            let other = b64(&component(&cas.internal, kind, "x1").await);
            refused(
                resolve(&request(Some(&proxy), true, Some(&other)), &cas),
                Code::PermissionDenied,
                "only worker certificates may be forwarded",
            );
        }

        // Relayed with no client certificate (login through the proxy).
        let caller = resolve(&request(Some(&proxy), true, None), &cas).expect("anonymous");
        assert!(matches!(caller, Caller::Anonymous { .. }), "{caller:?}");
        assert_eq!(caller.addr(), Some(client_ip));
    }

    #[tokio::test]
    async fn a_forwarded_certificate_is_bounded_decoded_and_verified() {
        let cas = cas().await;
        let proxy = component(&cas.internal, ComponentKind::Proxy, "p1").await;
        let via_proxy = |cert: &str| resolve(&request(Some(&proxy), true, Some(cert)), &cas);

        // At the limit the value is decoded and judged as a certificate;
        // one byte over it is refused before decoding.
        let at_limit = "A".repeat(MAX_FORWARDED_CERT_LEN);
        refused(
            via_proxy(&at_limit),
            Code::Unauthenticated,
            "forwarded certificate rejected",
        );
        let over = "A".repeat(MAX_FORWARDED_CERT_LEN + 1);
        refused(via_proxy(&over), Code::InvalidArgument, "too large");

        refused(
            via_proxy("not*base64!"),
            Code::InvalidArgument,
            "malformed forwarded certificate",
        );

        // Signed by CAs Limen doesn't use: neither a user nor a worker.
        let rogue_user = ca(CaPurpose::UserX509).await;
        let forged = b64(&user(&rogue_user, "ada", &[ADMIN_ROLE]).await);
        refused(
            via_proxy(&forged),
            Code::Unauthenticated,
            "forwarded certificate rejected",
        );
        let rogue_internal = ca(CaPurpose::Internal).await;
        let forged = b64(&component(&rogue_internal, ComponentKind::Worker, "w1").await);
        refused(
            via_proxy(&forged),
            Code::Unauthenticated,
            "forwarded certificate rejected",
        );
    }

    #[tokio::test]
    async fn role_gates_refuse_the_wrong_kind_of_caller() {
        let cas = cas().await;
        let proxy = component(&cas.internal, ComponentKind::Proxy, "p1").await;
        let worker = component(&cas.internal, ComponentKind::Worker, "w1").await;
        let as_user = |roles: &'static [&'static str]| {
            let cas = &cas;
            let proxy = &proxy;
            async move {
                let cert = b64(&user(&cas.user, "ada", roles).await);
                resolve(&request(Some(proxy), true, Some(&cert)), cas).expect("user")
            }
        };
        let anonymous = resolve(&request(None, false, None), &cas).expect("anonymous");
        let direct_proxy = resolve(&request(Some(&proxy), false, None), &cas).expect("proxy");
        let direct_worker = resolve(&request(Some(&worker), false, None), &cas).expect("worker");
        let relayed_worker =
            resolve(&request(Some(&proxy), true, Some(&b64(&worker))), &cas).expect("relayed");
        let plain = as_user(&["dev"]).await;
        let auditor = as_user(&[AUDITOR_ROLE]).await;
        let admin = as_user(&[ADMIN_ROLE]).await;

        // Only a proxy on its own connection is a direct proxy: not a worker,
        // and not a worker the proxy relays for.
        assert_eq!(direct_proxy.direct_proxy().expect("proxy").id, "p1");
        // `resolve` never yields a relayed proxy, but if a caller were one it
        // must still not count as calling directly.
        let relayed_proxy = Caller::Component {
            identity: direct_proxy.component().expect("proxy").clone(),
            addr: None,
            via_proxy: true,
        };
        for c in [
            &direct_worker,
            &relayed_worker,
            &relayed_proxy,
            &anonymous,
            &admin,
        ] {
            assert_eq!(
                c.direct_proxy().expect_err("not a proxy").code(),
                Code::PermissionDenied,
                "{c:?}"
            );
        }

        for c in [&anonymous, &direct_proxy, &relayed_worker] {
            assert_eq!(c.user().expect_err("no user").code(), Code::Unauthenticated);
            assert_eq!(
                c.admin().expect_err("no user").code(),
                Code::Unauthenticated
            );
            assert_eq!(
                c.reader().expect_err("no user").code(),
                Code::Unauthenticated
            );
        }
        for c in [&anonymous, &plain] {
            assert_eq!(
                c.component().expect_err("no component").code(),
                Code::Unauthenticated
            );
        }

        assert_eq!(
            plain.admin().expect_err("dev").code(),
            Code::PermissionDenied
        );
        assert_eq!(
            plain.reader().expect_err("dev").code(),
            Code::PermissionDenied
        );
        assert_eq!(
            auditor.admin().expect_err("auditor").code(),
            Code::PermissionDenied
        );
        assert!(auditor.reader().is_ok());
        assert!(admin.admin().is_ok() && admin.reader().is_ok());
    }

    #[test]
    fn a_lock_wins_over_an_ended_login_and_neither_lets_a_call_through() {
        assert_eq!(refusal(false, false), None);
        assert_eq!(refusal(true, false).map(|r| r.0), Some("user locked"));
        assert_eq!(refusal(true, true).map(|r| r.0), Some("user locked"));
        assert_eq!(refusal(false, true).map(|r| r.0), Some("logged out"));
    }
}
