//! Session grants (ADR-0002): a proxy's signed statement that a user may
//! open a session to a resource as a principal, until a deadline.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use limen_ca::verify::{ComponentIdentity, UserIdentity, verify_user};
use limen_proto::v1::{SessionGrant, Signed};
use prost::Message as _;
use rustls_pki_types::CertificateDer;
use time::OffsetDateTime;

use crate::SessionError;
use crate::envelope::{EnvelopeSigner, Purpose, verify};

/// How long a grant may take to be used. Sessions themselves can last much
/// longer (`session_expires_at`).
pub const ESTABLISH_WITHIN: Duration = Duration::from_secs(60);
const CLOCK_SKEW_SECS: i64 = 120;

/// A grant whose signature, deadline, and user certificate checked out.
#[derive(Debug, Clone)]
pub struct VerifiedGrant {
    pub grant: SessionGrant,
    pub proxy: ComponentIdentity,
    pub user: UserIdentity,
}

pub fn sign(signer: &EnvelopeSigner, grant: &SessionGrant) -> Result<Signed, SessionError> {
    signer.sign(Purpose::SessionGrant, grant.encode_to_vec())
}

/// Verify a grant: signed by a proxy, inside its establish window, and
/// carrying a valid user certificate whose identity and roles match it.
/// Replay protection is the caller's job (see [`NonceCache`]), because the
/// control plane records nonces in its database instead.
pub fn verify_grant(
    signed: &Signed,
    internal_ca: &CertificateDer<'_>,
    user_ca: &CertificateDer<'_>,
    now: OffsetDateTime,
) -> Result<VerifiedGrant, SessionError> {
    let (proxy, payload) = verify(signed, Purpose::SessionGrant, internal_ca)?;
    let grant =
        SessionGrant::decode(payload).map_err(|e| SessionError::Malformed(e.to_string()))?;
    let now = now.unix_timestamp();
    if grant.issued_at_unix > now + CLOCK_SKEW_SECS {
        return Err(SessionError::Grant("issued in the future".into()));
    }
    if now > grant.establish_by_unix {
        return Err(SessionError::Grant("expired".into()));
    }
    if grant.proxy_id != proxy.id {
        return Err(SessionError::Grant(
            "proxy ID doesn't match the signer".into(),
        ));
    }
    if grant.nonce.len() < 16 {
        return Err(SessionError::Grant("nonce too short".into()));
    }
    let user = verify_user(
        &CertificateDer::from(grant.user_cert_der.as_slice()),
        user_ca,
    )
    .map_err(|e| SessionError::Grant(format!("user certificate: {e}")))?;
    if user.username != grant.username
        || user.roles != grant.roles
        || user.login_id != grant.login_id
    {
        return Err(SessionError::Grant(
            "identity doesn't match the user certificate".into(),
        ));
    }
    Ok(VerifiedGrant { grant, proxy, user })
}

/// Remembers grant nonces until they expire, so each grant opens one session.
#[derive(Debug, Default)]
pub struct NonceCache {
    seen: Mutex<HashMap<Vec<u8>, i64>>,
}

const MAX_NONCES: usize = 100_000;

impl NonceCache {
    /// `true` the first time a nonce is seen, `false` on replay.
    pub fn check_and_insert(&self, nonce: &[u8], expires_at_unix: i64) -> bool {
        let mut seen = self
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = OffsetDateTime::now_utc().unix_timestamp();
        if seen.len() >= MAX_NONCES {
            seen.retain(|_, exp| *exp >= now);
        }
        if seen.len() >= MAX_NONCES {
            // Fail closed rather than forget nonces that may still be valid.
            return false;
        }
        seen.insert(nonce.to_vec(), expires_at_unix).is_none()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use limen_ca::{
        CaPurpose, CertificateAuthority, ComponentCertRequest, FileSigner, UserCertRequest,
    };
    use limen_core::identity::ComponentKind;
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

    use super::*;

    struct Fixture {
        internal: CertificateAuthority,
        user_ca: CertificateAuthority,
    }

    async fn fixture() -> Fixture {
        Fixture {
            internal: CertificateAuthority::create_self_signed(
                CaPurpose::Internal,
                Arc::new(FileSigner::generate().expect("k")),
            )
            .await
            .expect("ca"),
            user_ca: CertificateAuthority::create_self_signed(
                CaPurpose::UserX509,
                Arc::new(FileSigner::generate().expect("k")),
            )
            .await
            .expect("ca"),
        }
    }

    async fn component(ca: &CertificateAuthority, kind: ComponentKind, id: &str) -> EnvelopeSigner {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
        let csr = CertificateParams::default()
            .serialize_request(&key)
            .expect("csr");
        let cert = ca
            .issue_component(ComponentCertRequest {
                csr_der: csr.der().to_vec(),
                kind,
                id: id.into(),
                dns_names: vec![],
                labels: std::collections::BTreeMap::new(),
                ttl: Duration::from_secs(600),
            })
            .await
            .expect("issue");
        EnvelopeSigner::new(&key.serialize_pem(), cert.der.to_vec()).expect("signer")
    }

    async fn user_cert(ca: &CertificateAuthority) -> (Vec<u8>, String) {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
        let csr = CertificateParams::default()
            .serialize_request(&key)
            .expect("csr");
        let login = uuid::Uuid::now_v7();
        let cert = ca
            .issue_user(UserCertRequest {
                csr_der: csr.der().to_vec(),
                username: "developer".into(),
                roles: vec!["dev".into()],
                login_id: login,
                ttl: Duration::from_secs(600),
                ci: None,
            })
            .await
            .expect("issue");
        (cert.der.to_vec(), login.to_string())
    }

    fn grant(user_cert_der: Vec<u8>, login_id: String, proxy_id: &str) -> SessionGrant {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        SessionGrant {
            session_id: "s1".into(),
            username: "developer".into(),
            roles: vec!["dev".into()],
            login_id,
            resource: "web-1".into(),
            kind: "ssh".into(),
            principal: "ubuntu".into(),
            issued_at_unix: now,
            establish_by_unix: now + 60,
            session_expires_at_unix: now + 3600,
            nonce: vec![7; 32],
            user_cert_der,
            proxy_id: proxy_id.into(),
            worker_id: "w1".into(),
            database: String::new(),
        }
    }

    #[tokio::test]
    async fn valid_grant_verifies() {
        let f = fixture().await;
        let proxy = component(&f.internal, ComponentKind::Proxy, "p1").await;
        let (cert, login) = user_cert(&f.user_ca).await;
        let signed = sign(&proxy, &grant(cert, login, "p1")).expect("sign");
        let v = verify_grant(
            &signed,
            f.internal.cert_der(),
            f.user_ca.cert_der(),
            OffsetDateTime::now_utc(),
        )
        .expect("verify");
        assert_eq!(v.user.username, "developer");
        assert_eq!(v.proxy.id, "p1");
    }

    #[tokio::test]
    async fn rejects_tampering_wrong_signer_expiry_and_identity_mismatch() {
        let f = fixture().await;
        let proxy = component(&f.internal, ComponentKind::Proxy, "p1").await;
        let worker = component(&f.internal, ComponentKind::Worker, "w1").await;
        let (cert, login) = user_cert(&f.user_ca).await;
        let now = OffsetDateTime::now_utc();
        let check =
            |s: &Signed, at| verify_grant(s, f.internal.cert_der(), f.user_ca.cert_der(), at);

        let mut tampered = sign(&proxy, &grant(cert.clone(), login.clone(), "p1")).expect("sign");
        let last = tampered.payload.len() - 1;
        tampered.payload[last] ^= 1;
        assert!(check(&tampered, now).is_err(), "tampered payload");

        let by_worker = sign(&worker, &grant(cert.clone(), login.clone(), "w1")).expect("sign");
        assert!(
            matches!(check(&by_worker, now), Err(SessionError::Signature(_))),
            "workers can't sign grants"
        );

        let good = sign(&proxy, &grant(cert.clone(), login.clone(), "p1")).expect("sign");
        assert!(
            check(&good, now + time::Duration::minutes(5)).is_err(),
            "expired"
        );

        let mut escalated = grant(cert.clone(), login.clone(), "p1");
        escalated.roles = vec!["admin".into()];
        assert!(
            check(&sign(&proxy, &escalated).expect("sign"), now).is_err(),
            "roles must match the user cert"
        );

        let wrong_proxy = sign(&proxy, &grant(cert, login, "p2")).expect("sign");
        assert!(
            check(&wrong_proxy, now).is_err(),
            "proxy_id must match the signer"
        );

        // A snapshot-purpose signature can't pass as a grant.
        let cp = component(&f.internal, ComponentKind::ControlPlane, "cp").await;
        let snapshot_sig = cp
            .sign(Purpose::PolicySnapshot, good.payload.clone())
            .expect("sign");
        assert!(check(&snapshot_sig, now).is_err(), "domain separation");
    }

    #[test]
    fn nonce_cache_rejects_replays() {
        let cache = NonceCache::default();
        assert!(cache.check_and_insert(b"0123456789abcdef", i64::MAX));
        assert!(!cache.check_and_insert(b"0123456789abcdef", i64::MAX));
        assert!(cache.check_and_insert(b"fedcba9876543210", i64::MAX));
    }
}
