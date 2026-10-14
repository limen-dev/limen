//! Signed policy snapshots (ADR-0008) and the cache proxies and workers
//! decide from. A snapshot's age is the time since the control plane last
//! answered; past the grace period, decisions fail closed (ADR-0011).

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use limen_policy::Policy;
use limen_proto::v1::{PolicySnapshot, Signed};
use prost::Message as _;
use rustls_pki_types::CertificateDer;
use time::OffsetDateTime;

use crate::SessionError;
use crate::envelope::{EnvelopeSigner, Purpose, verify};

/// Default grace period (ADR-0011).
pub const DEFAULT_GRACE: Duration = Duration::from_mins(5);

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub version: i64,
    pub issued_at: OffsetDateTime,
    pub policy: Arc<Policy>,
    pub restrictions: Arc<Restrictions>,
}

/// What admins have shut off, carried next to the policy (ADR-0017).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Restrictions {
    pub locked_users: BTreeSet<String>,
    pub killed_sessions: BTreeSet<String>,
}

impl Restrictions {
    /// Why this session must not continue, if it must not.
    #[must_use]
    pub fn blocks(&self, username: &str, session_id: &str) -> Option<&'static str> {
        if self.locked_users.contains(username) {
            Some("user locked")
        } else if self.killed_sessions.contains(session_id) {
            Some("session killed")
        } else {
            None
        }
    }
}

pub fn sign(
    signer: &EnvelopeSigner,
    version: i64,
    policy: &Policy,
    restrictions: &Restrictions,
    issued_at: OffsetDateTime,
) -> Result<Signed, SessionError> {
    let documents_json = serde_json::to_string(&policy.documents())
        .map_err(|e| SessionError::Malformed(e.to_string()))?;
    let snapshot = PolicySnapshot {
        version,
        issued_at_unix: issued_at.unix_timestamp(),
        documents_json,
        locked_users: restrictions.locked_users.iter().cloned().collect(),
        killed_sessions: restrictions.killed_sessions.iter().cloned().collect(),
    };
    signer.sign(Purpose::PolicySnapshot, snapshot.encode_to_vec())
}

/// Verify a snapshot signed by a control plane and compile its policy.
pub fn verify_snapshot(
    signed: &Signed,
    internal_ca: &CertificateDer<'_>,
) -> Result<Snapshot, SessionError> {
    let (_, payload) = verify(signed, Purpose::PolicySnapshot, internal_ca)?;
    let snapshot =
        PolicySnapshot::decode(payload).map_err(|e| SessionError::Malformed(e.to_string()))?;
    let docs: Vec<limen_policy::Document> = serde_json::from_str(&snapshot.documents_json)
        .map_err(|e| SessionError::Malformed(e.to_string()))?;
    let policy =
        Policy::from_documents(docs).map_err(|e| SessionError::Malformed(e.to_string()))?;
    let issued_at = OffsetDateTime::from_unix_timestamp(snapshot.issued_at_unix)
        .map_err(|e| SessionError::Malformed(e.to_string()))?;
    Ok(Snapshot {
        version: snapshot.version,
        issued_at,
        policy: Arc::new(policy),
        restrictions: Arc::new(Restrictions {
            locked_users: snapshot.locked_users.into_iter().collect(),
            killed_sessions: snapshot.killed_sessions.into_iter().collect(),
        }),
    })
}

/// The latest verified snapshot, optionally persisted so a restart can use
/// it (its age still counts from when it was issued).
#[derive(Debug, Clone)]
pub struct PolicyCache {
    latest: Arc<RwLock<Option<Snapshot>>>,
    grace: Duration,
    path: Option<PathBuf>,
}

impl PolicyCache {
    #[must_use]
    pub fn new(grace: Duration, path: Option<PathBuf>) -> Self {
        Self {
            latest: Arc::new(RwLock::new(None)),
            grace,
            path,
        }
    }

    /// Load a persisted snapshot, if any. A bad file is ignored with a warning.
    pub fn load(&self, internal_ca: &CertificateDer<'_>) {
        let Some(path) = &self.path else { return };
        let Ok(bytes) = std::fs::read(path) else {
            return;
        };
        match Signed::decode(bytes.as_slice())
            .map_err(|e| SessionError::Malformed(e.to_string()))
            .and_then(|s| verify_snapshot(&s, internal_ca))
        {
            Ok(snapshot) => {
                tracing::info!(version = snapshot.version, issued_at = %snapshot.issued_at, "loaded persisted policy snapshot");
                self.set(snapshot);
            }
            Err(e) => {
                tracing::warn!(error = %e, path = %path.display(), "ignoring persisted policy snapshot");
            }
        }
    }

    /// Verify, store, and persist a snapshot from the control plane.
    pub fn update(
        &self,
        signed: &Signed,
        internal_ca: &CertificateDer<'_>,
    ) -> Result<Snapshot, SessionError> {
        let snapshot = verify_snapshot(signed, internal_ca)?;
        if let Some(current) = self.latest()
            && (snapshot.version < current.version || snapshot.issued_at < current.issued_at)
        {
            return Err(SessionError::Malformed(
                "older than the snapshot already held".into(),
            ));
        }
        if let Some(path) = &self.path {
            let tmp = path.with_extension("tmp");
            if let Err(e) = std::fs::write(&tmp, signed.encode_to_vec())
                .and_then(|()| std::fs::rename(&tmp, path))
            {
                tracing::warn!(error = %e, "failed to persist policy snapshot");
            }
        }
        self.set(snapshot.clone());
        Ok(snapshot)
    }

    fn set(&self, snapshot: Snapshot) {
        *self
            .latest
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(snapshot);
    }

    #[must_use]
    pub fn latest(&self) -> Option<Snapshot> {
        self.latest
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The snapshot, if it's within the grace period at `now`.
    pub fn fresh(&self, now: OffsetDateTime) -> Result<Snapshot, SessionError> {
        let snapshot = self.latest().ok_or(SessionError::NoSnapshot)?;
        let age = (now - snapshot.issued_at).whole_seconds();
        let grace = i64::try_from(self.grace.as_secs()).unwrap_or(i64::MAX);
        if age > grace {
            return Err(SessionError::Stale {
                age_secs: age,
                grace_secs: grace,
            });
        }
        Ok(snapshot)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use limen_ca::{CaPurpose, CertificateAuthority, ComponentCertRequest, FileSigner};
    use limen_core::identity::ComponentKind;
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

    use super::*;

    async fn setup() -> (CertificateAuthority, EnvelopeSigner, EnvelopeSigner) {
        let ca = CertificateAuthority::create_self_signed(
            CaPurpose::Internal,
            Arc::new(FileSigner::generate().expect("k")),
        )
        .await
        .expect("ca");
        let mut signers = Vec::new();
        for kind in [ComponentKind::ControlPlane, ComponentKind::Proxy] {
            let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
            let csr = CertificateParams::default()
                .serialize_request(&key)
                .expect("csr");
            let cert = ca
                .issue_component(ComponentCertRequest {
                    csr_der: csr.der().to_vec(),
                    kind,
                    id: "c".into(),
                    dns_names: vec![],
                    labels: std::collections::BTreeMap::new(),
                    ttl: Duration::from_secs(600),
                })
                .await
                .expect("issue");
            signers.push(
                EnvelopeSigner::new(&key.serialize_pem(), cert.der.to_vec()).expect("signer"),
            );
        }
        let proxy = signers.pop().expect("proxy");
        let cp = signers.pop().expect("cp");
        (ca, cp, proxy)
    }

    #[tokio::test]
    async fn fresh_within_grace_and_stale_after() {
        let (ca, cp, _) = setup().await;
        let now = OffsetDateTime::now_utc();
        let cache = PolicyCache::new(Duration::from_mins(5), None);
        assert!(matches!(cache.fresh(now), Err(SessionError::NoSnapshot)));
        cache
            .update(
                &sign(&cp, 3, &Policy::default(), &Restrictions::default(), now).expect("sign"),
                ca.cert_der(),
            )
            .expect("update");
        assert_eq!(
            cache
                .fresh(now + time::Duration::minutes(4))
                .expect("fresh")
                .version,
            3
        );
        assert!(matches!(
            cache.fresh(now + time::Duration::minutes(6)),
            Err(SessionError::Stale { .. })
        ));
    }

    #[tokio::test]
    async fn only_control_plane_may_sign_and_rollback_is_refused() {
        let (ca, cp, proxy) = setup().await;
        let now = OffsetDateTime::now_utc();
        let cache = PolicyCache::new(DEFAULT_GRACE, None);
        assert!(
            cache
                .update(
                    &sign(&proxy, 9, &Policy::default(), &Restrictions::default(), now)
                        .expect("sign"),
                    ca.cert_der()
                )
                .is_err(),
            "proxies can't sign snapshots"
        );
        cache
            .update(
                &sign(&cp, 5, &Policy::default(), &Restrictions::default(), now).expect("sign"),
                ca.cert_der(),
            )
            .expect("v5");
        assert!(
            cache
                .update(
                    &sign(&cp, 4, &Policy::default(), &Restrictions::default(), now).expect("sign"),
                    ca.cert_der()
                )
                .is_err(),
            "no version rollback"
        );
    }

    #[tokio::test]
    async fn persisted_snapshot_reloads_with_its_original_age() {
        let (ca, cp, _) = setup().await;
        let dir = std::env::temp_dir().join(format!("limen-snap-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("policy.snapshot");
        let issued = OffsetDateTime::now_utc() - time::Duration::minutes(10);
        PolicyCache::new(DEFAULT_GRACE, Some(path.clone()))
            .update(
                &sign(&cp, 1, &Policy::default(), &Restrictions::default(), issued).expect("sign"),
                ca.cert_der(),
            )
            .expect("update");
        let reloaded = PolicyCache::new(DEFAULT_GRACE, Some(path));
        reloaded.load(ca.cert_der());
        assert_eq!(reloaded.latest().expect("loaded").version, 1);
        assert!(
            matches!(
                reloaded.fresh(OffsetDateTime::now_utc()),
                Err(SessionError::Stale { .. })
            ),
            "a restart doesn't reset the age"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn restrictions_travel_in_the_signed_snapshot() {
        let (ca, cp, _) = setup().await;
        let restrictions = Restrictions {
            locked_users: ["mallory@example.com".to_owned()].into(),
            killed_sessions: ["s-1".to_owned()].into(),
        };
        let signed = sign(
            &cp,
            1,
            &Policy::default(),
            &restrictions,
            OffsetDateTime::now_utc(),
        )
        .expect("sign");
        let snapshot = verify_snapshot(&signed, ca.cert_der()).expect("verify");
        assert_eq!(*snapshot.restrictions, restrictions);
        let r = &snapshot.restrictions;
        assert_eq!(r.blocks("mallory@example.com", "s-9"), Some("user locked"));
        assert_eq!(r.blocks("alice@example.com", "s-1"), Some("session killed"));
        assert_eq!(r.blocks("alice@example.com", "s-2"), None);
    }
}
