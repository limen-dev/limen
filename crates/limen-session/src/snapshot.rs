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

impl Snapshot {
    /// [`Restrictions::effective_roles`] for a user certificate, at `now`.
    #[must_use]
    pub fn roles_for(
        &self,
        username: &str,
        cert_roles: &[String],
        resource: &str,
        now: OffsetDateTime,
    ) -> EffectiveRoles {
        self.restrictions
            .effective_roles(username, cert_roles, resource, now.unix_timestamp())
    }
}

/// What admins have shut off, carried next to the policy (ADR-0017).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Restrictions {
    pub locked_users: BTreeSet<String>,
    pub killed_sessions: BTreeSet<String>,
    pub revoked_components: BTreeSet<String>,
    /// Logins ended by `limen logout`.
    pub revoked_logins: BTreeSet<String>,
    /// Roles held for a while because an access request was approved
    /// (ADR-0025).
    pub grants: Vec<ActiveGrant>,
    /// Roles an access review took away (ADR-0029). They beat grants, and a
    /// role mapping too.
    pub denies: Vec<RoleDeny>,
}

/// A role a user holds on one resource until `expires_at_unix`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveGrant {
    /// The access request that produced it. Also the grant's id.
    pub request_id: String,
    pub username: String,
    pub role: String,
    pub resource: String,
    pub expires_at_unix: i64,
}

/// A role withheld from a user until `expires_at_unix`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleDeny {
    pub id: String,
    pub username: String,
    pub role: String,
    pub expires_at_unix: i64,
}

/// The roles that decide one request, and the grants that supplied some.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectiveRoles {
    pub roles: Vec<String>,
    /// Request ids of the grants whose role was added. A session started
    /// with a non-empty list ends when one of them does.
    pub request_ids: Vec<String>,
    /// The earliest deadline among those grants. A session may not outlive it.
    pub earliest_expiry_unix: Option<i64>,
}

impl Restrictions {
    /// Why this session must not continue, if it must not. `login_id` is the
    /// one in the user's certificate, `session_id` may be empty before one exists.
    #[must_use]
    pub fn blocks(&self, username: &str, login_id: &str, session_id: &str) -> Option<&'static str> {
        if self.locked_users.contains(username) {
            Some("user locked")
        } else if self.revoked_logins.contains(login_id) {
            Some("logged out")
        } else if self.killed_sessions.contains(session_id) {
            Some("session killed")
        } else {
            None
        }
    }

    /// The roles that decide whether `username` may reach `resource`: the ones
    /// in their certificate, plus any role an unexpired grant gives them on
    /// that resource, less any role an access review took away. Expiry is
    /// checked here against `now_unix`, so a grant ends at its deadline even
    /// if no newer snapshot has arrived (ADR-0025). A lock is checked
    /// separately by [`Restrictions::blocks`] and beats all of this.
    #[must_use]
    pub fn effective_roles(
        &self,
        username: &str,
        cert_roles: &[String],
        resource: &str,
        now_unix: i64,
    ) -> EffectiveRoles {
        let mut out = EffectiveRoles {
            roles: cert_roles.to_vec(),
            ..EffectiveRoles::default()
        };
        for grant in &self.grants {
            if grant.username == username
                && grant.resource == resource
                && grant.expires_at_unix > now_unix
                && !out.roles.contains(&grant.role)
            {
                out.roles.push(grant.role.clone());
                out.request_ids.push(grant.request_id.clone());
                out.earliest_expiry_unix = Some(
                    out.earliest_expiry_unix
                        .map_or(grant.expires_at_unix, |e| e.min(grant.expires_at_unix)),
                );
            }
        }
        let denied: Vec<&str> = self
            .denies
            .iter()
            .filter(|d| d.username == username && d.expires_at_unix > now_unix)
            .map(|d| d.role.as_str())
            .collect();
        if !denied.is_empty() {
            out.roles.retain(|r| !denied.contains(&r.as_str()));
            // A grant for a denied role supplies nothing.
            out.request_ids = self
                .grants
                .iter()
                .filter(|g| {
                    out.request_ids.contains(&g.request_id) && !denied.contains(&g.role.as_str())
                })
                .map(|g| g.request_id.clone())
                .collect();
        }
        out
    }

    /// The grants `username` holds right now, on any resource.
    pub fn grants_of<'a>(
        &'a self,
        username: &'a str,
        now_unix: i64,
    ) -> impl Iterator<Item = &'a ActiveGrant> {
        self.grants
            .iter()
            .filter(move |g| g.username == username && g.expires_at_unix > now_unix)
    }

    /// Whether any of the grants a session was started under has ended
    /// (revoked, or past its deadline). The snapshot a session started from
    /// held every one of them, so a grant that is missing now has ended.
    #[must_use]
    pub fn grant_ended(&self, request_ids: &[String], now_unix: i64) -> bool {
        request_ids.iter().any(|id| {
            !self
                .grants
                .iter()
                .any(|g| &g.request_id == id && g.expires_at_unix > now_unix)
        })
    }

    /// Whether `component_id` (a proxy or worker) was revoked.
    #[must_use]
    pub fn is_revoked(&self, component_id: &str) -> bool {
        self.revoked_components.contains(component_id)
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
        revoked_components: restrictions.revoked_components.iter().cloned().collect(),
        revoked_logins: restrictions.revoked_logins.iter().cloned().collect(),
        grants: restrictions
            .grants
            .iter()
            .map(|g| limen_proto::v1::AccessGrant {
                request_id: g.request_id.clone(),
                username: g.username.clone(),
                role: g.role.clone(),
                resource: g.resource.clone(),
                expires_at_unix: g.expires_at_unix,
            })
            .collect(),
        denies: restrictions
            .denies
            .iter()
            .map(|d| limen_proto::v1::AccessDeny {
                id: d.id.clone(),
                username: d.username.clone(),
                role: d.role.clone(),
                expires_at_unix: d.expires_at_unix,
            })
            .collect(),
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
            revoked_components: snapshot.revoked_components.into_iter().collect(),
            revoked_logins: snapshot.revoked_logins.into_iter().collect(),
            grants: snapshot
                .grants
                .into_iter()
                .map(|g| ActiveGrant {
                    request_id: g.request_id,
                    username: g.username,
                    role: g.role,
                    resource: g.resource,
                    expires_at_unix: g.expires_at_unix,
                })
                .collect(),
            denies: snapshot
                .denies
                .into_iter()
                .map(|d| RoleDeny {
                    id: d.id,
                    username: d.username,
                    role: d.role,
                    expires_at_unix: d.expires_at_unix,
                })
                .collect(),
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
            revoked_components: ["worker-9".to_owned()].into(),
            revoked_logins: ["login-7".to_owned()].into(),
            grants: vec![grant("req-1", "alice", "prod-db", "orders", 2_000)],
            denies: vec![RoleDeny {
                id: "deny-1".into(),
                username: "bob".into(),
                role: "dev".into(),
                expires_at_unix: 3_000,
            }],
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
        assert_eq!(
            r.blocks("mallory@example.com", "login-1", "s-9"),
            Some("user locked")
        );
        assert_eq!(
            r.blocks("admin@example.com", "login-1", "s-1"),
            Some("session killed")
        );
        assert_eq!(r.blocks("admin@example.com", "login-1", "s-2"), None);
        // One login ended; the same user's other logins carry on.
        assert_eq!(
            r.blocks("admin@example.com", "login-7", "s-2"),
            Some("logged out")
        );
        assert!(r.is_revoked("worker-9"));
        assert!(!r.is_revoked("worker-1"));
    }

    fn grant(id: &str, user: &str, role: &str, resource: &str, expires: i64) -> ActiveGrant {
        ActiveGrant {
            request_id: id.into(),
            username: user.into(),
            role: role.into(),
            resource: resource.into(),
            expires_at_unix: expires,
        }
    }

    fn roles(r: &[&str]) -> Vec<String> {
        r.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn a_grant_adds_its_role_on_its_resource_only_until_it_expires() {
        let r = Restrictions {
            grants: vec![grant("req-1", "alice", "prod-db", "orders", 2_000)],
            ..Restrictions::default()
        };
        let held = roles(&["dev"]);
        let eff = r.effective_roles("alice", &held, "orders", 1_999);
        assert_eq!(eff.roles, ["dev", "prod-db"]);
        assert_eq!(eff.request_ids, ["req-1"]);
        assert_eq!(eff.earliest_expiry_unix, Some(2_000));
        // Not on another resource, not for another user, not after the deadline.
        assert_eq!(
            r.effective_roles("alice", &held, "billing", 1_000).roles,
            ["dev"]
        );
        assert_eq!(
            r.effective_roles("mallory", &held, "orders", 1_000).roles,
            ["dev"]
        );
        assert_eq!(
            r.effective_roles("alice", &held, "orders", 2_000).roles,
            ["dev"]
        );
        assert_eq!(
            r.effective_roles("alice", &held, "orders", 2_000)
                .request_ids,
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_role_the_user_already_holds_is_not_credited_to_a_grant() {
        let r = Restrictions {
            grants: vec![grant("req-1", "alice", "dev", "orders", 2_000)],
            ..Restrictions::default()
        };
        let eff = r.effective_roles("alice", &roles(&["dev"]), "orders", 1_000);
        assert_eq!(eff.roles, ["dev"]);
        assert!(
            eff.request_ids.is_empty(),
            "the session doesn't depend on the grant"
        );
        assert_eq!(eff.earliest_expiry_unix, None);
    }

    #[test]
    fn the_earliest_deadline_among_the_grants_used_wins() {
        let r = Restrictions {
            grants: vec![
                grant("a", "alice", "r1", "orders", 5_000),
                grant("b", "alice", "r2", "orders", 3_000),
            ],
            ..Restrictions::default()
        };
        let eff = r.effective_roles("alice", &[], "orders", 1_000);
        assert_eq!(eff.roles, ["r1", "r2"]);
        assert_eq!(eff.earliest_expiry_unix, Some(3_000));
    }

    #[test]
    fn a_deny_override_beats_the_certificate_and_a_grant() {
        let r = Restrictions {
            grants: vec![grant("req-1", "alice", "prod-db", "orders", 9_000)],
            denies: vec![
                RoleDeny {
                    id: "d1".into(),
                    username: "alice".into(),
                    role: "dev".into(),
                    expires_at_unix: 5_000,
                },
                RoleDeny {
                    id: "d2".into(),
                    username: "alice".into(),
                    role: "prod-db".into(),
                    expires_at_unix: 5_000,
                },
            ],
            ..Restrictions::default()
        };
        let held = roles(&["dev", "sre"]);
        let eff = r.effective_roles("alice", &held, "orders", 1_000);
        assert_eq!(eff.roles, ["sre"]);
        assert!(
            eff.request_ids.is_empty(),
            "a denied grant supplies nothing"
        );
        // The override lapses, and the roles come back.
        assert_eq!(
            r.effective_roles("alice", &held, "orders", 5_000).roles,
            ["dev", "sre", "prod-db"]
        );
        // It is per user.
        assert_eq!(
            r.effective_roles("bob", &held, "orders", 1_000).roles,
            ["dev", "sre"]
        );
    }

    #[test]
    fn a_lock_still_blocks_a_user_who_holds_a_grant() {
        let r = Restrictions {
            locked_users: ["alice".to_owned()].into(),
            grants: vec![grant("req-1", "alice", "prod-db", "orders", 9_000)],
            ..Restrictions::default()
        };
        assert_eq!(r.blocks("alice", "l", "s"), Some("user locked"));
    }

    #[test]
    fn a_session_notices_when_its_grant_ends() {
        let live = Restrictions {
            grants: vec![grant("req-1", "alice", "prod-db", "orders", 2_000)],
            ..Restrictions::default()
        };
        let ids = roles(&["req-1"]);
        assert!(!live.grant_ended(&ids, 1_999));
        assert!(live.grant_ended(&ids, 2_000), "past its deadline");
        // Revoked: gone from the snapshot.
        assert!(Restrictions::default().grant_ended(&ids, 1_000));
        // A session that used no grant never ends this way.
        assert!(!Restrictions::default().grant_ended(&[], 1_000));
    }
}
