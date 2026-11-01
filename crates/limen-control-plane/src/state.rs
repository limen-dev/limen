//! State shared by every request handler.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use limen_audit::Emitter;
use limen_policy::Policy;
use time::OffsetDateTime;
use tonic::Status;

use crate::ca_store::Cas;
use crate::config::Config;
use crate::db::{self, Db};
use crate::oidc::OidcVerifier;

#[derive(Debug, Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: Db,
    pub cas: Cas,
    pub oidc: OidcVerifier,
    pub bots: crate::bots::BotVerifier,
    pub policy: PolicyStore,
    pub audit: Emitter,
    pub pipeline: crate::pipeline::Pipeline,
    /// Present when `--console-public-url` is set.
    pub console: Option<crate::console::Console>,
    pub limits: Arc<Limits>,
    /// Proof that this process owns its row in the replica registry.
    pub registration: crate::replicas::Registration,
    /// Set once shutdown starts: not ready, and `Ingest` is refused.
    pub draining: Arc<std::sync::atomic::AtomicBool>,
    /// Signs policy snapshots with this replica's own (rotating) key. Set
    /// once the server certificate is issued.
    pub snapshot_signer: Arc<RwLock<Option<Arc<limen_session::envelope::EnvelopeSigner>>>>,
    /// Tells people an access request needs them (ADR-0025). Does nothing
    /// unless a notifier is configured.
    pub notifier: crate::access::notify::Notifier,
}

impl AppState {
    /// `unavailable` once shutdown has started, so callers move to a peer.
    pub fn refuse_if_draining(&self) -> Result<(), Status> {
        if self.draining.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(Status::unavailable(
                "this control plane is shutting down; try another replica",
            ));
        }
        Ok(())
    }
}

/// The currently active policy, cached in memory.
#[derive(Debug, Clone)]
pub struct LoadedPolicy {
    pub version: i64,
    /// Digest of the documents, so a refresh notices a changed set under a
    /// reused version number (a restored backup, #188).
    pub digest: String,
    pub policy: Arc<Policy>,
    pub author: String,
    pub created_at: Option<OffsetDateTime>,
}

/// The policy the control plane decides from: what an admin applied (the
/// *base*, which versions and diffs are about), plus accepted discovered
/// resources (the *overlay*, ADR-0027). [`PolicyStore::current`] is the sum,
/// which is also what snapshots carry.
#[derive(Debug, Clone)]
pub struct PolicyStore(Arc<RwLock<Layers>>);

#[derive(Debug)]
struct Layers {
    base: Arc<LoadedPolicy>,
    overlay: Arc<Vec<limen_policy::model::ResourceDoc>>,
    effective: Arc<LoadedPolicy>,
}

impl Layers {
    fn new(base: Arc<LoadedPolicy>, overlay: Arc<Vec<limen_policy::model::ResourceDoc>>) -> Self {
        let effective = if overlay.is_empty() {
            Arc::clone(&base)
        } else {
            let (policy, skipped) = base.policy.with_discovered(overlay.iter().cloned());
            for (name, why) in skipped {
                tracing::warn!(resource = %name, %why, "a discovered resource is not in the policy");
            }
            Arc::new(LoadedPolicy {
                version: base.version,
                digest: base.digest.clone(),
                policy: Arc::new(policy),
                author: base.author.clone(),
                created_at: base.created_at,
            })
        };
        Self {
            base,
            overlay,
            effective,
        }
    }
}

impl PolicyStore {
    #[must_use]
    pub fn empty() -> Self {
        let base = Arc::new(LoadedPolicy {
            version: 0,
            digest: String::new(),
            policy: Arc::new(Policy::default()),
            author: String::new(),
            created_at: None,
        });
        Self(Arc::new(RwLock::new(Layers::new(base, Arc::default()))))
    }

    /// The policy to decide from: applied policy plus accepted discovered resources.
    #[must_use]
    pub fn current(&self) -> Arc<LoadedPolicy> {
        Arc::clone(
            &self
                .0
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .effective,
        )
    }

    /// The policy as applied, without discovered resources. What versions,
    /// diffs, and `limen admin apply` are about.
    #[must_use]
    pub fn base(&self) -> Arc<LoadedPolicy> {
        Arc::clone(
            &self
                .0
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .base,
        )
    }

    pub fn set(&self, loaded: LoadedPolicy) {
        let mut layers = self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *layers = Layers::new(Arc::new(loaded), Arc::clone(&layers.overlay));
    }

    /// Replace the accepted discovered resources. A no-op if they are the same.
    pub fn set_overlay(&self, docs: Vec<limen_policy::model::ResourceDoc>) {
        let mut layers = self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *layers.overlay == docs {
            return;
        }
        *layers = Layers::new(Arc::clone(&layers.base), Arc::new(docs));
    }

    /// Reload from the database if another replica applied a newer version.
    pub async fn refresh(&self, db: &Db) -> anyhow::Result<()> {
        let mut conn = db.acquire().await?;
        self.latest(&mut conn).await.map(|_| ())
    }

    /// The applied policy as the database has it now, read on `conn` (inside a
    /// transaction, when the caller is about to write). Installs it when its
    /// version differs from this replica's copy, older included, so a database
    /// restored from a backup takes effect. A write must start from this, never
    /// from [`PolicyStore::base`], which another replica's apply reaches only
    /// at the next refresh (#182).
    pub async fn latest(&self, conn: &mut sqlx::PgConnection) -> anyhow::Result<Arc<LoadedPolicy>> {
        let known = self.base();
        let (latest, latest_digest) = db::latest_policy_head(&mut *conn)
            .await?
            .unwrap_or((0, String::new()));
        if latest == known.version && latest_digest == known.digest {
            return Ok(known);
        }
        let Some(row) = db::latest_policy(&mut *conn).await? else {
            return Ok(known);
        };
        let docs: Vec<limen_policy::Document> = serde_json::from_value(row.documents)?;
        let policy = Policy::from_documents(docs)?;
        tracing::info!(version = row.version, digest = %row.digest, "loaded policy");
        let loaded = LoadedPolicy {
            version: row.version,
            digest: row.digest.clone(),
            policy: Arc::new(policy),
            author: row.author,
            created_at: Some(row.created_at),
        };
        self.set(loaded.clone());
        Ok(Arc::new(loaded))
    }
}

/// Per-client-IP rate limits for unauthenticated entry points.
#[derive(Debug)]
pub struct Limits {
    pub unauthenticated: DefaultKeyedRateLimiter<IpAddr>,
    /// Browser sign-ins (two requests each: start and callback). Separate, so
    /// the console and the CLI don't share one budget.
    pub console_login: DefaultKeyedRateLimiter<IpAddr>,
    /// Searches of the audit trail, per person (ADR-0026): search is also a
    /// way to read a lot at once.
    pub search: DefaultKeyedRateLimiter<String>,
    /// Policy writes through the management API, per principal (ADR-0042 §10).
    pub policy_writes: DefaultKeyedRateLimiter<String>,
    /// Dry runs: more of them (a plan checks every resource), still bounded,
    /// since each computes the whole policy.
    pub policy_dry_runs: DefaultKeyedRateLimiter<String>,
}

impl Default for Limits {
    fn default() -> Self {
        // 30 requests a minute per IP, with bursts of 10.
        Self::new(30, 10)
    }
}

impl Limits {
    /// `per_minute` and `burst` apply to the unauthenticated entry points;
    /// browser sign-ins (two requests each) get twice as much, so the
    /// console and the CLI don't share one budget.
    #[must_use]
    pub fn new(per_minute: u32, burst: u32) -> Self {
        let nz = |n: u32| NonZeroU32::new(n).unwrap_or(NonZeroU32::MIN);
        let quota = Quota::per_minute(nz(per_minute)).allow_burst(nz(burst));
        let console = Quota::per_minute(nz(per_minute.saturating_mul(2)))
            .allow_burst(nz(burst.saturating_mul(2)));
        Self {
            unauthenticated: RateLimiter::keyed(quota),
            console_login: RateLimiter::keyed(console),
            // Thirty a minute, bursts of ten, whatever the sign-in limits are.
            search: RateLimiter::keyed(Quota::per_minute(nz(30)).allow_burst(nz(10))),
            // Sixty a minute, bursts of twenty: a Terraform apply of a few
            // dozen resources goes through; a loop doesn't.
            policy_writes: RateLimiter::keyed(Quota::per_minute(nz(60)).allow_burst(nz(20))),
            policy_dry_runs: RateLimiter::keyed(Quota::per_minute(nz(600)).allow_burst(nz(100))),
        }
    }
}

impl Limits {
    pub fn check_unauthenticated(&self, addr: Option<IpAddr>) -> Result<(), Status> {
        let key = addr.unwrap_or(IpAddr::from([0, 0, 0, 0]));
        self.unauthenticated
            .check_key(&key)
            .map_err(|_| Status::resource_exhausted("too many requests; slow down"))
    }

    pub fn check_console_login(&self, addr: Option<IpAddr>) -> Result<(), Status> {
        let key = addr.unwrap_or(IpAddr::from([0, 0, 0, 0]));
        self.console_login
            .check_key(&key)
            .map_err(|_| Status::resource_exhausted("too many sign-in attempts; slow down"))
    }

    pub fn check_search(&self, username: &str) -> Result<(), Status> {
        self.search
            .check_key(&username.to_owned())
            .map_err(|_| Status::resource_exhausted("too many searches; slow down"))
    }

    /// Whether `principal` may write policy now.
    #[must_use]
    pub fn allow_policy_write(&self, principal: &str, dry_run: bool) -> bool {
        let limiter = if dry_run {
            &self.policy_dry_runs
        } else {
            &self.policy_writes
        };
        limiter.check_key(&principal.to_owned()).is_ok()
    }

    /// Drop state for idle keys. Call periodically.
    pub fn shrink(&self) {
        self.policy_writes.retain_recent();
        self.policy_dry_runs.retain_recent();
        self.search.retain_recent();
        self.unauthenticated.retain_recent();
        self.console_login.retain_recent();
    }
}

/// Map an internal error to a gRPC status without leaking details.
pub fn internal(context: &str, err: impl std::fmt::Display) -> Status {
    tracing::error!(error = %err, "{context}");
    Status::internal(context.to_owned())
}

/// Seconds since the epoch, for API responses.
#[must_use]
pub fn unix(t: OffsetDateTime) -> i64 {
    t.unix_timestamp()
}

pub const TUNNEL_LEASE: Duration = Duration::from_secs(limen_core::registry::TUNNEL_LEASE_SECS);

#[cfg(test)]
mod limit_tests {
    use std::net::IpAddr;

    use super::Limits;

    fn allowed(limits: &Limits, ip: IpAddr, tries: u32) -> usize {
        (0..tries)
            .filter(|_| limits.check_unauthenticated(Some(ip)).is_ok())
            .count()
    }

    #[test]
    fn the_burst_and_the_rate_are_settable_and_the_default_is_unchanged() {
        let ip = IpAddr::from([10, 0, 0, 1]);
        assert_eq!(allowed(&Limits::default(), ip, 50), 10, "30/min, burst 10");
        assert_eq!(allowed(&Limits::new(600, 40), ip, 100), 40);
        // Limits are per client IP.
        let limits = Limits::new(30, 3);
        assert_eq!(allowed(&limits, ip, 10), 3);
        assert_eq!(allowed(&limits, IpAddr::from([10, 0, 0, 2]), 10), 3);
    }

    #[test]
    fn browser_sign_ins_get_twice_the_budget() {
        let ip = IpAddr::from([10, 0, 0, 1]);
        let limits = Limits::new(30, 3);
        let ok = (0..20)
            .filter(|_| limits.check_console_login(Some(ip)).is_ok())
            .count();
        assert_eq!(ok, 6);
    }
}
