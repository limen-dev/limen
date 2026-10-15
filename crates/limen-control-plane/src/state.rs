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
    /// Signs policy snapshots with this replica's own (rotating) key. Set
    /// once the server certificate is issued.
    pub snapshot_signer: Arc<RwLock<Option<Arc<limen_session::envelope::EnvelopeSigner>>>>,
}

/// The currently active policy, cached in memory.
#[derive(Debug, Clone)]
pub struct LoadedPolicy {
    pub version: i64,
    pub policy: Arc<Policy>,
    pub author: String,
    pub created_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone)]
pub struct PolicyStore(Arc<RwLock<Arc<LoadedPolicy>>>);

impl PolicyStore {
    #[must_use]
    pub fn empty() -> Self {
        Self(Arc::new(RwLock::new(Arc::new(LoadedPolicy {
            version: 0,
            policy: Arc::new(Policy::default()),
            author: String::new(),
            created_at: None,
        }))))
    }

    #[must_use]
    pub fn current(&self) -> Arc<LoadedPolicy> {
        Arc::clone(
            &self
                .0
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    pub fn set(&self, loaded: LoadedPolicy) {
        *self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(loaded);
    }

    /// Reload from the database if another replica applied a newer version.
    pub async fn refresh(&self, db: &Db) -> anyhow::Result<()> {
        let latest = db::latest_policy_version(db).await?.unwrap_or(0);
        if latest == self.current().version {
            return Ok(());
        }
        let Some(row) = db::latest_policy(db).await? else {
            return Ok(());
        };
        let docs: Vec<limen_policy::Document> = serde_json::from_value(row.documents)?;
        let policy = Policy::from_documents(docs)?;
        tracing::info!(version = row.version, digest = %row.digest, "loaded policy");
        self.set(LoadedPolicy {
            version: row.version,
            policy: Arc::new(policy),
            author: row.author,
            created_at: Some(row.created_at),
        });
        Ok(())
    }
}

/// Per-client-IP rate limits for unauthenticated entry points.
#[derive(Debug)]
pub struct Limits {
    pub unauthenticated: DefaultKeyedRateLimiter<IpAddr>,
    /// Browser sign-ins (two requests each: start and callback). Separate, so
    /// the console and the CLI don't share one budget.
    pub console_login: DefaultKeyedRateLimiter<IpAddr>,
}

impl Default for Limits {
    fn default() -> Self {
        // 30 requests a minute per IP, with bursts of 10.
        let quota = Quota::per_minute(NonZeroU32::new(30).unwrap_or(NonZeroU32::MIN))
            .allow_burst(NonZeroU32::new(10).unwrap_or(NonZeroU32::MIN));
        // 60 requests a minute per IP, with bursts of 20.
        let console = Quota::per_minute(NonZeroU32::new(60).unwrap_or(NonZeroU32::MIN))
            .allow_burst(NonZeroU32::new(20).unwrap_or(NonZeroU32::MIN));
        Self {
            unauthenticated: RateLimiter::keyed(quota),
            console_login: RateLimiter::keyed(console),
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

    /// Drop state for idle keys. Call periodically.
    pub fn shrink(&self) {
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

pub const TUNNEL_LEASE: Duration = Duration::from_secs(45);
