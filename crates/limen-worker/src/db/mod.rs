//! SQL database sessions (design §5.2, ADR-0033).
//!
//! The worker terminates the client's wire protocol, authenticates to the
//! target itself with a `limen_*` role, and relays frames in between. It parses
//! only the frames it audits or guards. The user never sees a credential.

mod audit;
pub mod bootstrap;
pub mod iam;
mod mysql;
pub mod mysqlclient;
mod pg;
pub mod pgclient;
pub mod scram;
pub mod secret;
pub mod sigv4;
pub mod sqltext;
pub mod target;

use std::collections::HashMap;
use std::sync::Mutex;

use limen_audit::Emitter;
use limen_core::secret::Secret;
use tokio::io::{AsyncRead, AsyncWrite};

pub use target::Target;

/// Which wire protocol and compatibility profile a resource uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    Postgres,
    Redshift,
    Mysql,
}

impl Engine {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Engine::Postgres => "postgres",
            Engine::Redshift => "redshift",
            Engine::Mysql => "mysql",
        }
    }
}

/// Everything a database session needs, decided by `session::admit`.
#[derive(Debug)]
pub struct DbSessionConfig {
    pub session_id: uuid::Uuid,
    pub username: String,
    pub resource: String,
    pub engine: Engine,
    /// The `limen_*` role the session is for (what policy and audit name).
    pub role: String,
    /// The user the worker logs in as on the target. The role itself, except
    /// for Redshift IAM, where the credential API names it (`IAM:<role>`).
    pub login_user: String,
    pub database: String,
    pub target: Target,
    /// The role's password, or a short-lived IAM token. Used once, at connect.
    pub password: Secret<String>,
    /// `audit.normalize_literals` on the resource.
    pub normalize_literals: bool,
    pub registry: std::sync::Arc<Registry>,
}

/// What a client needs to cancel its own query (PostgreSQL `CancelRequest`).
/// The client is given a random key; the real backend key stays here.
#[derive(Debug, Clone)]
pub(crate) struct CancelEntry {
    pub username: String,
    pub resource: String,
    pub pid: u32,
    pub secret: u32,
    pub target: Target,
}

/// A MySQL session a `KILL` can name: the connection id the client was given
/// maps to the thread id on the target.
#[derive(Debug, Clone)]
pub(crate) struct KillEntry {
    pub username: String,
    pub resource: String,
    pub real_id: u32,
}

/// Open database sessions that can be cancelled, by the key the client holds.
#[derive(Debug, Default)]
pub struct Registry {
    sessions: Mutex<HashMap<(u32, u32), CancelEntry>>,
    mysql: Mutex<HashMap<u32, KillEntry>>,
    next_id: std::sync::atomic::AtomicU32,
}

impl Registry {
    pub(crate) fn insert(&self, key: (u32, u32), entry: CancelEntry) {
        if let Ok(mut map) = self.sessions.lock() {
            map.insert(key, entry);
        }
    }

    pub(crate) fn remove(&self, key: (u32, u32)) {
        if let Ok(mut map) = self.sessions.lock() {
            map.remove(&key);
        }
    }

    pub(crate) fn get(&self, key: (u32, u32)) -> Option<CancelEntry> {
        self.sessions.lock().ok()?.get(&key).cloned()
    }

    /// A fresh connection id to show a MySQL client.
    pub(crate) fn next_connection_id(&self) -> u32 {
        // Start high so ids can't be mistaken for small real thread ids.
        0x4000_0000
            + self
                .next_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    pub(crate) fn insert_mysql(&self, id: u32, entry: KillEntry) {
        if let Ok(mut map) = self.mysql.lock() {
            map.insert(id, entry);
        }
    }

    pub(crate) fn remove_mysql(&self, id: u32) {
        if let Ok(mut map) = self.mysql.lock() {
            map.remove(&id);
        }
    }

    pub(crate) fn get_mysql(&self, id: u32) -> Option<KillEntry> {
        self.mysql.lock().ok()?.get(&id).cloned()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.lock().map_or(0, |m| m.len()) + self.mysql.lock().map_or(0, |m| m.len())
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Serve one client connection until it ends. `client` is the decrypted
/// stream from the proxy.
pub async fn serve<S>(client: S, cfg: DbSessionConfig, audit: Emitter) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match cfg.engine {
        Engine::Postgres | Engine::Redshift => pg::serve(client, cfg, audit).await,
        Engine::Mysql => mysql::serve(client, cfg, audit).await,
    }
}

/// A reconcile plan for every database resource `labels` may serve that
/// declares roles to bootstrap. A resource that can't be planned comes back
/// with the reason.
pub async fn bootstrap_plans(
    policy: &limen_policy::Policy,
    labels: &std::collections::BTreeMap<String, String>,
    allow_insecure: bool,
) -> Vec<(String, Result<bootstrap::Plan, String>)> {
    let mut plans = Vec::new();
    for resource in policy.resources() {
        let name = &resource.metadata.name;
        let (engine, spec) = match (
            resource.spec.postgres.as_ref(),
            resource.spec.redshift.as_ref(),
            resource.spec.mysql.as_ref(),
        ) {
            (Some(s), _, _) => (Engine::Postgres, s),
            (_, Some(s), _) => (Engine::Redshift, s),
            (_, _, Some(s)) => (Engine::Mysql, s),
            _ => continue,
        };
        if spec.bootstrap.is_empty() || !policy.worker_may_serve(name, labels) {
            continue;
        }
        plans.push((
            name.clone(),
            bootstrap::Plan::from_spec(name, engine, spec, allow_insecure)
                .await
                .map(|plan| plan.guarded(resource.spec.delegated.clone())),
        ));
    }
    plans
}
