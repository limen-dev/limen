//! Limen control plane: API, identity, policy, CA, worker registry, and
//! audit emission. Stateless: all state is in PostgreSQL (ADR-0010).

pub mod bots;
pub mod ca_store;
pub mod caller;
pub mod config;
pub mod console;
pub mod db;
pub mod http_client;
pub mod jobs;
pub mod oidc;
pub mod pipeline;
pub mod replicas;
pub mod server;
pub mod services;
pub mod sinks;
pub mod state;
pub mod verify;

use std::sync::Arc;

use anyhow::Context as _;
use limen_audit::Emitter;
use limen_audit::ship::SpoolSink;
use tokio::net::TcpListener;
use tokio::sync::watch;

pub use config::Config;
use state::{AppState, Limits, PolicyStore};

/// Build the shared state: connect and migrate the database, load the CAs,
/// load the policy, and open the audit sink.
pub async fn build_state(config: Config) -> anyhow::Result<AppState> {
    let db = db::connect(config.database_url.expose())
        .await
        .context("connecting to the database")?;
    let cas = ca_store::load(&config, &db)
        .await
        .context("loading CA keys")?;
    if let Some(dir) = &config.ca_export_dir {
        tokio::fs::create_dir_all(dir).await?;
        tokio::fs::write(dir.join("internal-ca.pem"), cas.internal.cert_pem()).await?;
        tokio::fs::write(dir.join("user-ca.pem"), cas.user.cert_pem()).await?;
        // SSH targets trust this one (TrustedUserCAKeys); the CLI trusts the host CA.
        tokio::fs::write(
            dir.join("ssh-user-ca.pub"),
            format!("{}\n", cas.ssh_user.public_key_openssh()?),
        )
        .await?;
        tokio::fs::write(
            dir.join("ssh-host-ca.pub"),
            format!("{}\n", cas.ssh_host.public_key_openssh()?),
        )
        .await?;
        tracing::info!(dir = %dir.display(), "exported CA certificates");
    }
    let http = http_client::HttpClient::new()?;
    let oidc = oidc::OidcVerifier::new(
        &config.oidc_issuer,
        config.oidc_internal_url.as_deref(),
        &config.oidc_client_id,
        config.oidc_username_claim,
        http.clone(),
    )?;
    let bots = bots::BotVerifier::new(
        &config.bot_audience,
        config.bot_max_token_age,
        config.bot_allow_insecure_issuers,
        http.clone(),
    );
    let console = build_console(&config, &http)?;
    let policy = PolicyStore::empty();
    policy.refresh(&db).await.context("loading policy")?;
    // Claim the id before the pipeline opens the spool, so a duplicate
    // replica never touches it.
    let registration = replicas::register(&db, &config.id, &config.ingest_url(), config.spool_mode)
        .await
        .context("registering this replica")?;
    let config = Arc::new(config);
    let snapshot_signer: sinks::SignerSlot = Arc::default();
    let pipeline = pipeline::Pipeline::open(&config, Arc::clone(&snapshot_signer)).await?;
    let sink = Arc::new(SpoolSink(pipeline.spool.clone()));
    let audit = Emitter::new("control-plane", &config.id, sink, config.audit_failure_mode);
    Ok(AppState {
        config,
        pipeline,
        console,
        db,
        cas,
        oidc,
        bots,
        policy,
        audit,
        limits: Arc::new(Limits::default()),
        registration,
        draining: Arc::default(),
        snapshot_signer,
    })
}

/// The web console is off unless `--console-public-url` is set.
fn build_console(
    config: &Config,
    http: &http_client::HttpClient,
) -> anyhow::Result<Option<console::Console>> {
    let Some(public) = &config.console_public_url else {
        return Ok(None);
    };
    let origin = public.trim_end_matches('/').to_owned();
    let url = url::Url::parse(&origin).context("--console-public-url")?;
    anyhow::ensure!(
        url.scheme() == "https" && url.path() == "/" && url.query().is_none(),
        "--console-public-url must be an https origin such as https://limen.example.com"
    );
    let secret = config
        .console_oidc_client_secret
        .clone()
        .context("the console needs --console-oidc-client-secret")?;
    let verifier = oidc::OidcVerifier::new(
        &config.oidc_issuer,
        config.oidc_internal_url.as_deref(),
        &config.console_oidc_client_id,
        config.oidc_username_claim,
        http.clone(),
    )?;
    let oidc = console::BrowserOidc::new(
        &config.oidc_issuer,
        config.oidc_internal_url.as_deref(),
        config.console_oidc_client_id.clone(),
        secret,
        format!("{origin}/console/callback"),
        config.oidc_scopes.clone(),
        http.clone(),
        verifier,
    );
    Ok(Some(console::Console { origin, oidc }))
}

/// Share of the drain timeout kept back for handing the spool to a peer.
const HANDOFF_RESERVE_PERCENT: u32 = 20;

/// Longest the heartbeat or the final deregister may delay the exit.
const WIND_DOWN_STEP: std::time::Duration = std::time::Duration::from_secs(2);

/// Time for shipping the spool: the drain timeout less the handoff reserve.
pub(crate) fn ship_budget(drain_timeout: std::time::Duration) -> std::time::Duration {
    drain_timeout * (100 - HANDOFF_RESERVE_PERCENT) / 100
}

/// Run until `shutdown` flips to true, then wind down in order: stop being
/// ready and refuse new audit ingest, finish in-flight calls, ship the spool.
pub async fn run(
    state: AppState,
    api: TcpListener,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    // Our own stop signal: the outside world or a lost replica id flips it.
    let (stop_tx, stop) = watch::channel(false);
    let stop_tx = Arc::new(stop_tx);
    // The whole wind-down is timed from the moment the stop flips.
    let started: Arc<std::sync::OnceLock<tokio::time::Instant>> = Arc::default();
    let forward = {
        let stop_tx = Arc::clone(&stop_tx);
        tokio::spawn(async move {
            // A dropped sender counts as shutdown, too.
            let _ = shutdown.wait_for(|stop| *stop).await;
            let _ = stop_tx.send(true);
        })
    };
    // Health and the heartbeat outlive the API drain: /readyz must report
    // "shutting down" and the registry row must stay fresh while the spool
    // ships.
    let (done_tx, done) = watch::channel(false);
    state.pipeline.start_sinks(&state.db);
    tokio::spawn(jobs::policy_refresh(state.clone(), stop.clone()));
    tokio::spawn(jobs::cleanup(state.clone(), stop.clone()));
    let heartbeat = tokio::spawn(jobs::replica_heartbeat(
        state.clone(),
        done.clone(),
        Arc::clone(&stop_tx),
    ));
    let health = tokio::spawn(server::serve_health(
        state.clone(),
        state.config.admin_listen,
        done,
    ));
    {
        let flag = Arc::clone(&state.draining);
        let started = Arc::clone(&started);
        let mut flipped = stop.clone();
        tokio::spawn(async move {
            let _ = flipped.wait_for(|stop| *stop).await;
            started.get_or_init(tokio::time::Instant::now);
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        });
    }
    let served = server::serve_api(state.clone(), api, stop, Arc::clone(&started)).await;
    let t0 = *started.get_or_init(tokio::time::Instant::now);
    let report = state
        .pipeline
        .drain(ship_budget(state.config.drain_timeout).saturating_sub(t0.elapsed()))
        .await;
    if report.is_clean() {
        tracing::info!("audit spool shipped to every sink");
    } else {
        tracing::warn!(pending = ?report.pending, "audit records remain in the spool after the drain deadline");
    }
    let _ = done_tx.send(true);
    if tokio::time::timeout(WIND_DOWN_STEP, heartbeat)
        .await
        .is_err()
    {
        tracing::warn!("the replica heartbeat did not stop in time");
    }
    forward.abort();
    match tokio::time::timeout(
        WIND_DOWN_STEP,
        replicas::deregister(&state.db, &state.registration),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "could not deregister this replica; its row expires");
        }
        Err(_) => tracing::warn!("deregistering timed out; this replica's row expires"),
    }
    // The health server stops with `done`; this is only a backstop.
    health.abort();
    served?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn ship_budget_keeps_a_fifth_back() {
        assert_eq!(
            super::ship_budget(std::time::Duration::from_secs(30)),
            std::time::Duration::from_secs(24)
        );
    }
}
