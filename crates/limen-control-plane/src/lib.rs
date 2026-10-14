//! Limen control plane: API, identity, policy, CA, worker registry, and
//! audit emission. Stateless: all state is in PostgreSQL (ADR-0010).

pub mod ca_store;
pub mod caller;
pub mod config;
pub mod console;
pub mod db;
pub mod http_client;
pub mod jobs;
pub mod oidc;
pub mod pipeline;
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
    let console = build_console(&config, &http)?;
    let policy = PolicyStore::empty();
    policy.refresh(&db).await.context("loading policy")?;
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
        policy,
        audit,
        limits: Arc::new(Limits::default()),
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

/// Run until `shutdown` flips to true.
pub async fn run(
    state: AppState,
    api: TcpListener,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    state.pipeline.start_sinks(&state.db, &shutdown);
    tokio::spawn(jobs::policy_refresh(state.clone(), shutdown.clone()));
    tokio::spawn(jobs::cleanup(state.clone(), shutdown.clone()));
    let health = tokio::spawn(server::serve_health(
        state.clone(),
        state.config.admin_listen,
        shutdown.clone(),
    ));
    server::serve_api(state, api, shutdown).await?;
    health.abort();
    Ok(())
}
