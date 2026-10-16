//! Background jobs.

use std::time::Duration;

use tokio::sync::watch;

use crate::state::AppState;

/// Keep the policy cache in sync with other replicas.
pub async fn policy_refresh(state: AppState, mut shutdown: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = shutdown.changed() => return,
        }
        if let Err(e) = state.policy.refresh(&state.db).await {
            tracing::warn!(error = %e, "policy refresh failed; serving the cached version");
        }
    }
}

/// Delete expired rows and idle rate limiter state.
pub async fn cleanup(state: AppState, mut shutdown: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = shutdown.changed() => return,
        }
        state.limits.shrink();
        match crate::db::cleanup(&state.db).await {
            Ok(Some(n)) if n > 0 => tracing::info!(deleted = n, "cleaned up expired rows"),
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "cleanup failed"),
        }
    }
}

/// Keep this replica's registry row alive. If the id was taken over by
/// another process, this replica has lost it: shut down via `stop`.
pub async fn replica_heartbeat(
    state: AppState,
    mut done: watch::Receiver<bool>,
    stop: std::sync::Arc<watch::Sender<bool>>,
) {
    let mut tick = tokio::time::interval(Duration::from_secs(crate::replicas::HEARTBEAT_SECS));
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = done.changed() => return,
        }
        match crate::replicas::heartbeat(&state.db, &state.registration).await {
            Ok(()) => match crate::replicas::live_count(&state.db).await {
                // Scale signal: how many control planes are serving.
                #[allow(clippy::cast_precision_loss)]
                Ok(n) => metrics::gauge!("limen_control_plane_replicas").set(n as f64),
                Err(e) => tracing::warn!(error = %e, "counting live replicas failed"),
            },
            Err(crate::replicas::HeartbeatError::Lost) => {
                tracing::error!(id = %state.registration.id, "another process took over this replica id; shutting down");
                let _ = stop.send(true);
                return;
            }
            Err(e) => tracing::warn!(error = %e, "replica heartbeat failed"),
        }
    }
}
