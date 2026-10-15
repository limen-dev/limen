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

/// Keep this replica's registry row alive.
pub async fn replica_heartbeat(state: AppState, mut shutdown: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(Duration::from_secs(crate::replicas::HEARTBEAT_SECS));
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = shutdown.changed() => return,
        }
        if let Err(e) = crate::replicas::heartbeat(&state.db, &state.config.id).await {
            tracing::warn!(error = %e, "replica heartbeat failed");
        }
    }
}
