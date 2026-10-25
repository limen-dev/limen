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
        // Events and recording text age out of the search window (ADR-0026).
        let days = i32::try_from(state.config.search_retention.as_secs() / 86_400)
            .unwrap_or(i32::MAX)
            .max(1);
        match crate::search::index::trim(&state.db, days).await {
            Ok(n) if n > 0 => tracing::info!(deleted = n, "trimmed the search index"),
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "trimming the search index failed"),
        }
        match crate::db::cleanup(&state.db).await {
            Ok(Some(n)) if n > 0 => tracing::info!(deleted = n, "cleaned up expired rows"),
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "cleanup failed"),
        }
    }
}

/// Lapse access requests nobody answered and note grants that ended.
pub async fn access_expiry(state: AppState, mut shutdown: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = shutdown.changed() => return,
        }
        if let Err(e) = crate::access::expire(&state).await {
            tracing::warn!(error = %e, "expiring access requests failed");
        }
    }
}

/// Keep the accepted discovered resources in the policy in step with the
/// database (another replica may have accepted one), and sweep the stale
/// (ADR-0027).
pub async fn discovery_sweep(state: AppState, mut shutdown: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    let mut n: u32 = 0;
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = shutdown.changed() => return,
        }
        if let Err(e) = crate::discovery::refresh_overlay(&state).await {
            tracing::warn!(error = %e, "refreshing discovered resources failed; keeping the last");
        }
        n = n.wrapping_add(1);
        if n.is_multiple_of(6)
            && let Err(e) = crate::discovery::sweep(&state).await
        {
            tracing::warn!(error = %e, "sweeping discovered resources failed");
        }
    }
}

/// Whether a replica that last managed a heartbeat `since_ok` ago must stop
/// shipping to S3: its row goes stale 15 seconds after the last success, and
/// then another process may take the id over and write the same chain.
fn must_fence(since_ok: Duration) -> bool {
    since_ok >= Duration::from_secs(crate::replicas::FENCE_AFTER_SECS)
}

/// Keep this replica's registry row alive. If the id was taken over by
/// another process, this replica has lost it: shut down via `stop`. If the
/// database cannot be reached for a while, stop shipping to S3 (the events
/// wait in the spool) until it can, so a replacement that takes over the id
/// never shares the manifest chain with this process.
pub async fn replica_heartbeat(
    state: AppState,
    mut done: watch::Receiver<bool>,
    stop: std::sync::Arc<watch::Sender<bool>>,
) {
    let mut tick = tokio::time::interval(Duration::from_secs(crate::replicas::HEARTBEAT_SECS));
    let mut last_ok = tokio::time::Instant::now();
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = done.changed() => return,
        }
        // A hung query counts as a failure: bounded by one interval.
        let beat = tokio::time::timeout(
            Duration::from_secs(crate::replicas::HEARTBEAT_SECS),
            crate::replicas::heartbeat(&state.db, &state.registration),
        )
        .await;
        match beat {
            Ok(Ok(())) => {
                last_ok = tokio::time::Instant::now();
                if state.pipeline.is_fenced() {
                    tracing::info!("replica heartbeat is back; resuming S3 shipping");
                    state.pipeline.set_fenced(false);
                }
                match crate::replicas::live_count(&state.db).await {
                    // Scale signal: how many control planes are serving.
                    #[allow(clippy::cast_precision_loss)]
                    Ok(n) => metrics::gauge!("limen_control_plane_replicas").set(n as f64),
                    Err(e) => tracing::warn!(error = %e, "counting live replicas failed"),
                }
            }
            Ok(Err(crate::replicas::HeartbeatError::Lost)) => {
                // Never ship to S3 again: the id belongs to someone else now.
                state.pipeline.set_fenced(true);
                tracing::error!(id = %state.registration.id, "another process took over this replica id; shutting down");
                let _ = stop.send(true);
                return;
            }
            failure => {
                match failure {
                    Ok(Err(e)) => tracing::warn!(error = %e, "replica heartbeat failed"),
                    _ => tracing::warn!("replica heartbeat timed out"),
                }
                if must_fence(last_ok.elapsed()) && !state.pipeline.is_fenced() {
                    tracing::error!(
                        since_ok = ?last_ok.elapsed(),
                        "no replica heartbeat for too long; pausing S3 shipping until the registry is reachable (events wait in the spool)"
                    );
                    state.pipeline.set_fenced(true);
                }
            }
        }
    }
}

#[cfg(test)]
mod fence_tests {
    use std::time::Duration;

    use super::must_fence;
    use crate::replicas::{FENCE_AFTER_SECS, HEARTBEAT_SECS};

    #[test]
    fn the_fence_is_in_place_before_the_row_can_be_taken_over() {
        assert!(!must_fence(Duration::from_secs(HEARTBEAT_SECS)));
        assert!(must_fence(Duration::from_secs(FENCE_AFTER_SECS)));
        // (That the latest tick that can see the failure still beats the
        // lease is a compile-time check in `replicas`.)
    }
}
