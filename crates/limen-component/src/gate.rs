//! The upgrade gate (ADR-0045): a proxy or worker does not start serving while the control
//! plane it talks to is older than itself, so a rolling upgrade orders itself.
//!
//! The gate waits only on a *positive* answer that the control plane is older. If the control
//! plane cannot be reached, or its answer cannot be read, the component starts as before:
//! starting must never depend on the control plane being up (ADR-0011).

use std::future::Future;
use std::time::Duration;

use limen_core::backoff::Backoff;
use limen_proto::v1::GetServerVersionRequest;
use limen_proto::v1::policy_sync_client::PolicySyncClient;
use limen_tunnel::connect::TracedChannel as Channel;
use semver::Version;
use tonic::Code;

/// How long one poll may take before it counts as no answer.
const POLL_TIMEOUT: Duration = Duration::from_secs(10);

/// What the control plane's answer means for a component at version `own`.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Start: the control plane is at least as new.
    Go,
    /// Start, but say why the gate could not decide.
    Skip(String),
    /// Wait: the control plane is older.
    Wait(String),
}

/// Compare `own` with the control plane's answer: its version, or the status code of a failed call.
#[must_use]
pub fn verdict(own: &str, answer: Result<&str, Code>) -> Verdict {
    let theirs = match answer {
        Ok(theirs) => theirs,
        // A control plane from before this call existed is older by definition.
        Err(Code::Unimplemented) => {
            return Verdict::Wait("the control plane predates the version call".to_owned());
        }
        Err(code) => return Verdict::Skip(format!("the control plane did not answer ({code:?})")),
    };
    let (Some(own_v), Some(theirs_v)) = (parse(own), parse(theirs)) else {
        return Verdict::Skip(format!(
            "cannot compare versions {own:?} and {theirs:?} as semantic versions"
        ));
    };
    if theirs_v >= own_v {
        Verdict::Go
    } else {
        Verdict::Wait(format!(
            "the control plane is at {theirs}, this component at {own}"
        ))
    }
}

/// Semantic version without build metadata, which does not take part in precedence.
fn parse(v: &str) -> Option<Version> {
    let mut v = Version::parse(v.trim().trim_start_matches('v')).ok()?;
    v.build = semver::BuildMetadata::EMPTY;
    Some(v)
}

/// Poll `ask` until the control plane is at least `own`. `ask` returns the control plane's
/// version or the status code of the failed call. Waits 2 s to 15 s between polls.
pub async fn wait_until_current<F, Fut>(own: &str, mut ask: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<String, Code>>,
{
    let mut backoff = Backoff::new(Duration::from_secs(2), Duration::from_secs(15));
    let mut waited = false;
    loop {
        // The channel connects within 10 s but sets no request timeout, and a blackholed
        // address must not hold a restarting component back: an expired poll counts as no answer.
        let answer = tokio::time::timeout(POLL_TIMEOUT, ask())
            .await
            .unwrap_or(Err(Code::DeadlineExceeded));
        match verdict(own, answer.as_deref().map_err(|c| *c)) {
            Verdict::Go => {
                if waited {
                    tracing::info!(version = own, "the control plane is current; starting");
                }
                return;
            }
            Verdict::Skip(why) => {
                tracing::warn!("not waiting for the control plane: {why}");
                return;
            }
            Verdict::Wait(why) => {
                waited = true;
                let delay = backoff
                    .next_delay(rand::random())
                    .max(Duration::from_secs(1));
                tracing::warn!(
                    retry_in = ?delay,
                    "waiting for the control plane to be upgraded before starting: {why}"
                );
                tokio::time::sleep(delay).await;
            }
        }
    }
}

/// Ask the control plane behind `channel` for its version. `Err` is the status code of the failed call.
pub async fn control_plane_version(channel: Channel) -> Result<String, Code> {
    PolicySyncClient::new(channel)
        .get_server_version(GetServerVersionRequest {})
        .await
        .map(|r| r.into_inner().version)
        .map_err(|s| s.code())
}

/// [`wait_until_current`] against the control plane behind `channel` (a proxy's own channel, or a
/// worker's through its proxy). `channel` must present the component's certificate.
pub async fn wait_for_control_plane(own: &str, channel: impl Fn() -> anyhow::Result<Channel>) {
    wait_until_current(own, || async {
        control_plane_version(channel().map_err(|_| Code::Unavailable)?).await
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wait(why: &str) -> Verdict {
        Verdict::Wait(why.to_owned())
    }

    #[test]
    fn equal_versions_start() {
        assert_eq!(verdict("0.1.0", Ok("0.1.0")), Verdict::Go);
    }

    #[test]
    fn a_newer_control_plane_starts_and_an_older_one_waits() {
        assert_eq!(verdict("0.1.0", Ok("0.2.0")), Verdict::Go);
        assert_eq!(
            verdict("0.1.1", Ok("0.1.0")),
            wait("the control plane is at 0.1.0, this component at 0.1.1")
        );
    }

    #[test]
    fn a_release_candidate_is_older_than_its_release() {
        assert_eq!(verdict("0.1.0-rc.2", Ok("0.1.0")), Verdict::Go);
        assert!(matches!(
            verdict("0.1.0", Ok("0.1.0-rc.2")),
            Verdict::Wait(_)
        ));
        // Numeric pre-release identifiers compare as numbers: rc.10 is newer than rc.2.
        assert_eq!(verdict("0.1.0-rc.2", Ok("0.1.0-rc.10")), Verdict::Go);
        assert!(matches!(
            verdict("0.1.0-rc.10", Ok("0.1.0-rc.2")),
            Verdict::Wait(_)
        ));
    }

    #[test]
    fn build_metadata_and_a_leading_v_do_not_count() {
        assert_eq!(verdict("0.1.0+abc", Ok("v0.1.0+def")), Verdict::Go);
    }

    #[test]
    fn a_control_plane_without_the_call_is_older() {
        assert!(matches!(
            verdict("0.1.0", Err(Code::Unimplemented)),
            Verdict::Wait(_)
        ));
    }

    #[test]
    fn an_unreachable_or_unreadable_control_plane_does_not_hold_a_component_back() {
        for code in [
            Code::Unavailable,
            Code::DeadlineExceeded,
            Code::Unauthenticated,
            Code::Internal,
        ] {
            assert!(
                matches!(verdict("0.1.0", Err(code)), Verdict::Skip(_)),
                "{code:?}"
            );
        }
        assert!(matches!(
            verdict("0.1.0", Ok("not a version")),
            Verdict::Skip(_)
        ));
        assert!(matches!(verdict("dev", Ok("0.1.0")), Verdict::Skip(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn the_gate_waits_until_the_control_plane_catches_up() {
        let answers = std::sync::Mutex::new(vec![
            Ok("0.1.0".to_owned()),
            Err(Code::Unimplemented),
            Ok("0.0.9".to_owned()),
        ]);
        let calls = std::sync::atomic::AtomicUsize::new(0);
        wait_until_current("0.2.0", || {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // Three older answers, then the upgraded control plane.
            let next = answers
                .lock()
                .expect("lock")
                .pop()
                .unwrap_or_else(|| Ok("0.2.0".to_owned()));
            async move { next }
        })
        .await;
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 4);
    }

    #[tokio::test(start_paused = true)]
    async fn a_poll_that_never_answers_ends_the_wait() {
        // A blackholed control plane: the call never returns. After the poll timeout it counts
        // as no answer, and the component starts.
        let started = tokio::time::Instant::now();
        wait_until_current("0.2.0", std::future::pending::<Result<String, Code>>).await;
        assert_eq!(started.elapsed(), POLL_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn an_unreachable_control_plane_ends_the_wait_at_once() {
        let calls = std::sync::atomic::AtomicUsize::new(0);
        wait_until_current("0.2.0", || {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async { Err(Code::Unavailable) }
        })
        .await;
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
