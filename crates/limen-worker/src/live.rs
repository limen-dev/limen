//! Letting an authorised person watch a live SSH session (ADR-0030).
//!
//! The worker already holds the plaintext it records, so it is the one that
//! can publish it. **The user's session always wins**: output goes into a
//! small ring and, only while someone is watching, into a bounded buffer a
//! background task ships to the control plane. A slow control plane, a slow
//! watcher, or none at all makes the buffers drop; nothing here ever blocks
//! the session. Only output is ever published, never input.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use limen_proto::v1::watch_client::WatchClient;
use limen_proto::v1::{WatchPollRequest, WatchPublishRequest};
use tokio::sync::watch;

/// Recent output kept so a watcher who joins sees the screen's recent past.
const RING_BYTES: usize = 16 * 1024;
/// The most output waiting to be shipped; past it the oldest is dropped.
const PENDING_BYTES: usize = 256 * 1024;
/// The largest piece sent in one call.
const CHUNK_BYTES: usize = 32 * 1024;
const FLUSH_EVERY: Duration = Duration::from_millis(300);
const POLL_EVERY: Duration = Duration::from_secs(2);

#[derive(Debug, Default)]
struct State {
    ring: VecDeque<u8>,
    pending: Vec<u8>,
    cols: u32,
    rows: u32,
}

#[derive(Debug)]
struct Inner {
    session_id: String,
    started: Instant,
    active: AtomicBool,
    state: Mutex<State>,
    hub: Arc<Hub>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.hub
            .taps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.session_id);
    }
}

/// One session's output, as the bridge sees it. Cloning shares it; the hub
/// forgets the session when the last clone goes.
#[derive(Debug, Clone)]
pub struct Tap(Arc<Inner>);

impl Tap {
    /// Terminal output. Cheap when nobody is watching.
    pub fn output(&self, data: &[u8]) {
        let mut s = self
            .0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        s.ring.extend(data);
        let over = s.ring.len().saturating_sub(RING_BYTES);
        s.ring.drain(..over);
        if self.0.active.load(Ordering::Relaxed) {
            s.pending.extend_from_slice(data);
            if s.pending.len() > PENDING_BYTES {
                // The watcher is behind: skip ahead rather than grow.
                let drop = s.pending.len() - PENDING_BYTES;
                s.pending.drain(..drop);
            }
        }
    }

    pub fn resize(&self, cols: u32, rows: u32) {
        let mut s = self
            .0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        s.cols = cols;
        s.rows = rows;
    }
}

/// All the taps of this worker, and the task that serves them.
#[derive(Debug, Default)]
pub struct Hub {
    taps: Mutex<HashMap<String, std::sync::Weak<Inner>>>,
}

impl Hub {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    #[must_use]
    pub fn tap(self: &Arc<Self>, session_id: &str) -> Tap {
        let inner = Arc::new(Inner {
            session_id: session_id.to_owned(),
            started: Instant::now(),
            active: AtomicBool::new(false),
            state: Mutex::new(State {
                cols: 80,
                rows: 24,
                ..State::default()
            }),
            hub: Arc::clone(self),
        });
        self.taps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(session_id.to_owned(), Arc::downgrade(&inner));
        Tap(inner)
    }

    fn live(&self) -> Vec<Arc<Inner>> {
        self.taps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .filter_map(std::sync::Weak::upgrade)
            .collect()
    }
}

/// The text of the longest valid UTF-8 prefix of `bytes`; the rest (a
/// character cut in half) is returned to wait for its other half.
fn split_utf8(bytes: &[u8]) -> (String, usize) {
    match std::str::from_utf8(bytes) {
        Ok(s) => (s.to_owned(), bytes.len()),
        Err(e) => {
            let valid = e.valid_up_to();
            // An incomplete character at the very end waits; bytes that can
            // never be valid are replaced and skipped.
            if e.error_len().is_none() {
                (String::from_utf8_lossy(&bytes[..valid]).into_owned(), valid)
            } else {
                (String::from_utf8_lossy(bytes).into_owned(), bytes.len())
            }
        }
    }
}

/// Serve the taps: ask who is being watched, and ship their output.
pub async fn run(
    hub: Arc<Hub>,
    mut channel: impl FnMut() -> anyhow::Result<tonic::transport::Channel> + Send + 'static,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut tick = tokio::time::interval(FLUSH_EVERY);
    let mut last_poll = Instant::now()
        .checked_sub(POLL_EVERY)
        .unwrap_or_else(Instant::now);
    let mut client: Option<WatchClient<tonic::transport::Channel>> = None;
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = shutdown.changed() => return,
        }
        let taps = hub.live();
        if taps.is_empty() {
            continue;
        }
        if client.is_none() {
            client = channel().ok().map(WatchClient::new);
        }
        let Some(c) = client.as_mut() else { continue };
        if last_poll.elapsed() >= POLL_EVERY {
            last_poll = Instant::now();
            let ids: Vec<String> = taps.iter().map(|t| t.session_id.clone()).collect();
            match c.poll(WatchPollRequest { session_ids: ids }).await {
                Ok(r) => {
                    let watched = r.into_inner().watched;
                    for t in &taps {
                        let on = watched.contains(&t.session_id);
                        let was = t.active.swap(on, Ordering::Relaxed);
                        if on && !was {
                            // Someone just started watching: begin with the recent screen.
                            let mut s = t
                                .state
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            s.pending = s.ring.iter().copied().collect();
                        } else if !on && was {
                            t.state
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .pending
                                .clear();
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!(error = %e, "polling for watchers failed");
                    drop(taps);
                    client = None;
                    continue;
                }
            }
        }
        let mut broken = false;
        for t in taps.iter().filter(|t| t.active.load(Ordering::Relaxed)) {
            loop {
                let (text, cols, rows) = {
                    let mut s = t
                        .state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if s.pending.is_empty() {
                        break;
                    }
                    let take = s.pending.len().min(CHUNK_BYTES);
                    let (text, used) = split_utf8(&s.pending[..take]);
                    if used == 0 {
                        break;
                    }
                    s.pending.drain(..used);
                    (text, s.cols, s.rows)
                };
                if text.is_empty() {
                    continue;
                }
                let sent = c
                    .publish(WatchPublishRequest {
                        session_id: t.session_id.clone(),
                        text,
                        elapsed_ms: u64::try_from(t.started.elapsed().as_millis())
                            .unwrap_or(u64::MAX),
                        cols,
                        rows,
                    })
                    .await;
                match sent {
                    Ok(r) => {
                        if !r.into_inner().watched {
                            t.active.store(false, Ordering::Relaxed);
                            t.state
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .pending
                                .clear();
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "publishing output failed");
                        broken = true;
                        break;
                    }
                }
            }
            if broken {
                break;
            }
        }
        if broken {
            client = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_character_cut_in_half_waits_for_its_other_half() {
        let s = "héllo".as_bytes();
        // 'é' is two bytes: cutting after its first leaves it behind.
        let (text, used) = split_utf8(&s[..2]);
        assert_eq!((text.as_str(), used), ("h", 1));
        let (text, used) = split_utf8(s);
        assert_eq!((text.as_str(), used), ("héllo", s.len()));
        // Bytes that can never be text are replaced, not stuck on.
        let (text, used) = split_utf8(&[b'a', 0xff, b'b']);
        assert_eq!(used, 3);
        assert!(text.starts_with('a') && text.ends_with('b'));
    }

    #[test]
    fn nothing_is_kept_to_ship_until_someone_watches_and_the_ring_is_bounded() {
        let hub = Hub::new();
        let tap = hub.tap("s1");
        tap.output(&vec![b'x'; RING_BYTES + 1000]);
        {
            let s = tap.0.state.lock().expect("lock");
            assert_eq!(s.ring.len(), RING_BYTES);
            assert!(s.pending.is_empty(), "no watcher, no buffer");
        }
        tap.0.active.store(true, Ordering::Relaxed);
        tap.output(&vec![b'y'; PENDING_BYTES + 10]);
        assert_eq!(
            tap.0.state.lock().expect("lock").pending.len(),
            PENDING_BYTES,
            "a lagging watcher drops, never grows"
        );
    }

    #[test]
    fn the_hub_forgets_a_session_when_it_ends() {
        let hub = Hub::new();
        let tap = hub.tap("s1");
        let more = tap.clone();
        assert_eq!(hub.live().len(), 1);
        drop(tap);
        assert_eq!(hub.live().len(), 1, "a clone is still out");
        drop(more);
        assert!(hub.live().is_empty());
    }
}
