//! Worker tunnels held by this proxy, and the load each worker carries.
//!
//! Load: each periodic ping tells us how many sessions a worker holds and
//! its cap ([`Load`]). Between pings, the sessions this proxy opens count at
//! once (so a burst of new sessions doesn't all land on the worker that
//! looked idlest at the last ping), and stop counting when they end. A ping
//! answer is split into "ours" (sessions this proxy holds open to that worker
//! right now) and "others" (everyone else's, as of that ping):
//! `active = others_at_last_ping + ours_now`.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use limen_tunnel::tunnel::TunnelChannel;
use serde::Serialize;
use time::OffsetDateTime;
use tokio::sync::Notify;

/// How a worker that reports no cap is weighed: workers before Phase 5 (they
/// report 0/0, and so count only the sessions this proxy opened) and workers
/// started with `--max-sessions 0`. With `x = active / K`, their load is `x`
/// up to 0.5 and `1 - 0.25 / x` beyond (continuous and smooth at 0.5,
/// always below 1). So they never fill; among themselves the less busy
/// wins; up to half of K they weigh exactly like a worker with the default
/// cap (200) and the same count; past that they take a growing share of the
/// overflow, as capped workers near their limit. In a mixed fleet, during a
/// rolling upgrade say, neither kind is starved or flooded.
pub const UNCAPPED_K: u32 = 200;

#[derive(Debug, Clone)]
pub struct Tunnel {
    pub worker_id: String,
    /// From the worker's certificate, so they can't be self-reported.
    pub labels: std::collections::BTreeMap<String, String>,
    pub tunnel_id: String,
    pub connected_at: OffsetDateTime,
    pub channel: TunnelChannel,
}

#[derive(Debug, Clone, Serialize)]
pub struct TunnelSummary {
    pub worker_id: String,
    pub tunnel_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub connected_at: OffsetDateTime,
    /// This proxy's view of the worker's load ([`Load`]).
    pub active_sessions: u32,
    pub max_sessions: u32,
}

/// Sessions a worker holds and its cap. `max == 0`: no cap known.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Load {
    pub active: u32,
    pub max: u32,
}

impl Load {
    #[must_use]
    pub fn is_full(self) -> bool {
        self.max > 0 && self.active >= self.max
    }

    /// `active / max`, which is at least 1.0 exactly when the worker is full;
    /// below 1.0 always without a cap (see [`UNCAPPED_K`]).
    #[must_use]
    pub fn ratio(self) -> f64 {
        if self.max == 0 {
            let x = f64::from(self.active) / f64::from(UNCAPPED_K);
            if x <= 0.5 { x } else { 1.0 - 0.25 / x }
        } else {
            f64::from(self.active) / f64::from(self.max)
        }
    }
}

/// Power of two choices: among the candidates whose load is below 1.0 (a
/// load of 1.0 or more is a full worker; NaN never qualifies), pick two at
/// random and keep the less loaded. Nearly as good as always taking the
/// least loaded, without every proxy herding onto the same worker when
/// their load figures are a little stale.
pub fn p2c<'a, T>(
    candidates: &'a [T],
    load: impl Fn(&T) -> f64,
    rng: &mut impl rand::Rng,
) -> Option<&'a T> {
    use rand::RngExt as _;
    let open: Vec<(&T, f64)> = candidates
        .iter()
        .map(|c| (c, load(c)))
        .filter(|(_, l)| *l < 1.0)
        .collect();
    match open.len() {
        0 => None,
        1 => Some(open[0].0),
        n => {
            let a = rng.random_range(0..n);
            // A second, different candidate.
            let b = (a + rng.random_range(1..n)) % n;
            let (a, b) = (open[a], open[b]);
            Some(if b.1 < a.1 { b.0 } else { a.0 })
        }
    }
}

/// Why no worker was picked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoWorker {
    /// No live tunnel to an eligible worker.
    None,
    /// Eligible workers exist, and every one is at its session cap.
    Full,
}

/// A session this proxy is opening (or has open) to a worker. It counts
/// towards the worker's load until dropped: hold it for the session's life.
#[derive(Debug)]
pub struct SessionSlot(Arc<AtomicU32>);

impl Drop for SessionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The worker [`Tunnels::pick`] chose.
#[derive(Debug)]
pub struct Picked {
    pub worker_id: String,
    pub channel: TunnelChannel,
    pub slot: SessionSlot,
}

#[derive(Debug, Default)]
struct WorkerLoad {
    /// Sessions other proxies held at the last ping (the ping's count minus ours then).
    others: u32,
    max: u32,
    /// Sessions this proxy holds open to the worker now.
    ours: Arc<AtomicU32>,
}

impl WorkerLoad {
    fn load(&self) -> Load {
        Load {
            active: self.others.saturating_add(self.ours.load(Ordering::SeqCst)),
            max: self.max,
        }
    }

    fn slot(&self) -> SessionSlot {
        self.ours.fetch_add(1, Ordering::SeqCst);
        SessionSlot(Arc::clone(&self.ours))
    }
}

#[derive(Debug, Default)]
struct State {
    tunnels: BTreeMap<String, Tunnel>,
    /// One entry per worker with at least one tunnel here; its tunnels share it.
    workers: HashMap<String, WorkerLoad>,
}

/// Tunnels by ID. `changed` fires whenever one is added or removed.
#[derive(Debug, Default, Clone)]
pub struct Tunnels {
    inner: Arc<Mutex<State>>,
    pub changed: Arc<Notify>,
}

impl Tunnels {
    pub fn insert(&self, tunnel: Tunnel) {
        {
            let mut state = self.lock();
            state.workers.entry(tunnel.worker_id.clone()).or_default();
            state.tunnels.insert(tunnel.tunnel_id.clone(), tunnel);
        }
        self.changed.notify_one();
    }

    pub fn remove(&self, tunnel_id: &str) {
        let removed = {
            let mut state = self.lock();
            let removed = state.tunnels.remove(tunnel_id);
            if let Some(t) = &removed
                && !state.tunnels.values().any(|o| o.worker_id == t.worker_id)
            {
                state.workers.remove(&t.worker_id);
            }
            removed.is_some()
        };
        if removed {
            self.changed.notify_one();
        }
    }

    /// Record what a worker's ping said. Ignored once the worker has no
    /// tunnel here.
    ///
    /// `ours` is read when the answer arrives, not when the worker counted:
    /// a session we opened that hadn't reached the worker yet (or one that
    /// ended there but not yet here) makes `others` read low for a moment.
    /// The next ping corrects it, and the worker enforces its cap anyway.
    pub fn record_ping(&self, worker_id: &str, active: u32, max: u32) {
        if let Some(w) = self.lock().workers.get_mut(worker_id) {
            w.others = active.saturating_sub(w.ours.load(Ordering::SeqCst));
            w.max = max;
        }
    }

    /// The worker refused a session as full although our figure said it had
    /// room (it was stale): count it as full until its next ping. No effect
    /// on a worker without a cap.
    pub fn mark_full(&self, worker_id: &str) {
        if let Some(w) = self.lock().workers.get_mut(worker_id)
            && w.max > 0
        {
            w.others = w.max.saturating_sub(w.ours.load(Ordering::SeqCst));
        }
    }

    /// This proxy's view of a worker's load, if it holds a tunnel to it.
    #[must_use]
    pub fn load(&self, worker_id: &str) -> Option<Load> {
        self.lock().workers.get(worker_id).map(WorkerLoad::load)
    }

    #[must_use]
    pub fn summaries(&self) -> Vec<TunnelSummary> {
        let state = self.lock();
        state
            .tunnels
            .values()
            .map(|t| {
                let load = state
                    .workers
                    .get(&t.worker_id)
                    .map(WorkerLoad::load)
                    .unwrap_or_default();
                TunnelSummary {
                    worker_id: t.worker_id.clone(),
                    tunnel_id: t.tunnel_id.clone(),
                    connected_at: t.connected_at,
                    active_sessions: load.active,
                    max_sessions: load.max,
                }
            })
            .collect()
    }

    /// A live tunnel to `worker_id`, if this proxy holds one.
    #[must_use]
    pub fn channel_for(&self, worker_id: &str) -> Option<TunnelChannel> {
        self.lock()
            .tunnels
            .values()
            .find(|t| t.worker_id == worker_id && !t.channel.is_closed())
            .map(|t| t.channel.clone())
    }

    /// A live tunnel to `worker_id` with a slot on it, for a session a peer
    /// proxy forwards here. `Err(Full)` when the worker is at its cap.
    pub fn reserve(&self, worker_id: &str) -> Result<(TunnelChannel, SessionSlot), NoWorker> {
        let state = self.lock();
        let channel = state
            .tunnels
            .values()
            .find(|t| t.worker_id == worker_id && !t.channel.is_closed())
            .map(|t| t.channel.clone())
            .ok_or(NoWorker::None)?;
        let worker = state.workers.get(worker_id).ok_or(NoWorker::None)?;
        if worker.load().is_full() {
            return Err(NoWorker::Full);
        }
        Ok((channel, worker.slot()))
    }

    /// A worker whose labels satisfy `accept` and that is not in `exclude`,
    /// chosen by [`p2c`] on load, with a live tunnel to it and a slot that
    /// counts the new session.
    pub fn pick(
        &self,
        accept: impl Fn(&std::collections::BTreeMap<String, String>) -> bool,
        exclude: &[String],
    ) -> Result<Picked, NoWorker> {
        let state = self.lock();
        // One candidate per eligible worker, whatever its tunnel count.
        let mut candidates: Vec<(&str, Vec<&TunnelChannel>, f64)> = Vec::new();
        let mut index: HashMap<&str, usize> = HashMap::new();
        for t in state.tunnels.values() {
            if t.channel.is_closed() || exclude.contains(&t.worker_id) || !accept(&t.labels) {
                continue;
            }
            if let Some(&i) = index.get(t.worker_id.as_str()) {
                candidates[i].1.push(&t.channel);
                continue;
            }
            let load = state
                .workers
                .get(&t.worker_id)
                .map_or(0.0, |w| w.load().ratio());
            index.insert(&t.worker_id, candidates.len());
            candidates.push((&t.worker_id, vec![&t.channel], load));
        }
        if candidates.is_empty() {
            return Err(NoWorker::None);
        }
        let mut rng = rand::rng();
        let (worker_id, channels, _) = p2c(&candidates, |c| c.2, &mut rng).ok_or(NoWorker::Full)?;
        // Spread a worker's sessions over its tunnels.
        let channel = channels[rand::RngExt::random_range(&mut rng, 0..channels.len())];
        let slot = state.workers.get(*worker_id).ok_or(NoWorker::None)?.slot();
        Ok(Picked {
            worker_id: (*worker_id).to_owned(),
            channel: channel.clone(),
            slot,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};

    use rand::SeedableRng;
    use rand::rngs::StdRng;

    use super::*;

    #[test]
    fn p2c_prefers_the_less_loaded() {
        let workers = [("light", 0.1), ("heavy", 0.9)];
        let mut rng = StdRng::seed_from_u64(7);
        let light = (0..1000)
            .filter(|_| p2c(&workers, |w| w.1, &mut rng).expect("a pick").0 == "light")
            .count();
        assert!(light > 700, "the worker at 10 % got {light} of 1000 picks");
    }

    #[test]
    fn full_workers_are_never_picked() {
        let workers = [("full", 1.0), ("over", 1.5), ("free", 0.99), ("idle", 0.0)];
        let mut rng = StdRng::seed_from_u64(1);
        for _ in 0..1000 {
            let pick = p2c(&workers, |w| w.1, &mut rng).expect("a pick").0;
            assert!(pick == "free" || pick == "idle", "picked {pick}");
        }
    }

    #[test]
    fn all_full_returns_none() {
        let mut rng = StdRng::seed_from_u64(3);
        assert!(p2c(&[1.0, 2.0, f64::NAN], |l| *l, &mut rng).is_none());
        assert!(p2c::<f64>(&[], |l| *l, &mut rng).is_none());
        assert_eq!(p2c(&[0.4], |l| *l, &mut rng), Some(&0.4));
    }

    #[test]
    fn p2c_draws_two_of_many() {
        // One light worker among three heavy ones is in the drawn pair half
        // the time (1 - C(3,2)/C(4,2)), and then always wins: about 50 % of
        // the picks, twice its 25 % share under a uniform pick.
        let workers = [("light", 0.1), ("a", 0.9), ("b", 0.9), ("c", 0.9)];
        let mut rng = StdRng::seed_from_u64(11);
        let mut counts = HashMap::new();
        for _ in 0..1000 {
            *counts
                .entry(p2c(&workers, |w| w.1, &mut rng).expect("a pick").0)
                .or_insert(0) += 1;
        }
        let light = counts["light"];
        assert!((430..=570).contains(&light), "light got {light} of 1000");
        for heavy in ["a", "b", "c"] {
            assert!(counts[heavy] > 100, "{heavy} got {} of 1000", counts[heavy]);
        }
    }

    #[test]
    fn uncapped_workers_compare_by_count() {
        // Workers before Phase 5 (and workers without a cap) report 0/0:
        // never full, and among themselves the less busy is less loaded.
        let old = Load { active: 0, max: 0 };
        assert!(!old.is_full());
        assert!(old.ratio().abs() < f64::EPSILON);
        assert!(Load { active: 10, max: 0 }.ratio() < Load { active: 50, max: 0 }.ratio());
        // Against a worker with the default cap, an uncapped one with the same
        // count weighs the same up to half of it, and less beyond.
        let capped = |active| Load { active, max: 200 }.ratio();
        let uncapped = |active| Load { active, max: 0 }.ratio();
        assert!((uncapped(50) - capped(50)).abs() < f64::EPSILON);
        assert!(uncapped(150) < capped(150));
        assert!(uncapped(1_000_000) < 1.0);
        assert!(uncapped(999) < uncapped(1000));
        assert!(
            Load { active: 0, max: 0 }.ratio()
                < Load {
                    active: 150,
                    max: 200
                }
                .ratio()
        );
        assert!(
            Load {
                active: 10,
                max: 200
            }
            .ratio()
                < Load {
                    active: 100,
                    max: 0
                }
                .ratio()
        );
        let busy_unlimited = Load {
            active: 10_000,
            max: 0,
        };
        assert!(!busy_unlimited.is_full());
        assert!(busy_unlimited.ratio() < 1.0);
        assert!(Load { active: 2, max: 2 }.is_full());
        assert!(Load { active: 3, max: 2 }.ratio() >= 1.0);
        assert!((Load { active: 1, max: 4 }.ratio() - 0.25).abs() < f64::EPSILON);
    }

    /// Sessions placed one after another on two capped and two uncapped
    /// workers: everybody gets a fair share, nobody is starved or flooded.
    fn shares(loads: &mut [Load], picks: usize, seed: u64) -> Vec<usize> {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut got = vec![0; loads.len()];
        let ids: Vec<usize> = (0..loads.len()).collect();
        for _ in 0..picks {
            let i = *p2c(&ids, |&i| loads[i].ratio(), &mut rng).expect("room");
            loads[i].active += 1;
            got[i] += 1;
        }
        got
    }

    #[test]
    fn mixed_and_uncapped_fleets_share_the_sessions() {
        let mut mixed = [
            Load {
                active: 0,
                max: 200,
            },
            Load {
                active: 0,
                max: 200,
            },
            Load { active: 0, max: 0 },
            Load { active: 0, max: 0 },
        ];
        for (i, n) in shares(&mut mixed, 400, 5).into_iter().enumerate() {
            assert!((70..=130).contains(&n), "worker {i} got {n} of 400");
        }
        // Past half of the default cap the uncapped ones take more of the
        // overflow, but the capped ones keep filling: the loads meet at
        // capped 150/200 = uncapped 1 - 0.25 / (200/200), i.e. 150 and 200
        // each of 700. (Simulated means: a fixed 0.5 for uncapped gives
        // 138 / 211, and active / (active + 200) gives 111 / 239.)
        let mut busy = [
            Load {
                active: 0,
                max: 200,
            },
            Load {
                active: 0,
                max: 200,
            },
            Load { active: 0, max: 0 },
            Load { active: 0, max: 0 },
        ];
        let got = shares(&mut busy, 700, 9);
        for (i, n) in got.iter().enumerate().take(2) {
            assert!((144..=158).contains(n), "capped worker {i} got {n} of 700");
        }
        for (i, n) in got.iter().enumerate().skip(2) {
            assert!(
                (192..=206).contains(n),
                "uncapped worker {i} got {n} of 700"
            );
        }
        let mut uncapped = [Load::default(); 4];
        for (i, n) in shares(&mut uncapped, 400, 6).into_iter().enumerate() {
            assert!((70..=130).contains(&n), "worker {i} got {n} of 400");
        }
    }

    /// A tunnel channel over an in-memory pipe; nothing answers on it, but
    /// it stays open as long as the test holds the other end.
    async fn channel() -> (TunnelChannel, tokio::io::DuplexStream) {
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        let (channel, connection) =
            TunnelChannel::handshake(ours, limen_tunnel::serve::H2Settings::default())
                .await
                .expect("handshake");
        tokio::spawn(connection);
        (channel, theirs)
    }

    async fn add(tunnels: &Tunnels, worker: &str, tunnel: &str) -> tokio::io::DuplexStream {
        let (channel, end) = channel().await;
        tunnels.insert(Tunnel {
            worker_id: worker.into(),
            labels: BTreeMap::new(),
            tunnel_id: tunnel.into(),
            connected_at: OffsetDateTime::now_utc(),
            channel,
        });
        end
    }

    #[tokio::test]
    async fn an_old_worker_without_load_reports_is_picked_and_never_full() {
        let tunnels = Tunnels::default();
        let _end = add(&tunnels, "old", "t1").await;
        tunnels.record_ping("old", 0, 0);
        let mut held = Vec::new();
        for _ in 0..50 {
            let picked = tunnels
                .pick(|_| true, &[])
                .expect("an old worker has no cap");
            assert_eq!(picked.worker_id, "old");
            held.push(picked);
        }
        assert_eq!(tunnels.load("old"), Some(Load { active: 50, max: 0 }));
    }

    #[tokio::test]
    async fn sessions_opened_since_the_last_ping_count_and_are_not_counted_twice() {
        let tunnels = Tunnels::default();
        let _a = add(&tunnels, "w", "t1").await;
        let _b = add(&tunnels, "w", "t2").await;
        tunnels.record_ping("w", 1, 3);
        assert_eq!(tunnels.load("w"), Some(Load { active: 1, max: 3 }));

        // Both tunnels share one load: two picks fill the worker before any ping.
        let first = tunnels.pick(|_| true, &[]).expect("room");
        let second = tunnels.pick(|_| true, &[]).expect("room");
        assert_eq!(tunnels.load("w"), Some(Load { active: 3, max: 3 }));
        assert_eq!(
            tunnels.pick(|_| true, &[]).err(),
            Some(NoWorker::Full),
            "full between pings"
        );

        // The next ping includes our two sessions: still 3, not 5.
        tunnels.record_ping("w", 3, 3);
        assert_eq!(tunnels.load("w"), Some(Load { active: 3, max: 3 }));

        // One of ours ends: room again at once, without waiting for a ping.
        drop(first);
        assert_eq!(tunnels.load("w"), Some(Load { active: 2, max: 3 }));
        let third = tunnels
            .pick(|_| true, &[])
            .expect("room after a session ended");
        drop((second, third));
        assert_eq!(tunnels.load("w"), Some(Load { active: 1, max: 3 }));
    }

    #[tokio::test]
    async fn no_eligible_worker_is_not_a_capacity_problem() {
        let tunnels = Tunnels::default();
        assert_eq!(tunnels.pick(|_| true, &[]).err(), Some(NoWorker::None));
        let _end = add(&tunnels, "w", "t1").await;
        assert_eq!(tunnels.pick(|_| false, &[]).err(), Some(NoWorker::None));
        tunnels.record_ping("w", 5, 5);
        assert_eq!(tunnels.pick(|_| true, &[]).err(), Some(NoWorker::Full));
        // Reserving a named worker (a peer's forwarded session) honors the cap.
        assert!(tunnels.reserve("w").is_err());
        tunnels.record_ping("w", 4, 5);
        assert!(tunnels.reserve("w").is_ok());
        assert!(tunnels.reserve("missing").is_err());
    }

    #[tokio::test]
    async fn refused_workers_are_excluded_and_counted_full_until_the_next_ping() {
        let tunnels = Tunnels::default();
        let _a = add(&tunnels, "a", "t1").await;
        let _b = add(&tunnels, "b", "t2").await;
        tunnels.record_ping("a", 0, 2);
        tunnels.record_ping("b", 0, 2);
        for _ in 0..50 {
            let picked = tunnels.pick(|_| true, &["a".to_owned()]).expect("b");
            assert_eq!(picked.worker_id, "b");
        }
        assert_eq!(
            tunnels
                .pick(|_| true, &["a".to_owned(), "b".to_owned()])
                .err(),
            Some(NoWorker::None),
            "nothing left to try"
        );
        // A worker that refused as full while our figure said it had room.
        let held = tunnels.pick(|_| true, &["b".to_owned()]).expect("a");
        tunnels.mark_full("a");
        assert_eq!(tunnels.load("a"), Some(Load { active: 2, max: 2 }));
        drop(held);
        assert_eq!(tunnels.load("a"), Some(Load { active: 1, max: 2 }));
        tunnels.record_ping("a", 0, 2);
        assert_eq!(tunnels.load("a"), Some(Load { active: 0, max: 2 }));
        // Uncapped workers can't be marked full.
        tunnels.record_ping("b", 0, 0);
        tunnels.mark_full("b");
        assert_eq!(tunnels.load("b"), Some(Load { active: 0, max: 0 }));
    }

    #[tokio::test]
    async fn the_load_is_forgotten_with_the_last_tunnel_and_reported_per_tunnel() {
        let tunnels = Tunnels::default();
        let _a = add(&tunnels, "w", "t1").await;
        let _b = add(&tunnels, "w", "t2").await;
        tunnels.record_ping("w", 2, 10);
        let summaries = tunnels.summaries();
        assert_eq!(summaries.len(), 2);
        assert!(
            summaries
                .iter()
                .all(|s| s.active_sessions == 2 && s.max_sessions == 10)
        );
        tunnels.remove("t1");
        assert_eq!(tunnels.load("w"), Some(Load { active: 2, max: 10 }));
        tunnels.remove("t2");
        assert_eq!(tunnels.load("w"), None);
        // A late ping from a tunnel already removed changes nothing.
        tunnels.record_ping("w", 1, 10);
        assert_eq!(tunnels.load("w"), None);
    }
}
