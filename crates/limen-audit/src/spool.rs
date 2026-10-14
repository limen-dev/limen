//! A durable, local, append-only log of audit events (ADR-0009).
//!
//! Records are numbered from 0 and stored in segment files named after the
//! number of their first record. Each record is
//!
//! ```text
//! u32 length (big-endian) | u32 CRC-32 of the payload | payload
//! ```
//!
//! `append` returns only once the record is on disk: appends are written
//! immediately and fsynced in groups (every `fsync_interval`), so many
//! concurrent appends share one fsync. Each consumer (a shipper to the
//! control plane, S3, or Datadog) has a durable offset. A segment is deleted
//! once every consumer has moved past it.
//!
//! On open, a torn write at the end of the last segment (a crash mid-append)
//! is truncated. Earlier corruption is an error: we never skip records silently.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{Notify, watch};

const HEADER: u64 = 8;
/// A single event is small; refuse anything absurd.
pub const MAX_RECORD: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct SpoolConfig {
    pub dir: PathBuf,
    /// Roll to a new segment after this many bytes.
    pub segment_bytes: u64,
    /// Refuse appends once the spool holds this many bytes (ADR-0009: fail
    /// closed, or degrade, at the emitter).
    pub max_bytes: u64,
    pub fsync_interval: Duration,
    /// Consumers that must read every record before it can be deleted.
    pub consumers: Vec<String>,
}

impl SpoolConfig {
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>, consumers: &[&str]) -> Self {
        Self {
            dir: dir.into(),
            segment_bytes: 16 * 1024 * 1024,
            max_bytes: 1024 * 1024 * 1024,
            fsync_interval: Duration::from_millis(10),
            consumers: consumers.iter().map(|c| (*c).to_owned()).collect(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SpoolError {
    #[error("spool I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("spool is full ({used} of {max} bytes)")]
    Full { used: u64, max: u64 },
    #[error("record of {0} bytes exceeds the limit")]
    TooLarge(usize),
    #[error("spool corrupt in {segment}: {reason}")]
    Corrupt { segment: String, reason: String },
    #[error("unknown consumer {0:?}")]
    UnknownConsumer(String),
    #[error("spool closed")]
    Closed,
}

#[derive(Debug)]
struct Segment {
    first: u64,
    /// Number of records in it.
    count: u64,
    bytes: u64,
    path: PathBuf,
}

#[derive(Debug)]
struct State {
    segments: Vec<Segment>,
    active: File,
    /// Next record number to assign.
    next: u64,
    /// Records written but maybe not yet fsynced: `written` up to `next`.
    dirty: bool,
    offsets: BTreeMap<String, u64>,
}

#[derive(Debug, Clone)]
pub struct Spool {
    config: Arc<SpoolConfig>,
    state: Arc<Mutex<State>>,
    /// Everything below this record number is durable.
    synced: watch::Sender<u64>,
    /// Woken on every durable append, for consumers tailing the spool.
    pub(crate) appended: Arc<Notify>,
}

fn segment_name(first: u64) -> String {
    format!("{first:020}.log")
}

fn corrupt(path: &Path, reason: impl Into<String>) -> SpoolError {
    SpoolError::Corrupt {
        segment: path.display().to_string(),
        reason: reason.into(),
    }
}

/// Read records from `file` starting at its current position. Returns the
/// payloads and the byte offset just past the last complete, valid record.
fn scan(
    file: &mut File,
    path: &Path,
    limit: Option<u64>,
) -> Result<(Vec<Vec<u8>>, u64, bool), SpoolError> {
    let mut records = Vec::new();
    let mut pos = file.stream_position()?;
    let len = file.metadata()?.len();
    let mut torn = false;
    while pos < len && limit.is_none_or(|l| (records.len() as u64) < l) {
        let mut header = [0u8; 8];
        if len - pos < HEADER || file.read_exact(&mut header).is_err() {
            torn = true;
            break;
        }
        let size = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let crc = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
        if size > MAX_RECORD || len - pos - HEADER < size as u64 {
            torn = true;
            break;
        }
        let mut payload = vec![0u8; size];
        file.read_exact(&mut payload)?;
        if crc32fast::hash(&payload) != crc {
            torn = true;
            break;
        }
        pos += HEADER + size as u64;
        records.push(payload);
    }
    // The caller decides whether a bad tail is a crash artifact or corruption.
    let _ = path;
    Ok((records, pos, torn))
}

impl Spool {
    /// Open (or create) the spool, recovering from a crash mid-append.
    pub fn open(config: SpoolConfig) -> Result<Self, SpoolError> {
        let seg_dir = config.dir.join("segments");
        let off_dir = config.dir.join("offsets");
        std::fs::create_dir_all(&seg_dir)?;
        std::fs::create_dir_all(&off_dir)?;

        let mut firsts: Vec<u64> = std::fs::read_dir(&seg_dir)?
            .filter_map(Result::ok)
            .filter_map(|e| e.file_name().to_str()?.strip_suffix(".log")?.parse().ok())
            .collect();
        firsts.sort_unstable();

        let mut segments = Vec::new();
        for (i, first) in firsts.iter().enumerate() {
            let path = seg_dir.join(segment_name(*first));
            let mut file = File::open(&path)?;
            let (records, valid_end, torn) = scan(&mut file, &path, None)?;
            let is_last = i + 1 == firsts.len();
            if torn {
                if !is_last {
                    return Err(corrupt(&path, "invalid record before the last segment"));
                }
                // A crash mid-append: drop the partial record. (A CRC failure
                // in the last segment is treated the same way; it can't be
                // told apart from a torn write, so it's logged loudly.)
                let dropped = file.metadata()?.len() - valid_end;
                tracing::warn!(segment = %path.display(), valid_end, dropped_bytes = dropped, "truncating a torn record at the end of the spool");
                OpenOptions::new()
                    .write(true)
                    .open(&path)?
                    .set_len(valid_end)?;
            }
            if let Some(prev) = segments.last()
                && Self::end(prev) != *first
            {
                return Err(corrupt(&path, "gap between segments"));
            }
            segments.push(Segment {
                first: *first,
                count: records.len() as u64,
                bytes: valid_end,
                path,
            });
        }

        let next = segments.last().map_or(0, Self::end);
        if segments
            .last()
            .is_none_or(|s| s.bytes >= config.segment_bytes)
        {
            let path = seg_dir.join(segment_name(next));
            File::create(&path)?.sync_all()?;
            sync_dir(&seg_dir)?;
            segments.push(Segment {
                first: next,
                count: 0,
                bytes: 0,
                path,
            });
        }
        let active_path = &segments
            .last()
            .ok_or_else(|| corrupt(&seg_dir, "no segments"))?
            .path;
        let active = OpenOptions::new().append(true).open(active_path)?;

        let mut offsets = BTreeMap::new();
        let oldest = segments.first().map_or(0, |s| s.first);
        for consumer in &config.consumers {
            let path = off_dir.join(consumer);
            let offset = match std::fs::read_to_string(&path) {
                Ok(s) => s.trim().parse().map_err(|_| corrupt(&path, "bad offset"))?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => oldest,
                Err(e) => return Err(e.into()),
            };
            // A consumer added later starts at the oldest retained record.
            offsets.insert(consumer.clone(), offset.clamp(oldest, next));
        }

        let (synced, _) = watch::channel(next);
        let spool = Self {
            config: Arc::new(config),
            state: Arc::new(Mutex::new(State {
                segments,
                active,
                next,
                dirty: false,
                offsets,
            })),
            synced,
            appended: Arc::new(Notify::new()),
        };
        Ok(spool)
    }

    fn end(s: &Segment) -> u64 {
        s.first + s.count
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Start the group-commit flusher. Call once, inside a tokio runtime.
    pub fn start(&self) {
        let spool = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(spool.config.fsync_interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                if let Err(e) = spool.flush().await {
                    tracing::error!(error = %e, "spool fsync failed");
                }
            }
        });
    }

    /// fsync whatever has been written, and publish the new durable point.
    pub async fn flush(&self) -> Result<(), SpoolError> {
        let (file, upto) = {
            let mut st = self.lock();
            if !st.dirty {
                return Ok(());
            }
            st.dirty = false;
            (st.active.try_clone()?, st.next)
        };
        tokio::task::spawn_blocking(move || file.sync_data())
            .await
            .map_err(|e| SpoolError::Io(std::io::Error::other(e)))??;
        self.synced.send_if_modified(|v| {
            let changed = upto > *v;
            *v = (*v).max(upto);
            changed
        });
        self.appended.notify_waiters();
        Ok(())
    }

    /// Append a record and wait until it's durable. Returns its number.
    pub async fn append(&self, payload: &[u8]) -> Result<u64, SpoolError> {
        if payload.len() > MAX_RECORD {
            return Err(SpoolError::TooLarge(payload.len()));
        }
        let index = {
            let mut st = self.lock();
            let used: u64 = st.segments.iter().map(|s| s.bytes).sum();
            if used + HEADER + payload.len() as u64 > self.config.max_bytes {
                return Err(SpoolError::Full {
                    used,
                    max: self.config.max_bytes,
                });
            }
            let mut buf = Vec::with_capacity(payload.len() + 8);
            buf.extend_from_slice(
                &u32::try_from(payload.len())
                    .unwrap_or(u32::MAX)
                    .to_be_bytes(),
            );
            buf.extend_from_slice(&crc32fast::hash(payload).to_be_bytes());
            buf.extend_from_slice(payload);
            st.active.write_all(&buf)?;
            let index = st.next;
            st.next += 1;
            st.dirty = true;
            let seg = st.segments.last_mut().ok_or(SpoolError::Closed)?;
            seg.count += 1;
            seg.bytes += buf.len() as u64;
            if seg.bytes >= self.config.segment_bytes {
                self.roll(&mut st)?;
            }
            index
        };
        let mut rx = self.synced.subscribe();
        rx.wait_for(|synced| *synced > index)
            .await
            .map_err(|_| SpoolError::Closed)?;
        Ok(index)
    }

    /// Close the active segment (fsynced) and start a new one.
    fn roll(&self, st: &mut State) -> Result<(), SpoolError> {
        st.active.sync_data()?;
        let next = st.next;
        let path = self.config.dir.join("segments").join(segment_name(next));
        let file = OpenOptions::new()
            .create_new(true)
            .append(true)
            .open(&path)?;
        file.sync_all()?;
        sync_dir(&self.config.dir.join("segments"))?;
        st.active = file;
        st.segments.push(Segment {
            first: next,
            count: 0,
            bytes: 0,
            path,
        });
        // Everything in the old segment is durable now.
        self.synced.send_if_modified(|v| {
            let changed = next > *v;
            *v = (*v).max(next);
            changed
        });
        Ok(())
    }

    /// Up to `max` durable records for `consumer`, starting at its offset.
    pub fn read(&self, consumer: &str, max: usize) -> Result<Vec<(u64, Vec<u8>)>, SpoolError> {
        let synced = *self.synced.borrow();
        let st = self.lock();
        let start = *st
            .offsets
            .get(consumer)
            .ok_or_else(|| SpoolError::UnknownConsumer(consumer.to_owned()))?;
        let mut out = Vec::new();
        for seg in &st.segments {
            if Self::end(seg) <= start || seg.first >= synced || out.len() >= max {
                continue;
            }
            let mut file = File::open(&seg.path)?;
            let want = Self::end(seg).min(synced) - seg.first;
            let (records, _, _) = scan(&mut file, &seg.path, Some(want))?;
            for (i, payload) in records.into_iter().enumerate() {
                let index = seg.first + i as u64;
                if index >= start && index < synced && out.len() < max {
                    out.push((index, payload));
                }
            }
        }
        Ok(out)
    }

    /// Record that `consumer` has durably handled every record below `upto`,
    /// then delete segments no consumer needs.
    pub fn commit(&self, consumer: &str, upto: u64) -> Result<(), SpoolError> {
        let mut st = self.lock();
        let current = *st
            .offsets
            .get(consumer)
            .ok_or_else(|| SpoolError::UnknownConsumer(consumer.to_owned()))?;
        if upto <= current {
            return Ok(());
        }
        let upto = upto.min(st.next);
        let path = self.config.dir.join("offsets").join(consumer);
        let tmp = path.with_extension("tmp");
        let mut f = File::create(&tmp)?;
        f.write_all(upto.to_string().as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, &path)?;
        st.offsets.insert(consumer.to_owned(), upto);

        let min = st.offsets.values().copied().min().unwrap_or(upto);
        while st.segments.len() > 1 && Self::end(&st.segments[0]) <= min {
            let seg = st.segments.remove(0);
            std::fs::remove_file(&seg.path)?;
        }
        Ok(())
    }

    /// Wait until there may be new durable records, or `timeout` passes.
    pub async fn wait_for_data(&self, timeout: Duration) {
        let _ = tokio::time::timeout(timeout, self.appended.notified()).await;
    }

    /// Records waiting for `consumer`.
    #[must_use]
    pub fn pending(&self, consumer: &str) -> u64 {
        let st = self.lock();
        st.offsets
            .get(consumer)
            .map_or(0, |o| st.next.saturating_sub(*o))
    }

    /// Bytes on disk.
    #[must_use]
    pub fn used_bytes(&self) -> u64 {
        self.lock().segments.iter().map(|s| s.bytes).sum()
    }

    #[must_use]
    pub fn config(&self) -> &SpoolConfig {
        &self.config
    }
}

fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(dir: &Path) -> SpoolConfig {
        let mut c = SpoolConfig::new(dir, &["a", "b"]);
        c.segment_bytes = 256;
        c.fsync_interval = Duration::from_millis(2);
        c
    }

    #[tokio::test]
    async fn append_read_commit_and_segment_cleanup() {
        let dir = tempfile::tempdir().expect("dir");
        let spool = Spool::open(config(dir.path())).expect("open");
        spool.start();
        for i in 0..50 {
            assert_eq!(
                spool
                    .append(format!("event-{i}").as_bytes())
                    .await
                    .expect("append"),
                i
            );
        }
        let segments_before = std::fs::read_dir(dir.path().join("segments"))
            .expect("ls")
            .count();
        assert!(segments_before > 3, "small segments roll");

        let batch = spool.read("a", 10).expect("read");
        assert_eq!(batch.len(), 10);
        assert_eq!(batch[0], (0, b"event-0".to_vec()));
        spool.commit("a", 50).expect("commit a");
        // b hasn't read anything, so nothing can be deleted yet.
        assert_eq!(
            std::fs::read_dir(dir.path().join("segments"))
                .expect("ls")
                .count(),
            segments_before
        );
        assert_eq!(spool.pending("b"), 50);
        spool.commit("b", 50).expect("commit b");
        assert!(
            std::fs::read_dir(dir.path().join("segments"))
                .expect("ls")
                .count()
                < segments_before
        );
        assert_eq!(spool.read("a", 10).expect("read"), vec![]);
    }

    #[tokio::test]
    async fn survives_restart_and_truncates_a_torn_tail() {
        let dir = tempfile::tempdir().expect("dir");
        {
            let spool = Spool::open(config(dir.path())).expect("open");
            spool.start();
            for i in 0..5u8 {
                spool.append(&[i; 10]).await.expect("append");
            }
            spool.commit("a", 2).expect("commit");
        }
        // Simulate a crash mid-append: half a record at the end.
        let last = std::fs::read_dir(dir.path().join("segments"))
            .expect("ls")
            .filter_map(Result::ok)
            .map(|e| e.path())
            .max()
            .expect("segment");
        let mut f = OpenOptions::new().append(true).open(&last).expect("open");
        f.write_all(&[0, 0, 0, 50, 1, 2, 3]).expect("torn write");

        let spool = Spool::open(config(dir.path())).expect("reopen");
        spool.start();
        let a = spool.read("a", 100).expect("read a");
        assert_eq!(
            a.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
            [2, 3, 4],
            "offsets survive a restart"
        );
        assert_eq!(spool.read("b", 100).expect("read b").len(), 5);
        assert_eq!(
            spool.append(b"after").await.expect("append"),
            5,
            "numbering continues after the torn tail"
        );
    }

    #[tokio::test]
    async fn refuses_when_full_and_corruption_mid_spool_is_an_error() {
        let dir = tempfile::tempdir().expect("dir");
        let mut c = config(dir.path());
        c.max_bytes = 100;
        let spool = Spool::open(c.clone()).expect("open");
        spool.start();
        spool.append(&[1; 40]).await.expect("fits");
        assert!(matches!(
            spool.append(&[2; 60]).await,
            Err(SpoolError::Full { .. })
        ));
        drop(spool);

        // Flip a byte in a non-final segment.
        let dir2 = tempfile::tempdir().expect("dir");
        {
            let spool = Spool::open(config(dir2.path())).expect("open");
            spool.start();
            for _ in 0..30 {
                spool.append(&[7; 20]).await.expect("append");
            }
        }
        let mut segs: Vec<_> = std::fs::read_dir(dir2.path().join("segments"))
            .expect("ls")
            .filter_map(Result::ok)
            .map(|e| e.path())
            .collect();
        segs.sort();
        let mut bytes = std::fs::read(&segs[0]).expect("read");
        bytes[12] ^= 0xff;
        std::fs::write(&segs[0], bytes).expect("write");
        assert!(matches!(
            Spool::open(config(dir2.path())),
            Err(SpoolError::Corrupt { .. })
        ));
    }

    #[tokio::test]
    async fn concurrent_appends_share_fsyncs_and_all_land() {
        let dir = tempfile::tempdir().expect("dir");
        let mut c = config(dir.path());
        c.segment_bytes = 1024 * 1024;
        let spool = Spool::open(c).expect("open");
        spool.start();
        let tasks: Vec<_> = (0..200)
            .map(|i| {
                let spool = spool.clone();
                tokio::spawn(async move { spool.append(format!("{i}").as_bytes()).await })
            })
            .collect();
        let mut indexes: Vec<u64> = Vec::new();
        for t in tasks {
            indexes.push(t.await.expect("join").expect("append"));
        }
        indexes.sort_unstable();
        assert_eq!(indexes, (0..200).collect::<Vec<_>>());
        assert_eq!(spool.read("a", 1000).expect("read").len(), 200);
    }
}
