//! An upgraded `exec`, `attach`, or `port-forward` stream.
//!
//! The bytes between kubectl and the API server are copied untouched. A copy
//! goes through [`limen_kube::StreamDecoder`], and what it finds is recorded
//! (exec and attach) or counted (port-forward). If the stream cannot be
//! decoded or the recording cannot be written, the session ends: a stream we
//! cannot record is a stream we do not carry.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use limen_audit::{Context, EventKind};
use limen_kube::{Event, StreamDecoder, StreamKind};
use serde_json::json;
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::Admitted;
use crate::Worker;
use crate::recording::Recorder;

const CHUNK: usize = 16 * 1024;

/// What the session is, for the audit trail and the recording.
pub(super) struct StreamInfo {
    pub kind: StreamKind,
    /// `exec`, `attach`, or `portforward`.
    pub subresource: &'static str,
    pub namespace: String,
    pub pod: String,
    pub container: String,
    pub command: String,
    pub query_ports: Vec<u16>,
}

impl StreamInfo {
    fn records(&self) -> bool {
        self.subresource != "portforward"
    }

    fn title(&self) -> String {
        match self.subresource {
            "exec" => format!(
                "kubectl exec {}/{} -- {}",
                self.namespace, self.pod, self.command
            ),
            other => format!("kubectl {other} {}/{}", self.namespace, self.pod),
        }
    }
}

/// Shared by both directions.
struct State {
    decoder: StreamDecoder,
    recorder: Option<Recorder>,
    exit: Option<u32>,
    ports: Vec<u16>,
}

impl State {
    fn apply(&mut self, events: Vec<Event>) -> std::io::Result<()> {
        for event in events {
            match event {
                Event::Output(bytes) => {
                    if let Some(r) = &mut self.recorder {
                        r.output(&bytes)?;
                    }
                }
                Event::Resize { cols, rows } => {
                    if let Some(r) = &mut self.recorder {
                        r.resize(cols, rows)?;
                    }
                }
                Event::Exit(code) => self.exit = Some(code),
                Event::Port(port) => {
                    if !self.ports.contains(&port) {
                        self.ports.push(port);
                    }
                }
            }
        }
        Ok(())
    }
}

/// Why the stream ended.
#[derive(Debug)]
enum End {
    Closed,
    Fault(String),
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run<C, U>(
    worker: Worker,
    admitted: Arc<Admitted>,
    info: StreamInfo,
    client: C,
    upstream: U,
    expires: OffsetDateTime,
    recording: Option<Recorder>,
    started: Instant,
) where
    C: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    U: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let state = Arc::new(Mutex::new(State {
        decoder: StreamDecoder::new(info.kind),
        recorder: recording,
        exit: None,
        ports: info.query_ports.clone(),
    }));
    let bytes_in = Arc::new(AtomicU64::new(0));
    let bytes_out = Arc::new(AtomicU64::new(0));
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut up_read, mut up_write) = tokio::io::split(upstream);

    // kubectl → API server, decoding the client's side (resizes, stream types).
    let to_cluster = {
        let state = Arc::clone(&state);
        let counter = Arc::clone(&bytes_in);
        async move {
            let mut buf = vec![0u8; CHUNK];
            loop {
                let n = match client_read.read(&mut buf).await {
                    Ok(0) | Err(_) => break End::Closed,
                    Ok(n) => n,
                };
                counter.fetch_add(n as u64, Ordering::Relaxed);
                if let Err(fault) = decode(&state, &buf[..n], true) {
                    break End::Fault(fault);
                }
                if up_write.write_all(&buf[..n]).await.is_err() {
                    break End::Closed;
                }
            }
        }
    };
    // API server → kubectl, decoding what the container printed.
    let to_client = {
        let state = Arc::clone(&state);
        let counter = Arc::clone(&bytes_out);
        async move {
            let mut buf = vec![0u8; CHUNK];
            loop {
                let n = match up_read.read(&mut buf).await {
                    Ok(0) | Err(_) => break End::Closed,
                    Ok(n) => n,
                };
                counter.fetch_add(n as u64, Ordering::Relaxed);
                // Record first: output that is not on tape does not reach the user.
                if let Err(fault) = decode(&state, &buf[..n], false) {
                    break End::Fault(fault);
                }
                if client_write.write_all(&buf[..n]).await.is_err() {
                    break End::Closed;
                }
            }
        }
    };
    let revoked = async {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            if OffsetDateTime::now_utc() >= expires {
                return "max_session_ttl reached";
            }
            if let Some(snapshot) = worker.policy.latest()
                && let Some(why) = snapshot.restrictions.blocks(
                    &admitted.username,
                    &admitted.login_id,
                    &admitted.session_id,
                )
            {
                return why;
            }
        }
    };
    // A drain that reaches its timeout ends streams too: they outlive the
    // request the session's own drain handling covers.
    let mut drain = worker.end_sessions();
    let mut to_cluster = Box::pin(to_cluster);
    let mut to_client = Box::pin(to_client);
    tokio::pin!(revoked);
    let (end, reason) = tokio::select! {
        end = &mut to_cluster => (end, "client disconnected"),
        end = &mut to_client => (end, "cluster closed the stream"),
        why = &mut revoked => (End::Closed, why),
        _ = drain.wait_for(|ended| *ended) => (End::Closed, crate::session::WORKER_DRAIN),
    };
    let (bytes_in, bytes_out) = (
        bytes_in.load(Ordering::Relaxed),
        bytes_out.load(Ordering::Relaxed),
    );
    // Dropping the halves above closes both sockets; nothing more is relayed.
    drop(to_cluster);
    drop(to_client);

    let (exit, ports, recording) = {
        let mut state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let recorder = state.recorder.take();
        let exit = state.exit;
        let ports = state.ports.clone();
        (exit, ports, recorder)
    };
    let mut recorded = None;
    if let Some(mut recorder) = recording {
        if let Some(code) = exit {
            let _ = recorder.exit(code);
        }
        match recorder.finish() {
            Ok((_, _, sha)) => recorded = Some(sha),
            Err(e) => {
                tracing::error!(error = %e, session = %admitted.session_id, "finishing the recording failed");
            }
        }
    }
    let reason = match &end {
        End::Closed => reason.to_owned(),
        End::Fault(why) => format!("stream not recordable: {why}"),
    };
    let mut data = json!({
        "kind": "kube",
        "actor_type": admitted.actor_type,
        "resource": admitted.resource,
        "login": info.subresource,
        "worker_id": worker.id(),
        "duration_ms": u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        "bytes_in": bytes_in,
        "bytes_out": bytes_out,
        "reason": reason,
        "exit_code": exit,
        "ports": ports,
    });
    if let Some(sha) = recorded {
        data["recording_sha256"] = json!(sha);
        data["recording_uri"] = json!(format!("recording:{}", admitted.session_id));
    }
    metrics::gauge!("limen_sessions_active", "kind" => "kube").decrement(1.0);
    metrics::counter!("limen_sessions_total", "kind" => "kube").increment(1);
    let ctx = Context {
        user: Some(admitted.username.clone()),
        session_id: uuid::Uuid::parse_str(&admitted.session_id).ok(),
    };
    if let Err(e) = worker.audit.emit(EventKind::SessionEnd, ctx, data).await {
        tracing::error!(error = %e, "failed to audit the end of a kube stream");
    }
    tracing::info!(session = %admitted.session_id, user = %admitted.username, kind = info.subresource, %reason, "kube stream ended");
}

/// Feed bytes from one direction to the decoder and act on what it found.
fn decode(state: &Mutex<State>, bytes: &[u8], from_client: bool) -> Result<(), String> {
    let mut state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let events = if from_client {
        state.decoder.client(bytes)
    } else {
        state.decoder.server(bytes)
    }
    .map_err(|e| e.to_string())?;
    tracing::trace!(
        from_client,
        bytes = bytes.len(),
        ?events,
        "kube stream data"
    );
    state.apply(events).map_err(|e| format!("recording: {e}"))
}

impl StreamInfo {
    /// Open the recording for an exec or attach session, before any byte flows.
    pub(super) fn open_recording(
        &self,
        worker: &Worker,
        session_id: &str,
    ) -> std::io::Result<Option<Recorder>> {
        if !self.records() {
            return Ok(None);
        }
        // The terminal size is not known until kubectl sends one; 80x24 until then.
        Recorder::create(
            &worker.recordings_dir().join(format!("{session_id}.cast")),
            80,
            24,
            &self.title(),
        )
        .map(Some)
    }
}
