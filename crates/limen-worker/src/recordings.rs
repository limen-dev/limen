//! Uploading finished session recordings to the control plane (ADR-0009).
//! A recording is deleted from the worker only after the control plane has
//! stored it. Through outages, recordings wait on disk and are retried.

use std::path::{Path, PathBuf};
use std::time::Duration;

use limen_proto::v1::RecordingChunk;
use limen_proto::v1::audit_ingest_client::AuditIngestClient;
use tokio::io::AsyncReadExt;
use tokio::sync::watch;

use crate::Worker;
use crate::recording::sha256_file;

const CHUNK: usize = 256 * 1024;
const SCAN_EVERY: Duration = Duration::from_secs(5);

/// Upload finished recordings every few seconds. When `shutdown` flips, one
/// last pass (sessions are over by then), then return.
pub(crate) async fn upload_loop(worker: Worker, mut shutdown: watch::Receiver<bool>) {
    loop {
        let last = tokio::select! {
            () = tokio::time::sleep(SCAN_EVERY) => false,
            _ = shutdown.wait_for(|stop| *stop) => true,
        };
        upload_finished(&worker).await;
        if last {
            let left = finished(&worker.recordings_dir()).len();
            if left > 0 {
                tracing::warn!(
                    recordings = left,
                    "recordings not uploaded; they go on the next start"
                );
            }
            return;
        }
    }
}

async fn upload_finished(worker: &Worker) {
    for path in finished(&worker.recordings_dir()) {
        match upload(worker, &path).await {
            Ok(uri) => {
                tracing::info!(recording = %path.display(), %uri, "recording uploaded");
                if let Err(e) = tokio::fs::remove_file(&path).await {
                    tracing::warn!(error = %e, "couldn't delete an uploaded recording");
                }
            }
            Err(e) => {
                tracing::warn!(recording = %path.display(), error = %e, "recording upload failed; will retry");
                break;
            }
        }
    }
    metrics::gauge!("limen_recordings_pending").set(f64::from(
        u32::try_from(finished(&worker.recordings_dir()).len()).unwrap_or(u32::MAX),
    ));
}

/// Complete recordings (`.cast`; in-progress ones are `.cast.part`).
fn finished(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "cast"))
        .collect();
    out.sort();
    out
}

async fn upload(worker: &Worker, path: &Path) -> anyhow::Result<String> {
    let session_id = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_owned();
    let sha = sha256_file(path)?;
    let mut file = tokio::fs::File::open(path).await?;
    let mut chunks = Vec::new();
    loop {
        let mut buf = vec![0u8; CHUNK];
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        buf.truncate(n);
        chunks.push(RecordingChunk {
            session_id: session_id.clone(),
            data: buf,
            sha256: String::new(),
        });
    }
    chunks.push(RecordingChunk {
        session_id,
        data: Vec::new(),
        sha256: sha,
    });
    let response = AuditIngestClient::new(worker.control_plane()?)
        .upload_recording(tokio_stream::iter(chunks))
        .await?;
    Ok(response.into_inner().uri)
}
