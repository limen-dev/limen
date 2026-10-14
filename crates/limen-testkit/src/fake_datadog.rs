//! A fake Datadog Logs intake (`POST /api/v2/logs`). It stores what it
//! receives, can be told to fail, and exposes what it got at
//! `GET /fake/received` (the list of entries) for tests and the dev stack.
//! `POST /fake/fail?status=503` makes it fail, `POST /fake/recover` undoes it.

use std::io::Read;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};

#[derive(Debug, Default)]
pub struct Intake {
    pub received: Mutex<Vec<serde_json::Value>>,
    /// 0 = healthy, otherwise the status to answer with.
    pub failing: AtomicU16,
    pub api_key: Mutex<Option<String>>,
}

impl Intake {
    /// # Panics
    /// If the lock is poisoned. Tests only.
    #[must_use]
    pub fn received(&self) -> Vec<serde_json::Value> {
        self.received.lock().expect("lock").clone()
    }

    pub fn fail_with(&self, status: u16) {
        self.failing.store(status, Ordering::SeqCst);
    }
}

#[derive(Debug, serde::Deserialize)]
struct FailParams {
    status: Option<u16>,
}

pub fn router(intake: Arc<Intake>) -> axum::Router {
    axum::Router::new()
        .route("/api/v2/logs", post(logs))
        .route(
            "/fake/received",
            get(|State(i): State<Arc<Intake>>| async move { Json(i.received()) }),
        )
        .route(
            "/fake/fail",
            post(
                |State(i): State<Arc<Intake>>, Query(p): Query<FailParams>| async move {
                    i.fail_with(p.status.unwrap_or(503));
                    "failing"
                },
            ),
        )
        .route(
            "/fake/recover",
            post(|State(i): State<Arc<Intake>>| async move {
                i.fail_with(0);
                "ok"
            }),
        )
        .with_state(intake)
}

async fn logs(State(intake): State<Arc<Intake>>, headers: HeaderMap, body: Bytes) -> StatusCode {
    let failing = intake.failing.load(Ordering::SeqCst);
    if failing != 0 {
        return StatusCode::from_u16(failing).unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
    }
    let Some(key) = headers.get("DD-API-KEY").and_then(|v| v.to_str().ok()) else {
        return StatusCode::UNAUTHORIZED;
    };
    if let Some(expected) = intake.api_key.lock().ok().and_then(|k| k.clone())
        && expected != key
    {
        return StatusCode::FORBIDDEN;
    }
    let raw = if headers.get("Content-Encoding").is_some_and(|v| v == "gzip") {
        let mut out = Vec::new();
        if flate2::read::GzDecoder::new(&body[..])
            .read_to_end(&mut out)
            .is_err()
        {
            return StatusCode::BAD_REQUEST;
        }
        out
    } else {
        body.to_vec()
    };
    if raw.len() > 5 * 1024 * 1024 {
        return StatusCode::PAYLOAD_TOO_LARGE;
    }
    match serde_json::from_slice::<Vec<serde_json::Value>>(&raw) {
        Ok(entries) if entries.len() <= 1000 => {
            intake.received.lock().expect("lock").extend(entries);
            StatusCode::ACCEPTED
        }
        _ => StatusCode::BAD_REQUEST,
    }
}

/// Start an in-process intake on 127.0.0.1. Returns it and its logs URL.
///
/// # Panics
/// If it can't bind. Tests only.
pub async fn start(api_key: &str) -> (Arc<Intake>, String) {
    let intake = Arc::new(Intake::default());
    *intake.api_key.lock().expect("lock") = Some(api_key.to_owned());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    let app = router(Arc::clone(&intake));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (intake, format!("http://{addr}/api/v2/logs"))
}
