//! `OpenSearch` and Elasticsearch sessions (design §5.5, ADR-0036). The worker
//! is an HTTP server toward the user's client and an HTTP client toward the
//! engine:
//!
//! curl ──(TLS to proxy, tunnel)── worker ──(TLS, engine role)── Elasticsearch
//!
//! The client authenticates below HTTP (mTLS and the proxy's grant), so any
//! credential header it sends is dropped. The worker adds its own. Every
//! request is classified and checked against the session's grants, and
//! audited before it is forwarded. Requests on a connection are served one at
//! a time, in order; bodies are streamed unless the worker has to read them.

pub mod audit;
pub mod rules;
pub mod target;

#[cfg(test)]
mod tests;

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use http_body_util::{BodyExt as _, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use limen_audit::Emitter;
use limen_policy::{SearchGrant, SearchTarget};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use uuid::Uuid;

use self::audit::{Auditor, Outcome};
use self::rules::{BodyFacts, BodyKind, Named, Refused, Shape};
use self::target::{Auth, Plan, ReqBody, Settings, Upstream};
use crate::ssh::SessionOutcome;

/// How long a client may take to send a body the worker has to read. A client
/// that stalls mid-upload would otherwise hold its session slot (and a buffer)
/// until the session's own time limit.
const BODY_READ: Duration = Duration::from_mins(10);
/// A response body that sends nothing for this long ends the connection, so a
/// stalled engine doesn't hold a session until its time limit.
const BODY_IDLE: Duration = Duration::from_mins(15);
/// The longest an error body is read to find the engine's error type.
const MAX_ERROR_BODY: u64 = 64 * 1024;
/// How long the target may take to send the head of a response. Searches and
/// `_reindex` can run long, so this is generous; the session's own limit applies too.
const RESPONSE_HEAD: Duration = Duration::from_mins(15);

type RespBody = ReqBody;

/// A body that fails if no frame arrives within `idle`.
struct IdleBody {
    inner: hyper::body::Incoming,
    sleep: std::pin::Pin<Box<tokio::time::Sleep>>,
    idle: Duration,
}

impl hyper::body::Body for IdleBody {
    type Data = Bytes;
    type Error = target::BodyError;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        use std::task::Poll;
        match std::pin::Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(frame) => {
                let next = tokio::time::Instant::now() + self.idle;
                self.sleep.as_mut().reset(next);
                Poll::Ready(frame.map(|r| r.map_err(|e| -> target::BodyError { Box::new(e) })))
            }
            Poll::Pending => match self.sleep.as_mut().poll(cx) {
                Poll::Ready(()) => {
                    Poll::Ready(Some(Err("the search server stopped sending".into())))
                }
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

fn idle_body(inner: hyper::body::Incoming) -> RespBody {
    IdleBody {
        inner,
        sleep: Box::pin(tokio::time::sleep(BODY_IDLE)),
        idle: BODY_IDLE,
    }
    .boxed()
}

/// Everything about a session that is known before the first request.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub session_id: Uuid,
    pub username: String,
    pub resource: String,
    pub engine_role: String,
    /// `opensearch` or `elasticsearch`.
    pub engine: &'static str,
    pub target: SearchTarget,
    /// What the worker may dial, for a resource from a profile (ADR-0042).
    pub guard: Option<limen_policy::model::Delegated>,
}

/// A session whose target connection is open.
pub struct Prepared {
    config: SessionConfig,
    grants: Vec<SearchGrant>,
    plan: Plan,
    upstream: Upstream,
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prepared")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Prepared {
    #[must_use]
    pub fn session_id(&self) -> String {
        self.config.session_id.to_string()
    }
}

/// Connect to the target and check the worker's credential. Failing here
/// means the proxy gets a clean refusal instead of a session that fails on
/// the first request.
pub async fn prepare(
    settings: &Settings,
    grants: Vec<SearchGrant>,
    config: SessionConfig,
    aws: Option<target::AwsSource>,
) -> anyhow::Result<Prepared> {
    let mut plan = target::plan(
        settings,
        &config.resource,
        &config.target,
        &config.engine_role,
        aws,
    )?;
    plan.guard.clone_from(&config.guard);
    let mut upstream = plan.connect().await?;
    let status = probe(&plan, &mut upstream).await?;
    // 401 is the engine saying it doesn't know the worker. 403 can be a role
    // that may not read `/` (fine-grained access control), which is fine.
    if status == StatusCode::UNAUTHORIZED {
        anyhow::bail!("the search server answered 401: the worker's credential was refused");
    }
    Ok(Prepared {
        config,
        grants,
        plan,
        upstream,
    })
}

/// `GET /` with the worker's credential.
async fn probe(plan: &Plan, upstream: &mut Upstream) -> anyhow::Result<StatusCode> {
    let mut headers = HeaderMap::new();
    headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
    let request = build_request("GET", "/", None, &mut headers, plan, Bytes::new()).await?;
    let response = tokio::time::timeout(Duration::from_secs(20), upstream.send(request))
        .await
        .map_err(|_| anyhow::anyhow!("the search server didn't answer in time"))??;
    let status = response.status();
    // Read the (small) body so the connection can be reused.
    let _ = tokio::time::timeout(
        Duration::from_secs(10),
        Limited::new(response.into_body(), 1024 * 1024).collect(),
    )
    .await;
    Ok(status)
}

struct Inner {
    config: SessionConfig,
    grants: Vec<SearchGrant>,
    plan: Plan,
    audit: Auditor,
    upstream: Mutex<Option<Upstream>>,
    /// Requests started on this connection, and the ones still running.
    started: std::sync::atomic::AtomicU64,
    running: std::sync::atomic::AtomicUsize,
}

/// Serve the client on `stream` until it closes.
pub async fn serve<S>(
    stream: S,
    prepared: Prepared,
    emitter: Emitter,
) -> anyhow::Result<SessionOutcome>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Prepared {
        config,
        grants,
        plan,
        upstream,
    } = prepared;
    let audit = Auditor::new(
        emitter,
        config.session_id,
        &config.username,
        &config.resource,
        config.engine,
        &config.engine_role,
        config.target.audit.clone(),
    );
    let idle = plan.idle;
    let inner = Arc::new(Inner {
        config,
        grants,
        plan,
        audit,
        upstream: Mutex::new(Some(upstream)),
        started: std::sync::atomic::AtomicU64::new(0),
        running: std::sync::atomic::AtomicUsize::new(0),
    });
    let watched = Arc::clone(&inner);
    let service = hyper::service::service_fn(move |req| {
        let inner = Arc::clone(&inner);
        async move {
            inner.started.fetch_add(1, Ordering::SeqCst);
            inner.running.fetch_add(1, Ordering::SeqCst);
            let response = handle(&inner, req).await;
            inner.running.fetch_sub(1, Ordering::SeqCst);
            Ok::<_, Infallible>(response)
        }
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder.max_buf_size(64 * 1024).max_headers(100);
    // A client that goes away mid-request is the ordinary end of a session.
    // A connection that has served requests and then sits idle ends, which
    // frees its slot; one that has not yet sent any (the CLI keeps one open to
    // show the run as active) lasts until the session's own time limit.
    let conn = builder.serve_connection(TokioIo::new(stream), service);
    tokio::pin!(conn);
    let idle_watch = async {
        let mut seen = 0;
        loop {
            tokio::time::sleep(idle).await;
            let now = watched.started.load(Ordering::SeqCst);
            if now > 0 && now == seen && watched.running.load(Ordering::SeqCst) == 0 {
                return;
            }
            seen = now;
        }
    };
    tokio::select! {
        r = &mut conn => {
            if let Err(e) = r {
                tracing::debug!(error = %e, "search client connection ended");
            }
        }
        () = idle_watch => tracing::debug!("search connection idle; ending it"),
    }
    Ok(SessionOutcome::default())
}

// ---- one request ---------------------------------------------------------------------

/// Headers a client may send through. Anything else, including every
/// credential and impersonation header, is dropped.
const PASS: &[&str] = &[
    "accept",
    "accept-encoding",
    "content-type",
    "content-encoding",
    "user-agent",
    "if-match",
    "if-none-match",
    "cache-control",
    "x-elastic-client-meta",
    "x-elastic-product-origin",
    "elastic-api-version",
    "traceparent",
    "tracestate",
];

/// Response headers that are about the connection or about the worker's credential.
const DROP_RESPONSE: &[&str] = &[
    "connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
    "www-authenticate",
    "set-cookie",
    "te",
    "trailer",
];

fn json_response(status: StatusCode, kind: &str, reason: &str, close: bool) -> Response<RespBody> {
    let body = json!({
        "error": {
            "root_cause": [{ "type": kind, "reason": format!("Limen: {reason}") }],
            "type": kind,
            "reason": format!("Limen: {reason}"),
        },
        "status": status.as_u16(),
    })
    .to_string();
    let mut response = Response::new(target::full(Bytes::from(body)));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=UTF-8"),
    );
    response
        .headers_mut()
        .insert("x-limen-refused", HeaderValue::from_static("true"));
    if close {
        response
            .headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    response
}

fn counted(class: &str, result: &str) {
    metrics::counter!("limen_search_requests_total", "class" => class.to_owned(), "result" => result.to_owned())
        .increment(1);
}

/// Answer a refusal and record it. The request's body, if it has one, is not
/// read, so the connection closes.
async fn deny(
    inner: &Inner,
    method: &str,
    raw_target: &str,
    shape: Option<&Shape>,
    status: StatusCode,
    refused: &Refused,
    has_body: bool,
) -> Response<RespBody> {
    counted(shape.map_or("unknown", |s| s.class.as_str()), "denied");
    if let Err(e) = inner
        .audit
        .denied(method, raw_target, shape, &refused.0)
        .await
    {
        tracing::error!(error = %e, "couldn't record a refused search request");
    }
    json_response(status, "limen_security_exception", &refused.0, has_body)
}

#[allow(clippy::too_many_lines)] // one request, top to bottom; splitting it would hide the order
async fn handle(inner: &Inner, request: Request<Incoming>) -> Response<RespBody> {
    let (parts, body) = request.into_parts();
    let method = parts.method.as_str().to_owned();
    let raw_target = parts
        .uri
        .path_and_query()
        .map_or_else(|| parts.uri.to_string(), ToString::to_string);
    let has_body = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .is_some_and(|v| v.as_bytes() != b"0")
        || parts.headers.contains_key(header::TRANSFER_ENCODING);

    if parts.uri.scheme().is_some() || parts.uri.authority().is_some() {
        return deny(
            inner,
            &method,
            &raw_target,
            None,
            StatusCode::BAD_REQUEST,
            &Refused("absolute-form request targets aren't supported".into()),
            !drain(body, has_body).await,
        )
        .await;
    }
    let query = parts.uri.query();
    let shape = match rules::classify(&method, parts.uri.path(), query) {
        Ok(s) => s,
        Err(r) => {
            return deny(
                inner,
                &method,
                &raw_target,
                None,
                StatusCode::BAD_REQUEST,
                &r,
                !drain(body, has_body).await,
            )
            .await;
        }
    };
    if let Err(r) = rules::precheck(&inner.grants, &shape) {
        return deny(
            inner,
            &method,
            &raw_target,
            Some(&shape),
            StatusCode::FORBIDDEN,
            &r,
            !drain(body, has_body).await,
        )
        .await;
    }

    // Read the body when the worker needs it: to find indices, to sign it,
    // or to log it. Otherwise it streams.
    let signs = matches!(inner.plan.auth, Auth::Aws { .. });
    let log_bodies = inner.audit.settings().log_bodies;
    let need_body = shape.body != BodyKind::None || signs || log_bodies;
    let (buffered, outgoing): (Option<Bytes>, Option<ReqBody>) = if need_body {
        match tokio::time::timeout(BODY_READ, Limited::new(body, inner.plan.max_body).collect())
            .await
        {
            Ok(Ok(collected)) => (Some(collected.to_bytes()), None),
            Err(_) => {
                return deny(
                    inner,
                    &method,
                    &raw_target,
                    Some(&shape),
                    StatusCode::REQUEST_TIMEOUT,
                    &Refused("the request body wasn't received in time".into()),
                    true,
                )
                .await;
            }
            Ok(Err(_)) => {
                return deny(
                    inner,
                    &method,
                    &raw_target,
                    Some(&shape),
                    StatusCode::PAYLOAD_TOO_LARGE,
                    &Refused(format!(
                        "this request's body must be read and is over {} MiB",
                        inner.plan.max_body / (1024 * 1024)
                    )),
                    true,
                )
                .await;
            }
        }
    } else {
        (None, has_body.then(|| target::incoming(body)))
    };

    // Decode once for inspection and for logging; the original goes upstream.
    let encoding = parts
        .headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok());
    let mut facts = BodyFacts {
        named: Named::default(),
        ..BodyFacts::default()
    };
    let mut text: Option<String> = None;
    if let Some(bytes) = &buffered {
        let decoded = if bytes.is_empty() {
            Ok(Vec::new())
        } else {
            rules::decode_body(bytes, encoding, inner.plan.max_body)
        };
        match decoded {
            Ok(d) => {
                text = log_bodies.then(|| String::from_utf8_lossy(&d).into_owned());
                match rules::inspect_body(&shape, &d) {
                    Ok(f) => facts = f,
                    Err(r) => {
                        return deny(
                            inner,
                            &method,
                            &raw_target,
                            Some(&shape),
                            StatusCode::BAD_REQUEST,
                            &r,
                            false,
                        )
                        .await;
                    }
                }
            }
            // Only a body the worker must read to authorize is refused for its
            // encoding; a plain document upload (signing, logging) goes through.
            Err(r) if shape.body != BodyKind::None => {
                return deny(
                    inner,
                    &method,
                    &raw_target,
                    Some(&shape),
                    StatusCode::BAD_REQUEST,
                    &r,
                    false,
                )
                .await;
            }
            Err(_) => {
                facts.named = rules_named(&shape);
            }
        }
    } else {
        facts.named = rules_named(&shape);
    }
    if shape.body == BodyKind::None {
        facts.named = rules_named(&shape);
    }
    if let Err(r) = rules::decide(&inner.grants, &shape, &facts.named) {
        return deny(
            inner,
            &method,
            &raw_target,
            Some(&shape),
            StatusCode::FORBIDDEN,
            &r,
            false,
        )
        .await;
    }
    if facts.remote {
        // A reindex from another cluster sends that cluster the worker's
        // network position and the user's chosen credentials.
        return deny(
            inner,
            &method,
            &raw_target,
            Some(&shape),
            StatusCode::FORBIDDEN,
            &Refused("reindex from a remote cluster isn't allowed".into()),
            false,
        )
        .await;
    }

    // Written before the request goes anywhere: if it can't be, the request doesn't run.
    let body_len = buffered.as_ref().map_or_else(
        || {
            parts
                .headers
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0)
        },
        |b| b.len() as u64,
    );
    let request_id = match inner
        .audit
        .request(&method, &shape, &facts, query, body_len, text.as_deref())
        .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::error!(error = %e, "couldn't record a search request; not sending it");
            counted(shape.class.as_str(), "audit_failed");
            return json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "limen_audit_exception",
                "the request couldn't be recorded, so it wasn't sent",
                true,
            );
        }
    };

    // Forward it.
    let started = Instant::now();
    let mut headers = HeaderMap::new();
    for name in PASS {
        if let Some(v) = parts.headers.get(*name) {
            headers.insert(HeaderName::from_static(name), v.clone());
        }
    }
    if let Ok(v) = HeaderValue::from_str(&format!("limen:{}", inner.config.session_id)) {
        headers.insert("x-opaque-id", v);
    }
    let path = parts.uri.path().to_owned();
    let sent = send(
        inner,
        &method,
        &path,
        query,
        headers,
        buffered.clone(),
        outgoing,
    )
    .await;
    let response = match sent {
        Ok(r) => r,
        Err(why) => {
            tracing::warn!(resource = %inner.config.resource, error = %why, "search request failed upstream");
            counted(shape.class.as_str(), "upstream_error");
            let outcome = Outcome {
                status: 502,
                duration_ms: millis(started),
                by_worker: true,
                ..Outcome::default()
            };
            let _ = inner.audit.response(request_id, &outcome).await;
            return json_response(
                StatusCode::BAD_GATEWAY,
                "limen_upstream_exception",
                "couldn't reach the search server; ask an admin to check the worker's log",
                true,
            );
        }
    };
    let ttfb = millis(started);
    metrics::histogram!("limen_search_upstream_seconds").record(started.elapsed().as_secs_f64());

    let status = response.status();
    if status == StatusCode::UNAUTHORIZED {
        // The worker's credential, not the user's. Say so without the server's text.
        tracing::warn!(resource = %inner.config.resource, role = %inner.config.engine_role, "the search server refused the worker's credential (401)");
        counted(shape.class.as_str(), "upstream_error");
        let outcome = Outcome {
            status: 401,
            duration_ms: ttfb,
            by_worker: true,
            ..Outcome::default()
        };
        let _ = inner.audit.response(request_id, &outcome).await;
        return json_response(
            StatusCode::BAD_GATEWAY,
            "limen_upstream_exception",
            "the search server refused the worker's credential; ask an admin to check the worker's log",
            false,
        );
    }
    let (mut resp_parts, resp_body) = response.into_parts();
    for name in DROP_RESPONSE {
        resp_parts.headers.remove(*name);
    }
    let content_length = resp_parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    let mut outcome = Outcome {
        status: status.as_u16(),
        duration_ms: ttfb,
        content_length,
        ..Outcome::default()
    };
    // Errors are small: read them to learn the engine's error type for the
    // trail. Anything else streams.
    let final_body: RespBody = if status.as_u16() >= 400
        && method != "HEAD"
        && content_length.is_some_and(|n| n <= MAX_ERROR_BODY)
    {
        match resp_body.collect().await {
            Ok(c) => {
                let bytes = c.to_bytes();
                // The engine compresses when the client asked for it.
                let gzip = resp_parts
                    .headers
                    .get(header::CONTENT_ENCODING)
                    .and_then(|v| v.to_str().ok());
                outcome.error_type = rules::decode_body(&bytes, gzip, 1024 * 1024)
                    .ok()
                    .and_then(|plain| audit::error_type(&plain));
                target::full(bytes)
            }
            Err(e) => {
                tracing::debug!(error = %e, "reading an error body failed");
                return json_response(
                    StatusCode::BAD_GATEWAY,
                    "limen_upstream_exception",
                    "the search server's answer was cut off",
                    true,
                );
            }
        }
    } else {
        idle_body(resp_body)
    };
    counted(
        shape.class.as_str(),
        if status.as_u16() >= 400 {
            "error"
        } else {
            "ok"
        },
    );
    let mut response = Response::from_parts(resp_parts, final_body);
    if let Err(e) = inner.audit.response(request_id, &outcome).await {
        // The request ran; the answer to it was not recorded. Stop serving this client.
        tracing::error!(error = %e, "couldn't record a search response; ending the connection");
        response
            .headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    response
}

/// Read and drop what is left of a request that was refused, so the
/// connection can carry the next one. False when it was too much or too slow.
async fn drain(body: Incoming, has_body: bool) -> bool {
    if !has_body {
        return true;
    }
    matches!(
        tokio::time::timeout(
            Duration::from_secs(5),
            Limited::new(body, 1024 * 1024).collect()
        )
        .await,
        Ok(Ok(_))
    )
}

fn rules_named(shape: &Shape) -> Named {
    let mut n = Named::default();
    match &shape.scope {
        rules::Scope::None => {}
        rules::Scope::All => n.all = true,
        rules::Scope::Indices(v) => n.names.extend(v.iter().cloned()),
    }
    n
}

fn millis(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Build the request for the target, with its credential.
async fn build_request(
    method: &str,
    path: &str,
    query: Option<&str>,
    headers: &mut HeaderMap,
    plan: &Plan,
    body: Bytes,
) -> anyhow::Result<Request<ReqBody>> {
    headers.insert(header::HOST, HeaderValue::from_str(&plan.host)?);
    match &plan.auth {
        Auth::None => {}
        Auth::Header(h) => {
            let mut v = HeaderValue::from_str(h.expose())?;
            v.set_sensitive(true);
            headers.insert(header::AUTHORIZATION, v);
        }
        Auth::Aws {
            source,
            region,
            service,
        } => {
            target::sign(
                headers, source, region, service, &plan.host, method, path, query, &body,
            )
            .await
            .map_err(|e| anyhow::anyhow!("signing the request: {e}"))?;
        }
    }
    let uri = match query {
        Some(q) => format!("{path}?{q}"),
        None => path.to_owned(),
    };
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .body(target::full(body))?;
    *request.headers_mut() = std::mem::take(headers);
    Ok(request)
}

/// Send the request, reconnecting once when the connection to the target
/// had gone stale and the request can be replayed.
async fn send(
    inner: &Inner,
    method: &str,
    path: &str,
    query: Option<&str>,
    headers: HeaderMap,
    buffered: Option<Bytes>,
    mut streaming: Option<ReqBody>,
) -> anyhow::Result<Response<Incoming>> {
    let mut guard = inner.upstream.lock().await;
    // A replay is safe when the body is in hand (or there is none), and the
    // failure came before the request was written, or the method is idempotent.
    let replayable = buffered.is_some() || streaming.is_none();
    let idempotent = matches!(method, "GET" | "HEAD" | "PUT" | "DELETE");
    for attempt in 0..2 {
        let stale = match guard.as_mut() {
            Some(u) => !u.ready().await,
            None => true,
        };
        if stale {
            *guard = Some(inner.plan.connect().await?);
        }
        let mut h = headers.clone();
        let mut request = build_request(
            method,
            path,
            query,
            &mut h,
            &inner.plan,
            buffered.clone().unwrap_or_default(),
        )
        .await?;
        if let Some(body) = streaming.take() {
            *request.body_mut() = body;
        }
        let upstream = guard.as_mut().expect("connected above");
        match tokio::time::timeout(RESPONSE_HEAD, upstream.send(request)).await {
            Ok(Ok(response)) => return Ok(response),
            Ok(Err(e))
                if attempt == 0
                    && replayable
                    && (e.is_canceled() || (idempotent && e.is_incomplete_message())) =>
            {
                // The connection closed under us before any answer.
                tracing::debug!(error = %e, "search target connection was stale; reconnecting");
                *guard = None;
            }
            Ok(Err(e)) => {
                *guard = None;
                return Err(e.into());
            }
            Err(_) => {
                *guard = None;
                anyhow::bail!("the search server didn't answer in time");
            }
        }
    }
    anyhow::bail!("couldn't reach the search server")
}
