//! One Kubernetes API request, as the user.
//!
//! The proxy speaks HTTP/1.1 to the worker over a session's byte stream: one
//! request per session. The worker rebuilds the request for the API server
//! with its own credentials and the user's impersonation headers, audits it,
//! and streams the answer back.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Instant;

use http::header::{CONNECTION, CONTENT_TYPE, HOST, UPGRADE};
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt as _, StreamBody};
use hyper::body::{Bytes, Frame, Incoming};
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use limen_audit::{Context, EventKind};
use limen_kube::info::StreamSubresource;
use limen_kube::{RequestInfo, StreamKind};
use serde_json::json;

use super::pump::{self, StreamInfo};
use super::{Admitted, Upstream};
use crate::Worker;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Body = UnsyncBoxBody<Bytes, BoxError>;

const IMPERSONATE_USER: HeaderName = HeaderName::from_static("impersonate-user");
const IMPERSONATE_GROUP: HeaderName = HeaderName::from_static("impersonate-group");
const IMPERSONATE_SESSION: HeaderName = HeaderName::from_static("impersonate-extra-limen-session");
const SEC_WEBSOCKET_PROTOCOL: HeaderName = HeaderName::from_static("sec-websocket-protocol");

/// Never forwarded from the client: hop-by-hop headers, anything that names an
/// identity, and the WebSocket extensions (compression would hide the frames
/// from the recorder).
const DROP: [&str; 11] = [
    "host",
    "authorization",
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "sec-websocket-extensions",
    "forwarded",
];

struct Ctx {
    worker: Worker,
    upstream: Arc<Upstream>,
    admitted: Arc<Admitted>,
}

pub(crate) async fn serve(worker: Worker, admitted: Admitted, io: tokio::io::DuplexStream) {
    let Some(upstream) = worker.kube.clone() else {
        return;
    };
    let ctx = Arc::new(Ctx {
        worker,
        upstream,
        admitted: Arc::new(admitted),
    });
    let service = tower::service_fn(move |req: Request<Incoming>| {
        let ctx = Arc::clone(&ctx);
        async move { Ok::<_, Infallible>(handle(ctx, req).await) }
    });
    let connection = hyper::server::conn::http1::Builder::new()
        // No keep_alive(false): it would add `close` to `Connection: Upgrade`, which
        // Go's SPDY and WebSocket handshakes reject. The proxy ends the stream
        // after the one request instead.
        .serve_connection(TokioIo::new(io), TowerToHyperService::new(service))
        .with_upgrades();
    if let Err(e) = connection.await {
        tracing::debug!(error = %e, "kube: the proxy connection ended with an error");
    }
}

#[allow(clippy::too_many_lines)]
async fn handle(ctx: Arc<Ctx>, mut req: Request<Incoming>) -> Response<Body> {
    let started = Instant::now();
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let query = req.uri().query().unwrap_or_default().to_owned();
    // Set by the proxy, which strips any copy the client sent.
    let client_addr = req
        .headers()
        .get(limen_proto::relay::CLIENT_ADDR)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let info = RequestInfo::parse(method.as_str(), &path, &query);
    let admitted = &ctx.admitted;

    // A lock or kill that arrived since the grant was signed.
    if let Some(snapshot) = ctx.worker.policy.latest()
        && let Some(why) = snapshot
            .restrictions
            .blocks(&admitted.username, &admitted.session_id)
    {
        return failure(StatusCode::FORBIDDEN, "Forbidden", why);
    }

    if !is_canonical(&path) {
        return failure(
            StatusCode::BAD_REQUEST,
            "BadRequest",
            "the path is not canonical",
        );
    }

    let upgrade = req
        .headers()
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_ascii_lowercase);
    let stream = match (&upgrade, info.stream_subresource()) {
        (None, _) => None,
        (Some(u), Some(sub)) if u == "websocket" => Some((sub, false)),
        (Some(u), Some(sub)) if u.starts_with("spdy/3") => Some((sub, true)),
        _ => {
            return failure(
                StatusCode::FORBIDDEN,
                "Forbidden",
                "only exec, attach, and port-forward may upgrade",
            );
        }
    };

    // The worker's own credential. If it is unreadable that is the operator's
    // problem, not the user's: say so, don't call it a denial.
    let bearer = match ctx.upstream.authorization() {
        Ok(bearer) => bearer,
        Err(e) => {
            tracing::error!(error = %e, "kube: the service account token is unavailable");
            return failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                "the worker has no usable cluster credential",
            );
        }
    };
    let headers = match forward_headers(&ctx, bearer, req.headers(), upgrade.as_deref()) {
        Ok(h) => h,
        Err(why) => return failure(StatusCode::FORBIDDEN, "Forbidden", &why),
    };

    let client_upgrade = stream.map(|_| hyper::upgrade::on(&mut req));
    let (parts, body) = req.into_parts();
    let mut upstream_req = Request::new(body.boxed_unsync());
    *upstream_req.method_mut() = parts.method;
    *upstream_req.uri_mut() = match parts.uri.path_and_query() {
        Some(pq) => match pq.as_str().parse() {
            Ok(uri) => uri,
            Err(_) => return failure(StatusCode::BAD_REQUEST, "BadRequest", "bad path"),
        },
        None => http::Uri::from_static("/"),
    };
    *upstream_req.headers_mut() = headers;

    let tls = match ctx.upstream.connect().await {
        Ok(tls) => tls,
        Err(e) => {
            tracing::warn!(error = %e, "kube: cannot reach the API server");
            return failure(
                StatusCode::BAD_GATEWAY,
                "ServiceUnavailable",
                "the worker cannot reach the API server",
            );
        }
    };
    let (mut sender, connection) =
        match hyper::client::conn::http1::handshake(TokioIo::new(tls)).await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(error = %e, "kube: API server handshake failed");
                return failure(
                    StatusCode::BAD_GATEWAY,
                    "ServiceUnavailable",
                    "the API server did not answer",
                );
            }
        };
    tokio::spawn(async move {
        let _ = connection.with_upgrades().await;
    });
    let mut response = match sender.send_request(upstream_req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "kube: the API server request failed");
            return failure(
                StatusCode::BAD_GATEWAY,
                "ServiceUnavailable",
                "the API server request failed",
            );
        }
    };
    let status = response.status();

    // Audit before the answer leaves: if the trail is unavailable the user
    // gets an error, not the data.
    let mut event = json!({
        "kind": "kube",
        "actor_type": admitted.actor_type,
        "resource": admitted.resource,
        "groups": admitted.groups,
        "worker_id": ctx.worker.id(),
        "proxy_id": admitted.proxy_id,
        "client_addr": client_addr,
        "method": method.as_str(),
        "verb": info.verb,
        "k8s_group": info.api_group,
        "k8s_resource": info.resource,
        "namespace": info.namespace,
        "name": info.name,
        "subresource": info.subresource,
        "path": path,
        "status": status.as_u16(),
        "latency_ms": u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    });
    if let Some(ci) = &admitted.ci {
        event["ci"] = json!(ci);
    }
    let audit_ctx = Context {
        user: Some(admitted.username.clone()),
        session_id: uuid::Uuid::parse_str(&admitted.session_id).ok(),
    };
    if let Err(e) = ctx
        .worker
        .audit
        .emit(EventKind::KubeRequest, audit_ctx.clone(), event)
        .await
    {
        tracing::error!(error = %e, "audit unavailable; refusing the kube request");
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "ServiceUnavailable",
            "audit unavailable",
        );
    }
    metrics::counter!("limen_kube_requests_total", "verb" => info.verb.clone()).increment(1);

    if status == StatusCode::SWITCHING_PROTOCOLS {
        let (Some((sub, spdy)), Some(client_upgrade)) = (stream, client_upgrade) else {
            return failure(
                StatusCode::BAD_GATEWAY,
                "ServiceUnavailable",
                "unexpected protocol switch",
            );
        };
        return start_stream(
            &ctx,
            &info,
            &query,
            client_addr,
            sub,
            spdy,
            client_upgrade,
            &mut response,
            audit_ctx,
            started,
        )
        .await;
    }

    let (mut parts, body) = response.into_parts();
    for name in [
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "upgrade",
    ] {
        parts.headers.remove(name);
    }
    Response::from_parts(parts, watch_body(body, Arc::clone(&ctx)))
}

#[allow(clippy::too_many_arguments)]
async fn start_stream(
    ctx: &Arc<Ctx>,
    info: &RequestInfo,
    query: &str,
    client_addr: Option<String>,
    sub: StreamSubresource,
    spdy: bool,
    client_upgrade: hyper::upgrade::OnUpgrade,
    response: &mut Response<Incoming>,
    audit_ctx: Context,
    started: Instant,
) -> Response<Body> {
    let admitted = &ctx.admitted;
    // What the API server agreed to speak. If it is not a protocol the
    // recorder reads, the stream does not run.
    let negotiated = response
        .headers()
        .get(SEC_WEBSOCKET_PROTOCOL)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let tunnelled_spdy = negotiated.starts_with("SPDY/3.1+");
    let readable = spdy || tunnelled_spdy || is_channel_protocol(&negotiated);
    if !readable {
        tracing::warn!(protocol = %negotiated, "refusing a stream in a protocol the recorder cannot read");
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "ServiceUnavailable",
            "this stream protocol cannot be recorded",
        );
    }
    tracing::debug!(protocol = %negotiated, spdy, tunnelled_spdy, "kube stream protocol");
    let (subresource, kind) = match (sub, spdy) {
        (StreamSubresource::Exec, false) => ("exec", StreamKind::ExecWebSocket),
        (StreamSubresource::Exec, true) => ("exec", StreamKind::ExecSpdy),
        (StreamSubresource::Attach, false) => ("attach", StreamKind::ExecWebSocket),
        (StreamSubresource::Attach, true) => ("attach", StreamKind::ExecSpdy),
        (StreamSubresource::PortForward, false) if tunnelled_spdy => {
            ("portforward", StreamKind::PortForwardSpdyOverWebSocket)
        }
        (StreamSubresource::PortForward, false) => {
            ("portforward", StreamKind::PortForwardWebSocket)
        }
        (StreamSubresource::PortForward, true) => ("portforward", StreamKind::PortForwardSpdy),
    };
    let params = |name: &str| -> Vec<String> {
        query
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .filter(|(k, _)| *k == name)
            .map(|(_, v)| percent_decode(v))
            .collect()
    };
    let stream_info = StreamInfo {
        kind,
        subresource,
        namespace: info.namespace.clone(),
        pod: info.name.clone(),
        container: params("container").into_iter().next().unwrap_or_default(),
        command: params("command").join(" "),
        query_ports: params("ports")
            .iter()
            .flat_map(|p| p.split(','))
            .filter_map(|p| p.parse().ok())
            .collect(),
    };
    let recording = match stream_info.open_recording(&ctx.worker, &admitted.session_id) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "cannot create the recording; refusing the stream");
            return failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                "cannot record this session",
            );
        }
    };
    let mut start = json!({
        "kind": "kube",
        "actor_type": admitted.actor_type,
        "resource": admitted.resource,
        "login": subresource,
        "worker_id": ctx.worker.id(),
        "proxy_id": admitted.proxy_id,
        "client_addr": client_addr,
        "namespace": stream_info.namespace,
        "pod": stream_info.pod,
        "container": stream_info.container,
        "command": stream_info.command,
        "groups": admitted.groups,
    });
    if let Some(ci) = &admitted.ci {
        start["ci"] = json!(ci);
    }
    if let Err(e) = ctx
        .worker
        .audit
        .emit(EventKind::SessionStart, audit_ctx, start)
        .await
    {
        tracing::error!(error = %e, "audit unavailable; refusing the stream");
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "ServiceUnavailable",
            "audit unavailable",
        );
    }
    metrics::gauge!("limen_sessions_active", "kind" => "kube").increment(1.0);
    tracing::info!(session = %admitted.session_id, user = %admitted.username, kind = subresource, "kube stream started");

    let upstream_upgrade = hyper::upgrade::on(&mut *response);
    let worker = ctx.worker.clone();
    let admitted = Arc::clone(admitted);
    let guard = worker.session_started();
    let expires = admitted.expires;
    tokio::spawn(async move {
        let _guard = guard;
        let (Ok(client), Ok(upstream)) = tokio::join!(client_upgrade, upstream_upgrade) else {
            // The stream never ran: close what session.start opened.
            metrics::gauge!("limen_sessions_active", "kind" => "kube").decrement(1.0);
            let ctx = Context {
                user: Some(admitted.username.clone()),
                session_id: uuid::Uuid::parse_str(&admitted.session_id).ok(),
            };
            let end = json!({ "kind": "kube", "resource": admitted.resource, "login": stream_info.subresource, "worker_id": worker.id(), "reason": "the connection was not upgraded" });
            let _ = worker.audit.emit(EventKind::SessionEnd, ctx, end).await;
            return;
        };
        pump::run(
            worker,
            admitted,
            stream_info,
            TokioIo::new(client),
            TokioIo::new(upstream),
            expires,
            recording,
            started,
        )
        .await;
    });
    let mut reply = Response::new(());
    *reply.status_mut() = response.status();
    *reply.headers_mut() = response.headers().clone();
    let (parts, ()) = reply.into_parts();
    Response::from_parts(
        parts,
        http_body_util::Empty::new()
            .map_err(|never| match never {})
            .boxed_unsync(),
    )
}

/// Why a response that is still streaming (a `watch`, `logs -f`) must stop:
/// the user was locked, the session was killed, or the grant ran out.
fn must_stop(ctx: &Ctx) -> Option<&'static str> {
    let admitted = &ctx.admitted;
    if time::OffsetDateTime::now_utc() >= admitted.expires {
        return Some("max_session_ttl reached");
    }
    ctx.worker.policy.latest().and_then(|snapshot| {
        snapshot
            .restrictions
            .blocks(&admitted.username, &admitted.session_id)
    })
}

/// Relay the API server's response body, and cut it off if the user is locked
/// or the grant expires while it streams. Without this a `kubectl get -w`
/// would outlive a lock, which an SSH session never does.
fn watch_body(mut body: Incoming, ctx: Arc<Ctx>) -> Body {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, BoxError>>(4);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tokio::select! {
                frame = body.frame() => match frame {
                    Some(Ok(frame)) => {
                        if tx.send(Ok(frame)).await.is_err() {
                            return; // the proxy hung up
                        }
                    }
                    Some(Err(e)) => {
                        let _ = tx.send(Err(Box::new(e) as BoxError)).await;
                        return;
                    }
                    None => return,
                },
                // The proxy hung up (the user pressed ctrl-c). An idle watch
                // sends nothing, so notice it here, not on the next frame.
                () = tx.closed() => return,
                _ = tick.tick() => {
                    if let Some(why) = must_stop(&ctx) {
                        tracing::warn!(session = %ctx.admitted.session_id, user = %ctx.admitted.username, reason = why, "ending a streaming response");
                        let _ = tx.send(Err(why.into())).await;
                        return;
                    }
                }
            }
        }
    });
    StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(rx)).boxed_unsync()
}

/// A path the API server and we would read the same way. Anything with dot
/// segments, empty segments, or an encoded slash or dot could be classified
/// as one thing in the audit trail and routed as another.
fn is_canonical(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    if path.contains('\\') || ["%2e", "%2f", "%5c"].iter().any(|bad| lower.contains(bad)) {
        return false;
    }
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    rest.is_empty()
        || rest
            .split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

/// The headers for the API server: the client's, minus anything that names an
/// identity, plus this worker's credential and the impersonation of the user.
fn forward_headers(
    ctx: &Ctx,
    bearer: HeaderValue,
    client: &HeaderMap,
    upgrade: Option<&str>,
) -> Result<HeaderMap, String> {
    let mut out = HeaderMap::new();
    for (name, value) in client {
        let n = name.as_str();
        if DROP.contains(&n)
            || n.starts_with("impersonate-")
            || n.starts_with("x-limen-")
            || n.starts_with("x-remote-")
        {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out.insert(
        HOST,
        HeaderValue::from_str(ctx.upstream.host_header()).map_err(|e| e.to_string())?,
    );
    out.insert(http::header::AUTHORIZATION, bearer);
    let a = &ctx.admitted;
    out.insert(
        IMPERSONATE_USER,
        HeaderValue::from_str(&a.username).map_err(|_| "the user name is not a valid header")?,
    );
    for group in &a.groups {
        out.append(
            IMPERSONATE_GROUP,
            HeaderValue::from_str(group).map_err(|_| "a group name is not a valid header")?,
        );
    }
    out.insert(
        IMPERSONATE_SESSION,
        HeaderValue::from_str(&a.session_id).map_err(|e| e.to_string())?,
    );
    if let Some(upgrade) = upgrade {
        out.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        out.insert(
            UPGRADE,
            client.get(UPGRADE).cloned().unwrap_or_else(|| {
                HeaderValue::from_str(upgrade).unwrap_or(HeaderValue::from_static("websocket"))
            }),
        );
        // Only the binary channel protocols: the base64 variants are text
        // frames the recorder does not read.
        if let Some(offered) = client
            .get(SEC_WEBSOCKET_PROTOCOL)
            .and_then(|v| v.to_str().ok())
        {
            let kept: Vec<&str> = offered
                .split(',')
                .map(str::trim)
                .filter(|p| !p.starts_with("base64."))
                .collect();
            if kept.is_empty() {
                return Err("no binary channel protocol offered".into());
            }
            out.insert(
                SEC_WEBSOCKET_PROTOCOL,
                HeaderValue::from_str(&kept.join(", ")).map_err(|e| e.to_string())?,
            );
        }
    }
    Ok(out)
}

/// `channel.k8s.io`, `v4.channel.k8s.io`, `v2.portforward.k8s.io`: the binary
/// protocols whose messages start with a channel byte.
fn is_channel_protocol(protocol: &str) -> bool {
    protocol == "channel.k8s.io"
        || (protocol.starts_with('v')
            && (protocol.ends_with(".channel.k8s.io") || protocol.ends_with(".portforward.k8s.io")))
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if bytes.get(i + 1..i + 3).is_some() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                if let Ok(b) = u8::from_str_radix(hex, 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
                out.push(b'%');
            }
            b'+' => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A Kubernetes `Status`, which is what kubectl prints.
fn failure(code: StatusCode, reason: &str, message: &str) -> Response<Body> {
    let body = json!({
        "kind": "Status", "apiVersion": "v1", "metadata": {},
        "status": "Failure", "message": message, "reason": reason, "code": code.as_u16(),
    });
    let mut response = Response::new(
        http_body_util::Full::new(Bytes::from(body.to_string()))
            .map_err(|never| match never {})
            .boxed_unsync(),
    );
    *response.status_mut() = code;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

#[cfg(test)]
mod tests {
    use super::{is_canonical, is_channel_protocol, percent_decode};

    #[test]
    fn only_canonical_paths_are_forwarded() {
        for ok in [
            "/",
            "/api",
            "/api/v1/namespaces/dev/pods/",
            "/apis/apps/v1/deployments",
            "/openapi/v3",
        ] {
            assert!(is_canonical(ok), "{ok}");
        }
        for bad in [
            "",
            "api/v1",
            "//api",
            "/api//v1",
            "/api/v1/../../x",
            "/api/./v1",
            "/api/v1/%2e%2e/x",
            "/api/v1/%2E%2E/x",
            "/api%2fv1",
            "/api\\v1",
            "/api/v1/..",
            "/a//",
        ] {
            assert!(!is_canonical(bad), "{bad}");
        }
    }

    #[test]
    fn only_binary_channel_protocols_are_readable() {
        for ok in [
            "channel.k8s.io",
            "v4.channel.k8s.io",
            "v5.channel.k8s.io",
            "v2.portforward.k8s.io",
        ] {
            assert!(is_channel_protocol(ok), "{ok}");
        }
        for bad in [
            "",
            "base64.channel.k8s.io",
            "SPDY/3.1+portforward.k8s.io",
            "graphql-ws",
        ] {
            assert!(!is_channel_protocol(bad), "{bad}");
        }
    }

    #[test]
    fn decodes_query_values() {
        assert_eq!(percent_decode("ls%20-l"), "ls -l");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
    }
}
