//! `kubectl` through Limen: `https://<proxy>/k8s/<cluster>/...` (ADR-0005, ADR-0033).
//!
//! 1. kubectl presents the user's Limen certificate (its exec plugin returns
//!    it), verified by mTLS against the user CA.
//! 2. The proxy decides from its signed policy snapshot which Kubernetes
//!    groups the user may assume on the cluster. None is a 403, audited.
//! 3. It opens a tunnel session to a worker that may serve the cluster, with a
//!    signed grant naming those groups, and speaks HTTP/1.1 to the worker over
//!    the session's byte stream. One request is one session.
//! 4. An upgrade (`exec`, `attach`, `port-forward`) turns the stream into raw
//!    bytes in both directions. The worker decodes a copy to record it.
//!
//! The proxy never sees a cluster credential and never talks to a cluster. The
//! worker is the only hop that does, and it impersonates the user (it ignores
//! any identity headers the client sends).

use std::time::Duration;

use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode};
use http_body_util::BodyExt as _;
use hyper::body::{Bytes, Incoming};
use hyper_util::rt::TokioIo;
use limen_audit::{Context, EventKind};
use limen_ca::verify::{UserIdentity, verify_user};
use limen_proto::relay::CLIENT_ADDR;
use limen_proto::v1::TunnelFrame;
use limen_proto::v1::tunnel_frame::Frame;
use limen_tunnel::PeerInfo;
use serde_json::json;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_stream::StreamExt;

use crate::Proxy;
use crate::session::{self, Denial, Inbound, Outbound, Target};

/// URL prefix of every cluster.
pub(crate) const PREFIX: &str = "/k8s/";

const CHUNK: usize = 32 * 1024;
type Body = tonic::body::Body;

/// Headers a client must not choose. The worker strips these too; stripping
/// them here keeps them off the tunnel at all.
const CLIENT_CONTROLLED: [&str; 1] = ["authorization"];

pub(crate) async fn handle(proxy: &Proxy, mut req: Request<Incoming>) -> Response<Body> {
    let peer = req.extensions().get::<PeerInfo>().cloned();
    let user = match peer.as_ref().and_then(PeerInfo::leaf) {
        None => {
            return status(
                StatusCode::UNAUTHORIZED,
                "Unauthorized",
                "a Limen user certificate is required; run `limen kube login`",
            );
        }
        Some(leaf) => match proxy
            .credentials()
            .user_ca()
            .map_err(|e| e.to_string())
            .and_then(|ca| verify_user(leaf, &ca).map_err(|e| e.to_string()))
        {
            Ok(user) => user,
            Err(e) => {
                return status(
                    StatusCode::UNAUTHORIZED,
                    "Unauthorized",
                    &format!("invalid user certificate: {e}"),
                );
            }
        },
    };
    let user_cert_der = peer
        .as_ref()
        .and_then(PeerInfo::leaf)
        .map(|c| c.to_vec())
        .unwrap_or_default();
    let client_addr = peer
        .as_ref()
        .and_then(|p| p.remote_addr)
        .map(|a| a.to_string());

    let path_and_query = req
        .uri()
        .path_and_query()
        .map_or_else(|| req.uri().path().to_owned(), ToString::to_string);
    let Some((cluster, rest)) = split_cluster(&path_and_query) else {
        return status(
            StatusCode::NOT_FOUND,
            "NotFound",
            "use /k8s/<cluster>/<kubernetes api path>",
        );
    };

    let upgrading = req.headers().contains_key(http::header::UPGRADE);
    if upgrading && req.version() == http::Version::HTTP_2 {
        return status(
            StatusCode::BAD_REQUEST,
            "BadRequest",
            "streams (exec, attach, port-forward) need HTTP/1.1",
        );
    }

    let opened = match open(proxy, &user, user_cert_der, &cluster).await {
        Ok(opened) => opened,
        Err(denial) => return refuse(proxy, &user, &cluster, client_addr, denial).await,
    };
    let (session_id, worker_id, inbound, outbound) = opened;

    let io = TokioIo::new(bridge(inbound, outbound));
    let (mut sender, connection) = match hyper::client::conn::http1::handshake(io).await {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!(error = %e, worker = %worker_id, "kube: HTTP handshake with the worker failed");
            return status(
                StatusCode::BAD_GATEWAY,
                "ServiceUnavailable",
                "the worker did not answer",
            );
        }
    };
    tokio::spawn(async move {
        if let Err(e) = connection.with_upgrades().await {
            tracing::debug!(error = %e, "kube: worker connection ended with error");
        }
    });

    let client_upgrade = upgrading.then(|| hyper::upgrade::on(&mut req));
    let (mut parts, body) = req.into_parts();
    let Ok(uri) = rest.parse::<http::Uri>() else {
        return status(StatusCode::BAD_REQUEST, "BadRequest", "bad path");
    };
    parts.uri = uri;
    parts.version = http::Version::HTTP_11;
    parts.extensions = http::Extensions::new();
    sanitize(&mut parts.headers, upgrading);
    if let Some(value) = client_addr
        .as_deref()
        .and_then(|a| HeaderValue::from_str(a).ok())
    {
        parts.headers.insert(CLIENT_ADDR, value);
    }
    let forwarded = Request::from_parts(parts, body.boxed_unsync());

    let mut response = match sender.send_request(forwarded).await {
        Ok(response) => response,
        Err(e) => {
            tracing::warn!(error = %e, session = %session_id, "kube: the worker failed the request");
            return status(
                StatusCode::BAD_GATEWAY,
                "ServiceUnavailable",
                "the worker failed the request",
            );
        }
    };

    if response.status() == StatusCode::SWITCHING_PROTOCOLS {
        let Some(client_upgrade) = client_upgrade else {
            return status(
                StatusCode::BAD_GATEWAY,
                "ServiceUnavailable",
                "unexpected protocol switch",
            );
        };
        let worker_upgrade = hyper::upgrade::on(&mut response);
        let proxy = proxy.clone();
        let username = user.username.clone();
        let worker = worker_id.clone();
        tokio::spawn(async move {
            let (Ok(client), Ok(worker_side)) = tokio::join!(client_upgrade, worker_upgrade) else {
                return;
            };
            let (mut client, mut worker_side) = (TokioIo::new(client), TokioIo::new(worker_side));
            let sid = session_id.to_string();
            let revoked = watch_revocation(&proxy, &username, &sid, &worker);
            tokio::select! {
                _ = tokio::io::copy_bidirectional(&mut client, &mut worker_side) => {}
                why = revoked => {
                    tracing::warn!(session = %session_id, user = %username, reason = why, "kube: ending the stream");
                    let _ = client.shutdown().await;
                    let _ = worker_side.shutdown().await;
                }
            }
        });
        let (parts, _) = response.into_parts();
        return Response::from_parts(parts, Body::empty());
    }

    let (mut parts, body) = response.into_parts();
    for name in HOP_BY_HOP {
        parts.headers.remove(name);
    }
    Response::from_parts(parts, Body::new(body))
}

/// `/k8s/<cluster>/<rest>` → (`cluster`, `/<rest>` with its query string).
fn split_cluster(path_and_query: &str) -> Option<(String, String)> {
    let tail = path_and_query.strip_prefix(PREFIX)?;
    let end = tail.find(['/', '?']).unwrap_or(tail.len());
    let (cluster, rest) = tail.split_at(end);
    if cluster.is_empty() {
        return None;
    }
    let rest = match rest {
        "" => "/".to_owned(),
        r if r.starts_with('?') => format!("/{r}"),
        r => r.to_owned(),
    };
    Some((cluster.to_owned(), rest))
}

/// Hop-by-hop headers (RFC 9110 §7.6.1) that must not cross the proxy.
const HOP_BY_HOP: [&str; 6] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "te",
    "trailer",
];

/// Strip what the client must not choose. `Connection` and `Upgrade` survive
/// for an upgrade: they *are* the request.
fn sanitize(headers: &mut HeaderMap, upgrading: bool) {
    let drop: Vec<HeaderName> = headers
        .keys()
        .filter(|k| {
            let k = k.as_str();
            k.starts_with("x-limen-")
                || k.starts_with("impersonate-")
                || k.starts_with("x-remote-")
                || CLIENT_CONTROLLED.contains(&k)
                || (HOP_BY_HOP.contains(&k) && !(upgrading && k == "connection"))
        })
        .cloned()
        .collect();
    for name in drop {
        headers.remove(name);
    }
    if upgrading {
        headers.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("Upgrade"),
        );
    }
}

async fn open(
    proxy: &Proxy,
    user: &UserIdentity,
    user_cert_der: Vec<u8>,
    cluster: &str,
) -> Result<(uuid::Uuid, String, Inbound, Outbound), Denial> {
    let now = OffsetDateTime::now_utc();
    let snapshot = proxy
        .policy
        .fresh(now)
        .map_err(|e| session::failed(format!("access can't be decided right now ({e})")))?;
    if let Some(why) = snapshot.restrictions.blocks(&user.username, "") {
        return Err(session::denied(why));
    }
    let groups = snapshot.policy.kube_groups(&user.roles, cluster);
    if groups.is_empty() {
        return Err(session::denied(format!("access denied to {cluster}")));
    }
    session::open(
        proxy,
        &snapshot.policy,
        user,
        user_cert_der,
        Target {
            resource: cluster,
            kind: "kube",
            principal: "",
            groups,
        },
    )
    .await
}

async fn refuse(
    proxy: &Proxy,
    user: &UserIdentity,
    cluster: &str,
    client_addr: Option<String>,
    denial: Denial,
) -> Response<Body> {
    if denial.audit {
        let data = json!({ "action": "kube", "resource": cluster, "reason": denial.reason, "client_addr": client_addr });
        if let Err(e) = proxy
            .audit
            .emit(
                EventKind::AuthDenied,
                Context {
                    user: Some(user.username.clone()),
                    session_id: None,
                },
                data,
            )
            .await
        {
            tracing::error!(error = %e, "failed to audit a denied kube request");
        }
        tracing::info!(user = %user.username, %cluster, reason = %denial.reason, "kube request refused");
        status(StatusCode::FORBIDDEN, "Forbidden", &denial.reason)
    } else {
        tracing::warn!(user = %user.username, %cluster, reason = %denial.reason, "kube request failed");
        status(
            StatusCode::SERVICE_UNAVAILABLE,
            "ServiceUnavailable",
            &denial.reason,
        )
    }
}

/// A Kubernetes `Status` object, which is what kubectl prints.
fn status(code: StatusCode, reason: &str, message: &str) -> Response<Body> {
    let body = json!({
        "kind": "Status", "apiVersion": "v1", "metadata": {},
        "status": "Failure", "message": message, "reason": reason, "code": code.as_u16(),
    });
    let mut response = Response::new(Body::new(
        http_body_util::Full::new(Bytes::from(body.to_string())).map_err(|never| match never {}),
    ));
    *response.status_mut() = code;
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

/// The tunnel session as one duplex byte stream.
fn bridge(mut inbound: Inbound, outbound: Outbound) -> tokio::io::DuplexStream {
    let (ours, theirs) = tokio::io::duplex(256 * 1024);
    let (mut theirs_read, mut theirs_write) = tokio::io::split(theirs);
    tokio::spawn(async move {
        let mut buf = vec![0u8; CHUNK];
        loop {
            match theirs_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let frame = TunnelFrame {
                        frame: Some(Frame::Data(buf[..n].to_vec())),
                    };
                    if outbound.send(frame).await.is_err() {
                        return;
                    }
                }
            }
        }
        let _ = outbound
            .send(TunnelFrame {
                frame: Some(Frame::Close(limen_proto::v1::SessionClose::default())),
            })
            .await;
    });
    tokio::spawn(async move {
        while let Some(Ok(frame)) = inbound.next().await {
            match frame.frame {
                Some(Frame::Data(d)) => {
                    if theirs_write.write_all(&d).await.is_err() {
                        break;
                    }
                }
                Some(Frame::Close(_)) => break,
                _ => {}
            }
        }
        let _ = theirs_write.shutdown().await;
    });
    ours
}

/// Resolves, with the reason, when an admin lock, a kill, or a worker
/// revocation reaches this proxy's cached snapshot. Checked every second.
async fn watch_revocation(
    proxy: &Proxy,
    username: &str,
    session_id: &str,
    worker_id: &str,
) -> &'static str {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tick.tick().await;
        if let Some(snapshot) = proxy.policy.latest() {
            if let Some(why) = snapshot.restrictions.blocks(username, session_id) {
                return why;
            }
            if snapshot.restrictions.is_revoked(worker_id) {
                return "worker revoked";
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_the_cluster_from_the_api_path() {
        assert_eq!(
            split_cluster("/k8s/dev/api/v1/pods?limit=5"),
            Some(("dev".into(), "/api/v1/pods?limit=5".into()))
        );
        assert_eq!(split_cluster("/k8s/dev"), Some(("dev".into(), "/".into())));
        assert_eq!(split_cluster("/k8s/dev/"), Some(("dev".into(), "/".into())));
        assert_eq!(
            split_cluster("/k8s/dev?x=1"),
            Some(("dev".into(), "/?x=1".into()))
        );
        assert_eq!(split_cluster("/k8s//api"), None);
        assert_eq!(split_cluster("/k8s/"), None);
        assert_eq!(split_cluster("/other/dev/api"), None);
    }

    #[test]
    fn clients_cannot_choose_identity_headers() {
        let mut h = HeaderMap::new();
        for name in [
            "authorization",
            "impersonate-user",
            "Impersonate-Group",
            "impersonate-extra-limen-session",
            "x-limen-client-cert",
            "x-remote-user",
            "keep-alive",
        ] {
            h.insert(
                HeaderName::from_bytes(name.as_bytes()).expect("name"),
                "x".parse().expect("v"),
            );
        }
        h.insert("content-type", "application/json".parse().expect("v"));
        sanitize(&mut h, false);
        assert_eq!(h.len(), 1, "{h:?}");
        assert!(h.contains_key("content-type"));
    }

    #[test]
    fn upgrades_keep_their_connection_header() {
        let mut h = HeaderMap::new();
        h.insert("upgrade", "websocket".parse().expect("v"));
        h.insert("connection", "keep-alive, Upgrade".parse().expect("v"));
        h.insert("keep-alive", "timeout=5".parse().expect("v"));
        sanitize(&mut h, true);
        assert_eq!(h["connection"], "Upgrade");
        assert_eq!(h["upgrade"], "websocket");
        assert!(!h.contains_key("keep-alive"));
    }
}
