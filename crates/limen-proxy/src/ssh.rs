//! Client sessions on `limen-ssh/1` (design §5, §5.1).
//!
//! 1. The client presents its user certificate (mTLS) and sends a `SessionRequest`.
//! 2. The proxy decides from its signed policy snapshot. A denial is audited.
//! 3. It picks a worker whose certified labels may serve the resource, signs
//!    a grant, and opens a tunnel stream. The worker checks everything again.
//! 4. Once the worker accepts, the proxy answers `ok` and relays bytes. The
//!    proxy sees only ciphertext: SSH runs end to end between the user's
//!    client and the worker.

use std::time::{Duration, Instant};

use limen_audit::{Context, EventKind};
use limen_ca::verify::{UserIdentity, verify_user};
use limen_policy::{AccessRequest, Principal};
use limen_proto::v1::tunnel_frame::Frame;
use limen_proto::v1::{SessionRequest, SessionResponse, TunnelFrame};
use limen_tunnel::PeerInfo;
use limen_tunnel::framing::{read_message, write_message};
use serde_json::json;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tokio_stream::StreamExt;
use uuid::Uuid;

use crate::Proxy;
use crate::session::{self, Denial, Inbound, Outbound, Target, denied, failed};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CHUNK: usize = 32 * 1024;

pub(crate) async fn handle(proxy: &Proxy, mut tls: TlsStream<TcpStream>, peer: PeerInfo) {
    let user = match identify(proxy, &peer) {
        Ok(user) => user,
        Err(reason) => {
            let _ = respond(&mut tls, Err(reason)).await;
            return;
        }
    };
    let request: SessionRequest =
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, read_message(&mut tls)).await {
            Ok(Ok(r)) => r,
            _ => return,
        };
    let client_addr = peer.remote_addr.map(|a| a.to_string());
    let user_cert_der = peer.leaf().map(|c| c.to_vec()).unwrap_or_default();
    match establish(proxy, &user, user_cert_der, &request).await {
        Ok((session_id, worker_id, inbound, outbound)) => {
            if respond(&mut tls, Ok(session_id.to_string())).await.is_err() {
                return;
            }
            relay(
                proxy,
                tls,
                &user,
                &request,
                session_id,
                &worker_id,
                client_addr,
                inbound,
                outbound,
            )
            .await;
        }
        Err(denial) => {
            if denial.audit {
                let data = json!({ "action": "ssh", "resource": request.resource, "login": request.principal, "reason": denial.reason, "client_addr": client_addr });
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
                    tracing::error!(error = %e, "failed to audit a denied session");
                }
            }
            tracing::info!(user = %user.username, resource = %request.resource, login = %request.principal, reason = %denial.reason, "session refused");
            let _ = respond(&mut tls, Err(denial.reason)).await;
        }
    }
}

fn identify(proxy: &Proxy, peer: &PeerInfo) -> Result<UserIdentity, String> {
    let leaf = peer
        .leaf()
        .ok_or("a user certificate is required; run `limen login`")?;
    let user_ca = proxy.credentials().user_ca().map_err(|e| e.to_string())?;
    verify_user(leaf, &user_ca).map_err(|e| format!("invalid user certificate: {e}"))
}

async fn respond(
    tls: &mut TlsStream<TcpStream>,
    result: Result<String, String>,
) -> std::io::Result<()> {
    let response = match result {
        Ok(session_id) => SessionResponse {
            ok: true,
            error: String::new(),
            session_id,
        },
        Err(error) => SessionResponse {
            ok: false,
            error,
            session_id: String::new(),
        },
    };
    write_message(tls, &response).await
}

async fn establish(
    proxy: &Proxy,
    user: &UserIdentity,
    user_cert_der: Vec<u8>,
    request: &SessionRequest,
) -> Result<(Uuid, String, Inbound, Outbound), Denial> {
    let now = OffsetDateTime::now_utc();
    let snapshot = proxy
        .policy
        .fresh(now)
        .map_err(|e| failed(format!("access can't be decided right now ({e})")))?;
    let policy = &snapshot.policy;
    if let Some(why) = snapshot.restrictions.blocks(&user.username, "") {
        return Err(denied(why));
    }
    let decision = policy.evaluate(&AccessRequest {
        roles: &user.roles,
        resource: &request.resource,
        principal: Principal::SshLogin(request.principal.clone()),
    });
    if !decision.is_allowed() {
        return Err(denied(format!(
            "access denied to {}@{}",
            request.principal, request.resource
        )));
    }
    session::open(
        proxy,
        policy,
        user,
        user_cert_der,
        Target {
            resource: &request.resource,
            kind: "ssh",
            principal: &request.principal,
            groups: Vec::new(),
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn relay(
    proxy: &Proxy,
    tls: TlsStream<TcpStream>,
    user: &UserIdentity,
    request: &SessionRequest,
    session_id: Uuid,
    worker_id: &str,
    client_addr: Option<String>,
    mut inbound: Inbound,
    outbound: Outbound,
) {
    let ctx = Context {
        user: Some(user.username.clone()),
        session_id: Some(session_id),
    };
    let mut start = json!({ "kind": "ssh", "actor_type": limen_core::identity::actor_type(&user.username), "resource": request.resource, "login": request.principal, "worker_id": worker_id, "proxy_id": proxy.id(), "client_addr": client_addr });
    if user.bot {
        // Which CI run this session belongs to (ADR-0019).
        start["ci"] = json!(user.ci);
    }
    if let Err(e) = proxy
        .audit
        .emit(EventKind::SessionStart, ctx.clone(), start)
        .await
    {
        tracing::error!(error = %e, "audit unavailable; closing the session");
        return;
    }
    tracing::info!(session = %session_id, user = %user.username, resource = %request.resource, login = %request.principal, worker = %worker_id, "session started");

    let started = Instant::now();
    metrics::gauge!("limen_sessions_active", "kind" => "ssh").increment(1.0);
    let (mut reader, mut writer) = tokio::io::split(tls);
    let upload = async {
        let mut bytes = 0u64;
        let mut buf = vec![0u8; CHUNK];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    bytes += n as u64;
                    if outbound
                        .send(TunnelFrame {
                            frame: Some(Frame::Data(buf[..n].to_vec())),
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
        let _ = outbound
            .send(TunnelFrame {
                frame: Some(Frame::Close(limen_proto::v1::SessionClose::default())),
            })
            .await;
        bytes
    };
    let download = async {
        let mut bytes = 0u64;
        let mut close = None;
        while let Some(frame) = inbound.next().await {
            match frame.map(|f| f.frame) {
                Ok(Some(Frame::Data(d))) => {
                    bytes += d.len() as u64;
                    if writer.write_all(&d).await.is_err() {
                        break;
                    }
                }
                Ok(Some(Frame::Close(c))) => {
                    close = Some(c);
                    break;
                }
                Ok(_) => {}
                Err(e) => {
                    close = Some(limen_proto::v1::SessionClose {
                        reason: format!("tunnel error: {}", e.message()),
                        ..Default::default()
                    });
                    break;
                }
            }
        }
        let _ = writer.shutdown().await;
        (bytes, close)
    };
    // Whichever side finishes first, give the other a moment: the worker's
    // closing frame carries the recording reference for session.end.
    // Locks and kills arrive with the policy snapshot (every 10 s). Check the
    // cached copy each second, and end the session as soon as one applies.
    let revoked = async {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            if let Some(snapshot) = proxy.policy.latest() {
                if let Some(why) = snapshot
                    .restrictions
                    .blocks(&user.username, &session_id.to_string())
                {
                    return why;
                }
                if snapshot.restrictions.is_revoked(worker_id) {
                    return "worker revoked";
                }
            }
        }
    };
    tokio::pin!(upload);
    tokio::pin!(download);
    tokio::pin!(revoked);
    let mut revoked_why = None;
    let (bytes_in, bytes_out, close) = tokio::select! {
        why = &mut revoked => {
            revoked_why = Some(why);
            tracing::warn!(session = %session_id, user = %user.username, reason = why, "ending the session");
            // Closing the tunnel makes the worker stop the target connection
            // and finish the recording; its closing frame still reaches us.
            let _ = outbound
                .send(TunnelFrame {
                    frame: Some(Frame::Close(limen_proto::v1::SessionClose {
                        reason: why.into(),
                        ..Default::default()
                    })),
                })
                .await;
            let (out, close) = tokio::time::timeout(Duration::from_secs(15), &mut download).await.unwrap_or((0, None));
            (0, out, close)
        }
        (out, close) = &mut download => {
            let bytes_in = tokio::time::timeout(Duration::from_secs(5), &mut upload).await.unwrap_or(0);
            (bytes_in, out, close)
        }
        bytes_in = &mut upload => {
            let (out, close) = tokio::time::timeout(Duration::from_secs(15), &mut download).await.unwrap_or((0, None));
            (bytes_in, out, close)
        }
    };
    let close = close.unwrap_or_default();
    let ctx_user = ctx.user.clone().unwrap_or_default();
    let end = json!({
        "kind": "ssh",
        "actor_type": limen_core::identity::actor_type(&ctx_user),
        "resource": request.resource,
        "login": request.principal,
        "worker_id": worker_id,
        "duration_ms": u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        "bytes_in": bytes_in,
        "bytes_out": bytes_out,
        "reason": match revoked_why {
            Some(why) => why.to_owned(),
            None if close.reason.is_empty() => "client disconnected".to_owned(),
            None => close.reason,
        },
        "recording_uri": close.recording_uri,
        "recording_sha256": close.recording_sha256,
    });
    metrics::gauge!("limen_sessions_active", "kind" => "ssh").decrement(1.0);
    metrics::counter!("limen_sessions_total", "kind" => "ssh").increment(1);
    if let Err(e) = proxy.audit.emit(EventKind::SessionEnd, ctx, end).await {
        tracing::error!(error = %e, "failed to audit session end");
    }
    tracing::info!(session = %session_id, "session ended");
}
