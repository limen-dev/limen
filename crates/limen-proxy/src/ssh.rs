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
use limen_proto::v1::worker_tunnel_client::WorkerTunnelClient;
use limen_proto::v1::{SessionGrant, SessionOpen, SessionRequest, SessionResponse, TunnelFrame};
use limen_session::grant::ESTABLISH_WITHIN;
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

struct Denial {
    reason: String,
    /// Policy denials are audited; infrastructure failures are logged.
    audit: bool,
}

fn denied(reason: impl Into<String>) -> Denial {
    Denial {
        reason: reason.into(),
        audit: true,
    }
}

fn failed(reason: impl Into<String>) -> Denial {
    Denial {
        reason: reason.into(),
        audit: false,
    }
}

type Outbound = tokio::sync::mpsc::Sender<TunnelFrame>;
type Inbound = tonic::Streaming<TunnelFrame>;

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
    let (worker_id, channel) = proxy
        .tunnels
        .pick(|labels| policy.worker_may_serve(&request.resource, labels))
        .ok_or_else(|| {
            failed(format!(
                "no worker is connected that can reach {}",
                request.resource
            ))
        })?;

    let session_id = Uuid::now_v7();
    let ttl = policy.max_session_ttl(&user.roles);
    let creds = proxy.credentials();
    let grant = SessionGrant {
        session_id: session_id.to_string(),
        username: user.username.clone(),
        roles: user.roles.clone(),
        login_id: user.login_id.clone(),
        resource: request.resource.clone(),
        kind: "ssh".into(),
        principal: request.principal.clone(),
        issued_at_unix: now.unix_timestamp(),
        establish_by_unix: (now + ESTABLISH_WITHIN).unix_timestamp(),
        session_expires_at_unix: (now + ttl).unix_timestamp(),
        nonce: rand::random::<[u8; 32]>().to_vec(),
        user_cert_der,
        proxy_id: creds.id.clone(),
        worker_id: worker_id.clone(),
    };
    let signed = limen_session::grant::sign(&proxy.signer(), &grant)
        .map_err(|e| failed(format!("signing grant: {e}")))?;

    let (tx, rx) = tokio::sync::mpsc::channel::<TunnelFrame>(64);
    tx.send(TunnelFrame {
        frame: Some(Frame::Open(SessionOpen {
            grant: Some(signed),
        })),
    })
    .await
    .map_err(|_| failed("tunnel closed"))?;
    let mut client = WorkerTunnelClient::new(channel);
    let mut inbound = client
        .open_session(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await
        .map_err(|s| match s.code() {
            tonic::Code::PermissionDenied => {
                denied(format!("worker refused the session: {}", s.message()))
            }
            _ => failed(format!("worker couldn't open the session: {}", s.message())),
        })?
        .into_inner();
    match tokio::time::timeout(Duration::from_secs(30), inbound.message()).await {
        Ok(Ok(Some(TunnelFrame {
            frame: Some(Frame::Opened(_)),
        }))) => Ok((session_id, worker_id, inbound, tx)),
        Ok(Ok(Some(TunnelFrame {
            frame: Some(Frame::Close(c)),
        }))) => Err(failed(format!("worker closed the session: {}", c.reason))),
        Ok(Err(s)) if s.code() == tonic::Code::PermissionDenied => Err(denied(format!(
            "worker refused the session: {}",
            s.message()
        ))),
        Ok(Err(s)) => Err(failed(format!(
            "worker couldn't open the session: {}",
            s.message()
        ))),
        Ok(_) => Err(failed("worker ended the session before it started")),
        Err(_) => Err(failed("worker didn't answer in time")),
    }
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
    let start = json!({ "kind": "ssh", "resource": request.resource, "login": request.principal, "worker_id": worker_id, "proxy_id": proxy.id(), "client_addr": client_addr });
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
    tokio::pin!(upload);
    tokio::pin!(download);
    let (bytes_in, bytes_out, close) = tokio::select! {
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
    let end = json!({
        "kind": "ssh",
        "resource": request.resource,
        "login": request.principal,
        "worker_id": worker_id,
        "duration_ms": u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        "bytes_in": bytes_in,
        "bytes_out": bytes_out,
        "reason": if close.reason.is_empty() { "client disconnected".to_owned() } else { close.reason },
        "recording_uri": close.recording_uri,
        "recording_sha256": close.recording_sha256,
    });
    if let Err(e) = proxy.audit.emit(EventKind::SessionEnd, ctx, end).await {
        tracing::error!(error = %e, "failed to audit session end");
    }
    tracing::info!(session = %session_id, "session ended");
}
