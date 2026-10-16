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
use crate::tunnels::{NoWorker, SessionSlot};

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
        Ok((session_id, worker_id, inbound, outbound, _slot)) => {
            // `_slot` counts the session in the worker's load until it ends.
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
                let mut data = json!({ "action": "ssh", "resource": request.resource, "login": request.principal, "reason": denial.reason, "client_addr": client_addr });
                if let Some(code) = denial.code {
                    // A machine-readable reason; the message stays for people.
                    data["reason"] = json!(code);
                    data["message"] = json!(denial.reason);
                }
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

enum Route {
    Local {
        worker_id: String,
        channel: limen_tunnel::tunnel::TunnelChannel,
    },
    Peer(crate::peer::Remote),
}

impl Route {
    fn worker_id(&self) -> &str {
        match self {
            Route::Local { worker_id, .. } => worker_id,
            Route::Peer(remote) => &remote.worker_id,
        }
    }
}

struct Denial {
    reason: String,
    /// Policy denials are audited; infrastructure failures are logged.
    audit: bool,
    /// For the audit event's `data.reason` instead of the message.
    code: Option<&'static str>,
}

fn denied(reason: impl Into<String>) -> Denial {
    Denial {
        reason: reason.into(),
        audit: true,
        code: None,
    }
}

fn failed(reason: impl Into<String>) -> Denial {
    Denial {
        reason: reason.into(),
        audit: false,
        code: None,
    }
}

/// Every worker that may serve the resource is at its session cap. Audited
/// (`auth.denied`, `data.reason = "capacity"`): a sign the pool is too small.
fn no_capacity(resource: &str) -> Denial {
    Denial {
        reason: format!(
            "no capacity: every worker that can reach {resource} is at its session limit; try again shortly"
        ),
        audit: true,
        code: Some("capacity"),
    }
}

/// A refusal from the worker, or from the peer proxy holding its tunnel,
/// other than "full" (which [`open_on`] reports as [`Opening::Full`]).
fn refused(s: &tonic::Status) -> Denial {
    match s.code() {
        tonic::Code::PermissionDenied => {
            denied(format!("worker refused the session: {}", s.message()))
        }
        _ => failed(format!("worker couldn't open the session: {}", s.message())),
    }
}

type Outbound = tokio::sync::mpsc::Sender<TunnelFrame>;
type Inbound = tonic::Streaming<TunnelFrame>;
/// Counts a local session in the worker's load (peered ones are counted by
/// the proxy holding the tunnel).
type Slot = Option<SessionSlot>;

async fn establish(
    proxy: &Proxy,
    user: &UserIdentity,
    user_cert_der: Vec<u8>,
    request: &SessionRequest,
) -> Result<(Uuid, String, Inbound, Outbound, Slot), Denial> {
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
    let session_id = Uuid::now_v7();
    let ttl = policy.max_session_ttl(&user.roles);
    let creds = proxy.credentials();
    // Load figures are a little stale, so the chosen worker (or the peer
    // proxy holding it) may turn out to be full. It says so before reading
    // anything, so another eligible worker is tried, with a grant of its
    // own: at most MAX_ATTEMPTS workers in all. Only the final outcome is
    // audited.
    let mut refused_full: Vec<String> = Vec::new();
    loop {
        let (route, slot) = choose_route(proxy, policy, &request.resource, &refused_full).await?;
        let worker_id = route.worker_id().to_owned();
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
            user_cert_der: user_cert_der.clone(),
            proxy_id: creds.id.clone(),
            worker_id: worker_id.clone(),
        };
        let signed = limen_session::grant::sign(&proxy.signer(), &grant)
            .map_err(|e| failed(format!("signing grant: {e}")))?;
        match open_on(route, signed).await {
            Ok((inbound, outbound)) => return Ok((session_id, worker_id, inbound, outbound, slot)),
            Err(Opening::Full(why)) => {
                tracing::info!(worker = %worker_id, reason = %why, "worker is full; trying another");
                // Our figure was stale: count it as full until the next ping
                // (after giving back this attempt's slot, so it isn't counted).
                let local = slot.is_some();
                drop(slot);
                if local {
                    proxy.tunnels.mark_full(&worker_id);
                }
                refused_full.push(worker_id);
                if refused_full.len() >= MAX_ATTEMPTS {
                    return Err(no_capacity(&request.resource));
                }
            }
            Err(Opening::Denied(s)) => return Err(refused(&s)),
            Err(Opening::Failed(denial)) => return Err(denial),
        }
    }
}

/// Workers tried for one session before giving up with "no capacity".
const MAX_ATTEMPTS: usize = 3;

/// A worker tunnelled to this proxy if possible, otherwise one held by a
/// peer proxy (ADR-0004). Among eligible workers not in `exclude`, the less
/// loaded of two; full ones never. `exclude` holds workers that just
/// refused as full, so running out of candidates then is "no capacity".
async fn choose_route(
    proxy: &Proxy,
    policy: &limen_policy::Policy,
    resource: &str,
    exclude: &[String],
) -> Result<(Route, Slot), Denial> {
    let accept = |labels: &std::collections::BTreeMap<String, String>| {
        policy.worker_may_serve(resource, labels)
    };
    let local = match proxy.tunnels.pick(accept, exclude) {
        Ok(picked) => {
            return Ok((
                Route::Local {
                    worker_id: picked.worker_id,
                    channel: picked.channel,
                },
                Some(picked.slot),
            ));
        }
        Err(local) => local,
    };
    let full = local == NoWorker::Full || !exclude.is_empty();
    match crate::peer::find(proxy, accept, exclude).await {
        Ok(Ok(remote)) => Ok((Route::Peer(remote), None)),
        Ok(Err(NoWorker::Full)) => Err(no_capacity(resource)),
        Ok(Err(NoWorker::None)) | Err(_) if full => Err(no_capacity(resource)),
        Ok(Err(NoWorker::None)) => Err(failed(format!(
            "no worker is connected that can reach {resource}"
        ))),
        Err(e) => Err(failed(format!(
            "no local worker for {resource}, and peer lookup failed: {}",
            e.message()
        ))),
    }
}

/// Why opening on one worker didn't work.
enum Opening {
    /// The worker, or the peer proxy holding it, is full; nothing was read.
    Full(String),
    /// Any other refusal from the worker.
    Denied(tonic::Status),
    Failed(Denial),
}

/// Open the session on `route` with `signed` (a grant for that worker), and
/// wait until the worker accepts it.
async fn open_on(
    route: Route,
    signed: limen_proto::v1::Signed,
) -> Result<(Inbound, Outbound), Opening> {
    let (tx, rx) = tokio::sync::mpsc::channel::<TunnelFrame>(64);
    tx.send(TunnelFrame {
        frame: Some(Frame::Open(SessionOpen {
            grant: Some(signed),
        })),
    })
    .await
    .map_err(|_| Opening::Failed(failed("tunnel closed")))?;
    let outbound = tokio_stream::wrappers::ReceiverStream::new(rx);
    let opened = match route {
        Route::Local { channel, .. } => {
            WorkerTunnelClient::new(channel)
                .open_session(outbound)
                .await
        }
        Route::Peer(remote) => {
            tracing::info!(worker = %remote.worker_id, via = %remote.proxy_id, "opening the session through a peer proxy");
            let mut request = tonic::Request::new(outbound);
            if let Ok(value) = remote.worker_id.parse() {
                request.metadata_mut().insert(crate::peer::WORKER_ID, value);
            }
            WorkerTunnelClient::new(remote.channel)
                .open_session(request)
                .await
        }
    };
    let classify = |s: tonic::Status| {
        if s.code() == tonic::Code::ResourceExhausted {
            Opening::Full(s.message().to_owned())
        } else {
            Opening::Denied(s)
        }
    };
    let mut inbound = opened.map_err(classify)?.into_inner();
    match tokio::time::timeout(Duration::from_secs(30), inbound.message()).await {
        Ok(Ok(Some(TunnelFrame {
            frame: Some(Frame::Opened(_)),
        }))) => Ok((inbound, tx)),
        Ok(Ok(Some(TunnelFrame {
            frame: Some(Frame::Close(c)),
        }))) => Err(Opening::Failed(failed(format!(
            "worker closed the session: {}",
            c.reason
        )))),
        Ok(Err(s)) => Err(classify(s)),
        Ok(_) => Err(Opening::Failed(failed(
            "worker ended the session before it started",
        ))),
        Err(_) => Err(Opening::Failed(failed("worker didn't answer in time"))),
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
