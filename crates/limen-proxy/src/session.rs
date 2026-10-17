//! Opening a session on a worker: pick the worker, sign the grant, and open
//! the tunnel stream (design §5). The protocol-specific front ends (SSH and
//! Kubernetes) decide *whether* to, from policy; this decides *where* and how.

use std::time::Duration;

use limen_ca::verify::UserIdentity;
use limen_policy::Policy;
use limen_proto::v1::tunnel_frame::Frame;
use limen_proto::v1::worker_tunnel_client::WorkerTunnelClient;
use limen_proto::v1::{SessionGrant, SessionOpen, TunnelFrame};
use limen_session::grant::ESTABLISH_WITHIN;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::Proxy;

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

pub(crate) struct Denial {
    pub(crate) reason: String,
    /// Policy denials are audited; infrastructure failures are logged.
    pub(crate) audit: bool,
}

pub(crate) fn denied(reason: impl Into<String>) -> Denial {
    Denial {
        reason: reason.into(),
        audit: true,
    }
}

pub(crate) fn failed(reason: impl Into<String>) -> Denial {
    Denial {
        reason: reason.into(),
        audit: false,
    }
}

pub(crate) type Outbound = tokio::sync::mpsc::Sender<TunnelFrame>;
pub(crate) type Inbound = tonic::Streaming<TunnelFrame>;

/// What a session is for. The proxy has already decided policy allows it.
pub(crate) struct Target<'a> {
    pub resource: &'a str,
    /// `ssh` or `kube`.
    pub kind: &'static str,
    /// The upstream identity for single-principal kinds (an SSH login).
    pub principal: &'a str,
    /// The Kubernetes groups to impersonate.
    pub groups: Vec<String>,
}

/// Pick a worker that may serve the resource, sign a grant, and open the
/// stream. Returns the session ID, the worker, and both ends of the stream.
pub(crate) async fn open(
    proxy: &Proxy,
    policy: &Policy,
    user: &UserIdentity,
    user_cert_der: Vec<u8>,
    target: Target<'_>,
) -> Result<(Uuid, String, Inbound, Outbound), Denial> {
    let now = OffsetDateTime::now_utc();
    // A worker tunnelled to this proxy if possible, otherwise one held by a
    // peer proxy (ADR-0004).
    let route = match proxy
        .tunnels
        .pick(|labels| policy.worker_may_serve(target.resource, labels))
    {
        Some((worker_id, channel)) => Route::Local { worker_id, channel },
        None => match crate::peer::find(proxy, |labels| {
            policy.worker_may_serve(target.resource, labels)
        })
        .await
        {
            Ok(Some(remote)) => Route::Peer(remote),
            Ok(None) => {
                return Err(failed(format!(
                    "no worker is connected that can reach {}",
                    target.resource
                )));
            }
            Err(e) => {
                return Err(failed(format!(
                    "no local worker for {}, and peer lookup failed: {}",
                    target.resource,
                    e.message()
                )));
            }
        },
    };
    let worker_id = route.worker_id().to_owned();

    let session_id = Uuid::now_v7();
    let ttl = policy.max_session_ttl(&user.roles);
    let creds = proxy.credentials();
    let grant = SessionGrant {
        session_id: session_id.to_string(),
        username: user.username.clone(),
        roles: user.roles.clone(),
        login_id: user.login_id.clone(),
        resource: target.resource.to_owned(),
        kind: target.kind.into(),
        principal: target.principal.to_owned(),
        issued_at_unix: now.unix_timestamp(),
        establish_by_unix: (now + ESTABLISH_WITHIN).unix_timestamp(),
        session_expires_at_unix: (now + ttl).unix_timestamp(),
        nonce: rand::random::<[u8; 32]>().to_vec(),
        user_cert_der,
        proxy_id: creds.id.clone(),
        worker_id: worker_id.clone(),
        groups: target.groups,
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
    let mut inbound = opened
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
