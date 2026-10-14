//! Admitting a session the proxy opened over a tunnel (design §5).
//!
//! The first frame carries the proxy's signed grant. The worker checks it
//! independently (defense in depth: both proxy and worker must allow), gets
//! per-session SSH certificates from the control plane, then bridges the
//! frame stream to its SSH server.

use std::sync::Arc;

use limen_policy::{AccessRequest, Principal};
use limen_proto::v1::ssh_certificates_client::SshCertificatesClient;
use limen_proto::v1::tunnel_frame::Frame;
use limen_proto::v1::{
    IssueSessionCertificatesRequest, SessionClose, SessionOpened, Signed, TunnelFrame,
};
use limen_session::grant::verify_grant;
use russh::keys::{Algorithm, Certificate, PrivateKey, PublicKey};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Response, Status, Streaming};

use crate::Worker;
use crate::ssh::{SshSessionConfig, serve};

type FrameStream =
    std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<TunnelFrame, Status>> + Send>>;

const FRAME_CHUNK: usize = 32 * 1024;

pub(crate) async fn open(
    worker: Worker,
    mut inbound: Streaming<TunnelFrame>,
) -> Result<Response<FrameStream>, Status> {
    let first = tokio::time::timeout(std::time::Duration::from_secs(10), inbound.message())
        .await
        .map_err(|_| Status::deadline_exceeded("no session open frame"))??;
    let Some(TunnelFrame {
        frame: Some(Frame::Open(open)),
    }) = first
    else {
        return Err(Status::invalid_argument(
            "the first frame must open the session",
        ));
    };
    let signed = open
        .grant
        .ok_or_else(|| Status::invalid_argument("missing grant"))?;
    let config = admit(&worker, &signed).await.map_err(|e| {
        tracing::warn!(error = %e, "session refused");
        e
    })?;

    let guard = worker.session_started();
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<TunnelFrame, Status>>(64);
    let _ = tx
        .send(Ok(TunnelFrame {
            frame: Some(Frame::Opened(SessionOpened {})),
        }))
        .await;
    let (ours, theirs) = tokio::io::duplex(256 * 1024);
    let (mut theirs_read, mut theirs_write) = tokio::io::split(theirs);

    // Proxy → SSH server.
    tokio::spawn(async move {
        while let Some(Ok(frame)) = inbound.next().await {
            match frame.frame {
                Some(Frame::Data(bytes)) => {
                    if theirs_write.write_all(&bytes).await.is_err() {
                        break;
                    }
                }
                Some(Frame::Close(_)) => break,
                _ => {}
            }
        }
        let _ = theirs_write.shutdown().await;
    });

    // SSH server → proxy, then the closing frame with the recording.
    let session_id = config.session_id.clone();
    let expires = config_expiry(&signed);
    let audit = worker.audit.clone();
    tokio::spawn(async move {
        let _guard = guard;
        let pump_tx = tx.clone();
        let pump = tokio::spawn(async move {
            let mut buf = vec![0u8; FRAME_CHUNK];
            loop {
                match theirs_read.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if pump_tx
                            .send(Ok(TunnelFrame {
                                frame: Some(Frame::Data(buf[..n].to_vec())),
                            }))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
        });
        let until = (expires - OffsetDateTime::now_utc())
            .max(time::Duration::ZERO)
            .unsigned_abs();
        let (reason, outcome) = match tokio::time::timeout(until, serve(ours, config, audit)).await
        {
            Ok(Ok(outcome)) => ("ended".to_owned(), outcome),
            Ok(Err(e)) => (format!("error: {e}"), crate::ssh::SessionOutcome::default()),
            Err(_) => (
                "max_session_ttl reached".to_owned(),
                crate::ssh::SessionOutcome::default(),
            ),
        };
        let _ = pump.await;
        tracing::info!(session = %session_id, %reason, recording = %outcome.recording_uri, "session ended");
        let _ = tx
            .send(Ok(TunnelFrame {
                frame: Some(Frame::Close(SessionClose {
                    reason,
                    recording_uri: outcome.recording_uri,
                    recording_sha256: outcome.recording_sha256,
                })),
            }))
            .await;
    });
    Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
}

fn config_expiry(signed: &Signed) -> OffsetDateTime {
    use prost::Message as _;
    limen_proto::v1::SessionGrant::decode(signed.payload.as_slice())
        .ok()
        .and_then(|g| OffsetDateTime::from_unix_timestamp(g.session_expires_at_unix).ok())
        .unwrap_or_else(OffsetDateTime::now_utc)
}

/// Every check a session must pass before the worker touches the target.
async fn admit(worker: &Worker, signed: &Signed) -> Result<SshSessionConfig, Status> {
    let creds = worker.credentials();
    let internal_ca = creds
        .internal_ca()
        .map_err(|e| Status::internal(e.to_string()))?;
    let user_ca = creds
        .user_ca()
        .map_err(|e| Status::internal(e.to_string()))?;
    let now = OffsetDateTime::now_utc();

    let verified = verify_grant(signed, &internal_ca, &user_ca, now)
        .map_err(|e| Status::permission_denied(e.to_string()))?;
    let grant = &verified.grant;
    if grant.worker_id != creds.id {
        return Err(Status::permission_denied("grant is for another worker"));
    }
    if !worker
        .nonces
        .check_and_insert(&grant.nonce, grant.establish_by_unix)
    {
        return Err(Status::permission_denied("grant already used"));
    }
    if grant.kind != "ssh" {
        return Err(Status::unimplemented(format!(
            "{} sessions arrive in a later phase",
            grant.kind
        )));
    }

    // Our own policy decision, from our own snapshot.
    let snapshot = worker
        .policy
        .fresh(now)
        .map_err(|e| Status::unavailable(format!("can't decide: {e}")))?;
    if let Some(why) = snapshot
        .restrictions
        .blocks(&verified.user.username, &grant.session_id)
    {
        return Err(Status::permission_denied(why));
    }
    let decision = snapshot.policy.evaluate(&AccessRequest {
        roles: &verified.user.roles,
        resource: &grant.resource,
        principal: Principal::SshLogin(grant.principal.clone()),
    });
    if !decision.is_allowed() {
        return Err(Status::permission_denied(format!(
            "worker policy check: {decision:?}"
        )));
    }
    if !snapshot
        .policy
        .worker_may_serve(&grant.resource, &creds.labels)
    {
        return Err(Status::permission_denied(
            "this worker may not serve the resource",
        ));
    }
    let target = snapshot
        .policy
        .resource(&grant.resource)
        .and_then(|r| r.spec.ssh.clone())
        .ok_or_else(|| Status::failed_precondition("resource is not an SSH resource"))?;
    let pinned = target
        .host_key
        .as_deref()
        .ok_or_else(|| {
            Status::failed_precondition(
                "resource has no pinned host_key; refusing to connect to an unverified host",
            )
        })
        .and_then(|k| {
            PublicKey::from_openssh(k)
                .map_err(|e| Status::failed_precondition(format!("pinned host_key: {e}")))
        })?;

    // Keys for this session only. The control plane certifies them.
    let (user_key, host_key) = {
        // Scoped: the thread-local RNG must not be held across an await.
        let mut rng = rand::rng();
        (
            PrivateKey::random(&mut rng, Algorithm::Ed25519)
                .map_err(|e| Status::internal(e.to_string()))?,
            PrivateKey::random(&mut rng, Algorithm::Ed25519)
                .map_err(|e| Status::internal(e.to_string()))?,
        )
    };
    let channel = worker
        .control_plane()
        .map_err(|e| Status::internal(e.to_string()))?;
    let certs = SshCertificatesClient::new(channel)
        .issue_session_certificates(IssueSessionCertificatesRequest {
            grant: Some(signed.clone()),
            user_public_key: user_key
                .public_key()
                .to_openssh()
                .map_err(|e| Status::internal(e.to_string()))?,
            host_public_key: host_key
                .public_key()
                .to_openssh()
                .map_err(|e| Status::internal(e.to_string()))?,
        })
        .await
        .map_err(|s| {
            if s.code() == tonic::Code::PermissionDenied {
                s
            } else {
                Status::unavailable(format!("control plane: {}", s.message()))
            }
        })?
        .into_inner();
    let user_cert = Certificate::from_openssh(&certs.user_certificate)
        .map_err(|e| Status::internal(e.to_string()))?;
    let host_cert = Certificate::from_openssh(&certs.host_certificate)
        .map_err(|e| Status::internal(e.to_string()))?;

    Ok(SshSessionConfig {
        recording_path: worker
            .recordings_dir()
            .join(format!("{}.cast", grant.session_id)),
        session_id: grant.session_id.clone(),
        username: grant.username.clone(),
        login: grant.principal.clone(),
        resource: grant.resource.clone(),
        target_address: target.address,
        target_host_key: pinned,
        user_key: Arc::new(user_key),
        user_cert,
        host_key,
        host_cert,
    })
}
