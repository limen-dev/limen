//! SSH sessions (design §5.1). The worker is an SSH server toward the user
//! and an SSH client toward the target:
//!
//! user's ssh ──(TLS to proxy, tunnel)── worker russh server ═ bridge ═ worker russh client ── target sshd
//!
//! Toward the user, the worker presents a per-session host certificate from
//! the Limen SSH host CA, and accepts the `none` method only for the granted
//! login: the stream is already authenticated by mTLS and the proxy's grant.
//! Toward the target, it presents a per-session user certificate from the
//! SSH user CA, and checks the target's host key against the pinned one.

// russh's handler traits are async; some of our implementations don't await.
#![allow(clippy::unused_async_trait_impl)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use limen_audit::{Context, Emitter, EventKind};
use russh::keys::{Certificate, PrivateKey, PublicKey, PublicKeyOrCertificate};
use russh::server::{Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId, ChannelMsg, MethodKind, MethodSet, client};
use serde_json::json;
use uuid::Uuid;

use crate::recording::Recorder;

/// Everything a session needs, decided before the SSH handshake starts.
#[derive(Debug, Clone)]
pub struct SshSessionConfig {
    pub session_id: String,
    pub username: String,
    pub login: String,
    pub resource: String,
    /// `host:port` of the target sshd.
    pub target_address: String,
    /// Pinned target host key, OpenSSH format.
    pub target_host_key: PublicKey,
    /// What the worker may dial, for a resource from a profile (ADR-0042).
    pub target_guard: Option<limen_policy::model::Delegated>,
    pub user_key: Arc<PrivateKey>,
    pub user_cert: Certificate,
    pub host_key: PrivateKey,
    pub host_cert: Certificate,
    pub recording_path: std::path::PathBuf,
    /// Where watchers see this session's output (ADR-0030).
    pub tap: Option<crate::live::Tap>,
    /// Tell the user they may be observed (a role says so).
    pub notify_observed: bool,
}

/// How a session ended, for the proxy's `session.end` event.
#[derive(Debug, Default, Clone)]
pub struct SessionOutcome {
    pub recording_uri: String,
    pub recording_sha256: String,
    pub output_bytes: u64,
    /// The worker ended the session because its drain timeout was up.
    pub ended_by_drain: bool,
}

/// How long an ended session gets to close before it is dropped.
pub(crate) const END_WITHIN: Duration = Duration::from_secs(3);

type SharedRecorder = Arc<Mutex<Option<Recorder>>>;

/// Run the SSH server side on `stream` until the user disconnects, or `end`
/// flips (the worker's drain timeout is up): then the user is disconnected
/// and the recording is finished as usual.
pub async fn serve<S>(
    stream: S,
    config: SshSessionConfig,
    audit: Emitter,
    mut end: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<SessionOutcome>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut methods = MethodSet::empty();
    methods.push(MethodKind::None);
    let server_config = Arc::new(russh::server::Config {
        methods,
        keys: vec![config.host_key.clone()],
        certificates: vec![config.host_cert.clone()],
        auth_rejection_time: Duration::from_millis(200),
        auth_rejection_time_initial: Some(Duration::ZERO),
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(30)),
        ..Default::default()
    });
    let recorder: SharedRecorder = Arc::new(Mutex::new(None));
    let handler = UserSide {
        config: config.clone(),
        audit,
        target: None,
        recorder: Arc::clone(&recorder),
    };
    let running = russh::server::run_stream(server_config, stream, handler).await?;
    let handle = running.handle();
    let mut running = std::pin::pin!(running);
    let ending = async {
        if end.wait_for(|end| *end).await.is_err() {
            // The worker is gone without asking: nothing to do here.
            std::future::pending::<()>().await;
        }
    };
    let (result, ended_by_drain) = tokio::select! {
        r = &mut running => (Some(r), false),
        () = ending => {
            tracing::info!(session = %config.session_id, "ending the session: the worker is shutting down");
            let _ = handle
                .disconnect(
                    russh::Disconnect::ByApplication,
                    "the Limen worker serving this session is shutting down; connect again".into(),
                    "en".into(),
                )
                .await;
            (tokio::time::timeout(END_WITHIN, &mut running).await.ok(), true)
        }
    };
    if let Some(Err(e)) = result {
        tracing::debug!(session = %config.session_id, error = %e, "SSH session ended with error");
    }
    let taken = recorder
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    let mut outcome = SessionOutcome {
        ended_by_drain,
        ..SessionOutcome::default()
    };
    if let Some(rec) = taken {
        let (_path, bytes, sha) = rec.finish()?;
        // The uploader sends it to the control plane, which stores it and
        // emits session.recording with its final location. Until then it's
        // identified by its session.
        outcome = SessionOutcome {
            recording_uri: format!("recording:{}", config.session_id),
            recording_sha256: sha,
            output_bytes: bytes,
            ended_by_drain,
        };
    }
    Ok(outcome)
}

/// Server-side handler: the user's SSH client talks to this.
struct UserSide {
    config: SshSessionConfig,
    audit: Emitter,
    target: Option<Arc<client::Handle<TargetSide>>>,
    recorder: SharedRecorder,
}

impl UserSide {
    async fn target(&mut self) -> anyhow::Result<Arc<client::Handle<TargetSide>>> {
        if let Some(t) = &self.target {
            return Ok(Arc::clone(t));
        }
        let tcp = tokio::time::timeout(
            Duration::from_secs(10),
            crate::dial::connect(
                &self.config.target_address,
                self.config.target_guard.as_ref(),
            ),
        )
        .await??;
        tcp.set_nodelay(true)?;
        let client_config = Arc::new(client::Config {
            inactivity_timeout: None,
            keepalive_interval: Some(Duration::from_secs(30)),
            ..Default::default()
        });
        let mut handle = client::connect_stream(
            client_config,
            tcp,
            TargetSide {
                pinned: self.config.target_host_key.clone(),
            },
        )
        .await?;
        let auth = handle
            .authenticate_openssh_cert(
                self.config.login.clone(),
                Arc::clone(&self.config.user_key),
                self.config.user_cert.clone(),
            )
            .await?;
        if !auth.success() {
            anyhow::bail!(
                "the target rejected the session certificate for {}",
                self.config.login
            );
        }
        let handle = Arc::new(handle);
        self.target = Some(Arc::clone(&handle));
        Ok(handle)
    }
}

impl russh::server::Handler for UserSide {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        if user == self.config.login {
            Ok(Auth::Accept)
        } else {
            tracing::warn!(session = %self.config.session_id, requested = user, granted = %self.config.login, "SSH login doesn't match the grant");
            Ok(Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let target = match self.target().await {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(session = %self.config.session_id, error = %e, "couldn't reach the target");
                reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
                return Ok(());
            }
        };
        let target_channel = match target.channel_open_session().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(session = %self.config.session_id, error = %e, "target refused a session channel");
                reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
                return Ok(());
            }
        };
        reply.accept().await;
        tokio::spawn(bridge(
            channel,
            target_channel,
            self.config.clone(),
            self.audit.clone(),
            Arc::clone(&self.recorder),
        ));
        Ok(())
    }

    // Requests are acknowledged here and forwarded by the bridge, which sees
    // the same messages on the channel.
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _t: &str,
        _c: u32,
        _r: u32,
        _pw: u32,
        _ph: u32,
        _m: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    // Environment variables aren't passed through: they can change how the
    // target's shell behaves (LD_PRELOAD and friends).
    async fn env_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        _value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)?;
        Ok(())
    }

    // Agent forwarding, X11, and port forwarding are refused (Phase 2).
    async fn agent_request(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    async fn tcpip_forward(
        &mut self,
        _address: &str,
        _port: &mut u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }
}

/// Client-side handler: talks to the target sshd.
struct TargetSide {
    pinned: PublicKey,
}

impl client::Handler for TargetSide {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        server: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let key = match server {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.key_data().clone(),
            PublicKeyOrCertificate::Certificate(cert) => cert.public_key().clone(),
        };
        let ok = key == *self.pinned.key_data();
        if !ok {
            tracing::error!(fingerprint = %PublicKey::from(key).fingerprint(russh::keys::HashAlg::default()), "target host key doesn't match the pinned key; refusing");
        }
        Ok(ok)
    }
}

/// Relay one session channel between the user and the target, recording
/// output and auditing commands.
async fn bridge(
    mut user: Channel<Msg>,
    mut target: Channel<client::Msg>,
    config: SshSessionConfig,
    audit: Emitter,
    recorder: SharedRecorder,
) {
    let record = |f: &mut dyn FnMut(&mut Recorder) -> std::io::Result<()>| {
        if let Some(rec) = recorder
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
            && let Err(e) = f(rec)
        {
            tracing::error!(error = %e, "recording write failed");
        }
    };
    let ensure_recorder = |cols: u32, rows: u32| {
        let mut guard = recorder
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.is_none() {
            let title = format!("{}@{} ({})", config.login, config.resource, config.username);
            match Recorder::create(&config.recording_path, cols.max(1), rows.max(1), &title) {
                Ok(r) => *guard = Some(r),
                Err(e) => tracing::error!(error = %e, "couldn't create the session recording"),
            }
        }
    };
    let ctx = Context {
        user: Some(config.username.clone()),
        session_id: Uuid::parse_str(&config.session_id).ok(),
    };

    loop {
        tokio::select! {
            msg = user.wait() => {
                let result = match msg {
                    Some(ChannelMsg::Data { data }) => target.data_bytes(data).await,
                    Some(ChannelMsg::Eof) => target.eof().await,
                    Some(ChannelMsg::RequestPty { term, col_width, row_height, pix_width, pix_height, terminal_modes, .. }) => {
                        ensure_recorder(col_width, row_height);
                        if let Some(tap) = &config.tap {
                            tap.resize(col_width, row_height);
                        }
                        target.request_pty(false, &term, col_width, row_height, pix_width, pix_height, &terminal_modes).await
                    }
                    Some(ChannelMsg::RequestShell { .. }) => {
                        ensure_recorder(80, 24);
                        if config.notify_observed {
                            // Before the shell prints anything: the user knows.
                            let _ = user.data(&b"\r\n[limen] This session may be observed by an administrator.\r\n"[..]).await;
                        }
                        target.request_shell(false).await
                    }
                    Some(ChannelMsg::Exec { command, .. }) => {
                        ensure_recorder(80, 24);
                        let cmd = String::from_utf8_lossy(&command).into_owned();
                        let data = json!({ "actor_type": limen_core::identity::actor_type(&config.username), "resource": config.resource, "login": config.login, "command": cmd });
                        if let Err(e) = audit.emit(EventKind::SshExec, ctx.clone(), data).await {
                            // Fail closed: a command we can't audit doesn't run.
                            tracing::error!(error = %e, "audit unavailable; refusing exec");
                            let _ = user.close().await;
                            break;
                        }
                        target.exec(false, command).await
                    }
                    Some(ChannelMsg::RequestSubsystem { name, .. }) => {
                        ensure_recorder(80, 24);
                        let data = json!({ "actor_type": limen_core::identity::actor_type(&config.username), "resource": config.resource, "login": config.login, "command": format!("subsystem {name}") });
                        if audit.emit(EventKind::SshExec, ctx.clone(), data).await.is_err() {
                            let _ = user.close().await;
                            break;
                        }
                        target.request_subsystem(false, name).await
                    }
                    Some(ChannelMsg::WindowChange { col_width, row_height, pix_width, pix_height }) => {
                        record(&mut |r| r.resize(col_width, row_height));
                        if let Some(tap) = &config.tap {
                            tap.resize(col_width, row_height);
                        }
                        target.window_change(col_width, row_height, pix_width, pix_height).await
                    }
                    Some(ChannelMsg::Signal { signal }) => target.signal(signal).await,
                    Some(ChannelMsg::Close) | None => {
                        let _ = target.close().await;
                        break;
                    }
                    Some(_) => Ok(()),
                };
                if let Err(e) = result {
                    tracing::debug!(error = %e, "forwarding to the target failed");
                    let _ = user.close().await;
                    break;
                }
            }
            msg = target.wait() => {
                let result = match msg {
                    Some(ChannelMsg::Data { data }) => {
                        record(&mut |r| r.output(&data));
                        if let Some(tap) = &config.tap {
                            tap.output(&data);
                        }
                        user.data_bytes(data).await
                    }
                    Some(ChannelMsg::ExtendedData { data, ext }) => {
                        record(&mut |r| r.output(&data));
                        if let Some(tap) = &config.tap {
                            tap.output(&data);
                        }
                        user.extended_data_bytes(ext, data).await
                    }
                    Some(ChannelMsg::Eof) => user.eof().await,
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        record(&mut |r| r.exit(exit_status));
                        user.exit_status(exit_status).await
                    }
                    Some(ChannelMsg::Close) | None => {
                        let _ = user.close().await;
                        break;
                    }
                    Some(_) => Ok(()),
                };
                if let Err(e) = result {
                    tracing::debug!(error = %e, "forwarding to the user failed");
                    let _ = target.close().await;
                    break;
                }
            }
        }
    }
}
