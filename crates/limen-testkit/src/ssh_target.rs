//! A minimal SSH server standing in for a target host in tests. Like a real
//! sshd with `TrustedUserCAKeys`, it accepts only user certificates signed by
//! the given CA, valid now, listing the requested login as a principal.
//!
//! `exec` answers `target: login=<login> command=<command>` and exits 0.
//! A shell echoes input back.

// russh's handler traits are async; some of our implementations don't await.
#![allow(clippy::unused_async_trait_impl)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use russh::keys::{Algorithm, Certificate, HashAlg, PrivateKey, PublicKey};
use russh::server::{Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId};

#[derive(Debug, Clone)]
pub struct SshTarget {
    pub addr: SocketAddr,
    /// The host public key, OpenSSH format, for pinning in policy.
    pub host_key: String,
    /// `(login, certificate key ID)` of every accepted authentication.
    pub logins: Arc<Mutex<Vec<(String, String)>>>,
}

impl SshTarget {
    /// # Panics
    /// On setup failures. Tests only.
    pub async fn start(user_ca_openssh: &str) -> Self {
        let ca = PublicKey::from_openssh(user_ca_openssh.trim()).expect("user CA public key");
        let host = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("host key");
        let host_key = host.public_key().to_openssh().expect("encode host key");
        let config = Arc::new(russh::server::Config {
            keys: vec![host],
            auth_rejection_time: std::time::Duration::ZERO,
            ..Default::default()
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let logins = Arc::new(Mutex::new(Vec::new()));
        let accepted = Arc::clone(&logins);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let handler = Target {
                    ca: ca.clone(),
                    logins: Arc::clone(&accepted),
                    login: String::new(),
                };
                let config = Arc::clone(&config);
                tokio::spawn(async move {
                    if let Ok(session) = russh::server::run_stream(config, tcp, handler).await {
                        let _ = session.await;
                    }
                });
            }
        });
        Self {
            addr,
            host_key,
            logins,
        }
    }
}

struct Target {
    ca: PublicKey,
    logins: Arc<Mutex<Vec<(String, String)>>>,
    login: String,
}

impl russh::server::Handler for Target {
    type Error = russh::Error;

    async fn auth_openssh_certificate(
        &mut self,
        user: &str,
        cert: &Certificate,
    ) -> Result<Auth, Self::Error> {
        let trusted = cert
            .validate([&self.ca.fingerprint(HashAlg::Sha256)])
            .is_ok();
        let for_user = cert.valid_principals().iter().any(|p| p == user);
        if trusted && for_user && cert.cert_type().is_user() {
            user.clone_into(&mut self.login);
            self.logins
                .lock()
                .expect("lock")
                .push((user.to_owned(), cert.key_id().to_owned()));
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

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
        session.data(channel, format!("welcome {}\r\n", self.login).into_bytes())?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        let reply = format!(
            "target: login={} command={}\n",
            self.login,
            String::from_utf8_lossy(data)
        );
        session.data(channel, reply.into_bytes())?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.data(channel, data.to_vec())?;
        Ok(())
    }
}
