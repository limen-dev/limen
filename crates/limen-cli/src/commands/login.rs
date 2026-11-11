//! `limen login`.

use std::path::Path;

use anyhow::Context as _;
use limen_proto::v1::auth_client::AuthClient;
use limen_proto::v1::{GetAuthConfigRequest, LoginFlow, LoginRequest, LoginResponse};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, PublicKeyData};

use crate::oidc::{self, IdpSettings};
use crate::profile::{self, Profile, ProfileMeta};
use crate::{api, commands, ui};

pub async fn run(
    proxy: Option<&str>,
    device: bool,
    open_browser: bool,
    ca: CaChoice<'_>,
) -> anyhow::Result<()> {
    let proxy = api::resolve_server(proxy)?;
    api::server_name(&proxy)?;
    apply_ca_choice(&proxy, ca)?;

    let channel = api::connect(&proxy, None)?;
    let mut auth = AuthClient::new(channel);
    let config = auth
        .get_auth_config(GetAuthConfigRequest {})
        .await
        .map_err(|s| api::status_error(&s))?
        .into_inner();
    let idp = IdpSettings {
        issuer: config.issuer_url,
        client_id: config.client_id,
        scopes: config.scopes,
    };

    // The key is generated here and never leaves this machine.
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let csr_der = CertificateParams::default()
        .serialize_request(&key)?
        .der()
        .to_vec();
    let salt: [u8; 32] = rand::random();

    let (tokens, flow) = if device {
        (oidc::device_login(&idp).await?, LoginFlow::Device)
    } else {
        let nonce = limen_core::login::nonce(&key.subject_public_key_info(), &salt);
        (
            oidc::pkce_login(&idp, nonce, open_browser).await?,
            LoginFlow::Pkce,
        )
    };

    let resp = auth
        .login(LoginRequest {
            id_token: tokens.id_token,
            csr_der,
            nonce_salt: salt.to_vec(),
            flow: flow.into(),
            refresh_token: tokens.refresh_token.unwrap_or_default(),
        })
        .await
        .map_err(|s| api::status_error(&s))?
        .into_inner();
    finish(&proxy, &key, resp).await
}

/// Save the credentials a login returned, refresh the ssh_config and
/// kubeconfig if they are installed, and show who we are now. Shared by
/// people's logins and bots'.
pub async fn finish(proxy: &str, key: &KeyPair, resp: LoginResponse) -> anyhow::Result<()> {
    let meta = ProfileMeta {
        proxy: proxy.to_owned(),
        username: resp.username.clone(),
        roles: resp.roles.clone(),
        login_id: resp.login_id,
        expires_at_unix: resp.expires_at_unix,
    };
    Profile::save(
        &profile::dir_for(proxy)?,
        &meta,
        &key.serialize_pem(),
        &resp.cert_pem,
    )?;
    if !resp.ssh_host_ca_public_key.is_empty() {
        commands::ssh::write_known_hosts(proxy, &resp.ssh_host_ca_public_key)?;
    }
    profile::set_current(proxy)?;
    ui::success(&format!(
        "Signed in to {} as {}",
        ui::bold(proxy),
        ui::accent(&resp.username)
    ));
    commands::tools::refresh_after_login(proxy).await;
    commands::status(Some(proxy), false)
}

/// What `limen login` does about the CA it trusts the server with.
#[derive(Debug, Clone, Copy)]
pub enum CaChoice<'a> {
    /// Leave things as they are: the CA pinned before, or the system trust store if none.
    Keep,
    /// `--ca-file`: trust this CA for the server from now on.
    Pin(&'a Path),
    /// `--system-roots`: drop any pinned CA and trust the system's, which is what a server with
    /// a certificate from a public CA needs (ADR-0043).
    SystemRoots,
}

impl<'a> CaChoice<'a> {
    pub fn from_flags(ca_file: Option<&'a Path>, system_roots: bool) -> Self {
        match (ca_file, system_roots) {
            (Some(path), _) => Self::Pin(path),
            (None, true) => Self::SystemRoots,
            (None, false) => Self::Keep,
        }
    }
}

/// Pin or drop the CA the user asked for, before the first connection to the server.
pub fn apply_ca_choice(proxy: &str, choice: CaChoice<'_>) -> anyhow::Result<()> {
    match choice {
        CaChoice::Keep => {}
        CaChoice::Pin(path) => {
            let pem = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            limen_tunnel::tls::certs_from_pem(&pem)
                .context("--ca-file must contain a PEM certificate")?;
            profile::pin_ca(proxy, &pem)?;
        }
        CaChoice::SystemRoots => {
            if profile::unpin_ca(proxy)? {
                ui::info(&format!(
                    "Forgot the CA pinned for {proxy}; its certificate is now checked against the system trust store."
                ));
            }
        }
    }
    Ok(())
}
