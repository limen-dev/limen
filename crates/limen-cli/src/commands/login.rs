//! `limen login`.

use std::path::Path;

use anyhow::Context as _;
use limen_proto::v1::auth_client::AuthClient;
use limen_proto::v1::{GetAuthConfigRequest, LoginFlow, LoginRequest};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, PublicKeyData};

use crate::oidc::{self, IdpSettings};
use crate::profile::{self, Profile, ProfileMeta};
use crate::{api, commands, ui};

pub async fn run(
    proxy: Option<&str>,
    device: bool,
    open_browser: bool,
    ca_file: Option<&Path>,
) -> anyhow::Result<()> {
    let proxy = api::resolve_proxy(proxy)?;
    api::server_name(&proxy)?;
    if let Some(path) = ca_file {
        let pem =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        limen_tunnel::tls::certs_from_pem(&pem)
            .context("--ca-file must contain a PEM certificate")?;
        profile::pin_ca(&proxy, &pem)?;
    }

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

    let (id_token, flow) = if device {
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
            id_token,
            csr_der,
            nonce_salt: salt.to_vec(),
            flow: flow.into(),
        })
        .await
        .map_err(|s| api::status_error(&s))?
        .into_inner();
    let meta = ProfileMeta {
        proxy: proxy.clone(),
        username: resp.username.clone(),
        roles: resp.roles.clone(),
        login_id: resp.login_id,
        expires_at_unix: resp.expires_at_unix,
    };
    Profile::save(
        &profile::dir_for(&proxy)?,
        &meta,
        &key.serialize_pem(),
        &resp.cert_pem,
    )?;
    if !resp.ssh_host_ca_public_key.is_empty() {
        commands::ssh::write_known_hosts(&proxy, &resp.ssh_host_ca_public_key)?;
    }
    profile::set_current(&proxy)?;
    ui::success(&format!(
        "Signed in to {} as {}",
        ui::bold(&proxy),
        ui::accent(&resp.username)
    ));
    commands::status(Some(&proxy))
}
