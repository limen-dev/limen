//! Connections to the proxy.

use anyhow::{Context as _, bail};
use limen_tunnel::connect::{SharedClientConfig, channel};
use limen_tunnel::tls::{Identity, client_config};
use tonic::transport::Channel;

use crate::profile::{self, Profile};

/// The host part of `host:port`, used as the TLS server name.
pub fn server_name(proxy: &str) -> anyhow::Result<&str> {
    let (host, port) = proxy
        .rsplit_once(':')
        .context("proxy address must be host:port")?;
    port.parse::<u16>().context("invalid proxy port")?;
    Ok(host.trim_start_matches('[').trim_end_matches(']'))
}

/// A channel to `proxy`, trusting its pinned CA, optionally presenting `identity`.
pub fn connect(proxy: &str, identity: Option<Identity>) -> anyhow::Result<Channel> {
    let Some(ca) = profile::trusted_ca(proxy)? else {
        bail!("no CA is pinned for {proxy}; run `limen login --proxy {proxy} --ca-file <ca.pem>`");
    };
    let roots = limen_tunnel::tls::certs_from_pem(&ca)?;
    let tls = client_config(&roots, identity, &[limen_tunnel::alpn::H2])?;
    Ok(channel(
        proxy,
        server_name(proxy)?,
        SharedClientConfig::new(tls),
    ))
}

/// The proxy to use: `--proxy`, else the current profile.
pub fn resolve_proxy(flag: Option<&str>) -> anyhow::Result<String> {
    match flag {
        Some(p) => Ok(p.to_owned()),
        None => profile::current_proxy()?
            .context("no proxy selected; run `limen login --proxy host:port`"),
    }
}

/// An authenticated channel for the current user.
pub fn authenticated(flag: Option<&str>) -> anyhow::Result<(Profile, Channel)> {
    let proxy = resolve_proxy(flag)?;
    let profile = Profile::load(&proxy)?
        .with_context(|| format!("not logged in to {proxy}; run `limen login`"))?;
    let channel = connect(&proxy, Some(profile.identity()?))?;
    Ok((profile, channel))
}

/// Turn a gRPC status into a readable error.
pub fn status_error(status: &tonic::Status) -> anyhow::Error {
    match status.code() {
        tonic::Code::Unauthenticated => anyhow::anyhow!(
            "not authenticated: {}. Run `limen login`.",
            status.message()
        ),
        tonic::Code::PermissionDenied => anyhow::anyhow!("permission denied: {}", status.message()),
        tonic::Code::Unavailable => anyhow::anyhow!("unavailable: {}", status.message()),
        _ => anyhow::anyhow!("{}", status.message()),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn server_name_strips_port_and_brackets() {
        assert_eq!(
            super::server_name("limen.example.com:443").expect("ok"),
            "limen.example.com"
        );
        assert_eq!(super::server_name("[::1]:3443").expect("ok"), "::1");
        assert!(super::server_name("nohost").is_err());
        assert!(super::server_name("host:port").is_err());
    }
}
