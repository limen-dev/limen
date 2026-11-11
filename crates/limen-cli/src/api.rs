//! Connections to the proxy.

use anyhow::{Context as _, bail};
use limen_tunnel::connect::TracedChannel as Channel;
use limen_tunnel::connect::{SharedClientConfig, channel};
use limen_tunnel::tls::{Identity, client_config};
use rustls::ClientConfig;
use rustls_platform_verifier::BuilderVerifierExt as _;

use crate::profile::{self, Profile};

/// Port used when the server is given as a bare host name.
pub const DEFAULT_PORT: u16 = 443;

/// `limen.example.com`, `limen.example.com:443`, `[::1]:3443` or `https://limen.example.com/`
/// as the `host:port` that profiles are keyed on. A bare host gets port 443.
pub fn normalize_server(input: &str) -> anyhow::Result<String> {
    let s = input.trim();
    let s = s.strip_prefix("https://").unwrap_or(s);
    let s = s.trim_end_matches('/');
    if s.is_empty() || s.contains(['/', ' ', '@']) {
        bail!("{input:?} is not a server name; use a host name such as limen.example.com");
    }
    let with_port = if s.starts_with('[') {
        // [v6] or [v6]:port
        if s.contains("]:") {
            s.to_owned()
        } else {
            format!("{s}:{DEFAULT_PORT}")
        }
    } else {
        match s.matches(':').count() {
            0 => format!("{s}:{DEFAULT_PORT}"),
            1 => s.to_owned(),
            // An IPv6 address without brackets can't carry a port.
            _ => format!("[{s}]:{DEFAULT_PORT}"),
        }
    };
    server_name(&with_port)?;
    Ok(with_port)
}

/// The host part of `host:port`, used as the TLS server name.
pub fn server_name(server: &str) -> anyhow::Result<&str> {
    let (host, port) = server
        .rsplit_once(':')
        .context("server address must be host:port")?;
    port.parse::<u16>().context("invalid server port")?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        bail!("server address has no host name");
    }
    Ok(host)
}

/// TLS settings for talking to `server`: the CA pinned by `limen login --ca-file` if there is
/// one, else the operating system's trust store, which is what a server with a certificate
/// from a public CA needs (ADR-0043). TLS 1.3 only.
pub fn tls_config(
    server: &str,
    identity: Option<Identity>,
    alpn: &[&[u8]],
) -> anyhow::Result<ClientConfig> {
    match profile::trusted_ca(server)? {
        Some(ca) => Ok(client_config(
            &limen_tunnel::tls::certs_from_pem(&ca)?,
            identity,
            alpn,
        )?),
        None => platform_tls_config(identity, alpn),
    }
}

/// Trust whatever the operating system trusts, checking the host name as usual.
fn platform_tls_config(identity: Option<Identity>, alpn: &[&[u8]]) -> anyhow::Result<ClientConfig> {
    let builder = ClientConfig::builder_with_provider(limen_tunnel::tls::provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_platform_verifier()
        .context("loading the system trust store")?;
    let mut config = match identity {
        Some(id) => builder.with_client_auth_cert(id.certs, id.key)?,
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(config)
}

/// A channel to `server`, presenting `identity` if given.
pub fn connect(server: &str, identity: Option<Identity>) -> anyhow::Result<Channel> {
    let tls = tls_config(server, identity, &[limen_tunnel::alpn::H2])?;
    Ok(channel(
        server,
        server_name(server)?,
        SharedClientConfig::new(tls),
    ))
}

/// The server to use: `--server`, else the current profile.
pub fn resolve_server(flag: Option<&str>) -> anyhow::Result<String> {
    match flag {
        Some(s) => normalize_server(s),
        None => profile::current_proxy()?
            .context("no server selected; run `limen login --server limen.example.com`"),
    }
}

/// An authenticated channel for the current user.
pub fn authenticated(flag: Option<&str>) -> anyhow::Result<(Profile, Channel)> {
    let proxy = resolve_server(flag)?;
    let profile = Profile::load(&proxy)?
        .with_context(|| format!("not logged in to {proxy}; run `limen login`"))?;
    let channel = connect(&proxy, Some(profile.identity()?))?;
    Ok((profile, channel))
}

/// If `message` is a TLS trust failure, explain the usual cause and the fix.
pub fn tls_hint(message: &str) -> Option<&'static str> {
    // Only an unknown or wrong issuer: a name mismatch or an expired
    // certificate has another cause, and re-pinning the CA wouldn't fix it.
    (message.contains("UnknownIssuer") || message.contains("BadSignature")).then_some(
        "the server's certificate isn't trusted. A server with its own CA needs \
         `limen login --ca-file <ca.pem>`, again if its CA changed (for example, the dev stack \
         was reset). A public deployment needs a certificate from a public CA",
    )
}

/// Turn a gRPC status into a readable error.
pub fn status_error(status: &tonic::Status) -> anyhow::Error {
    if let Some(hint) = tls_hint(status.message()) {
        return anyhow::anyhow!("{}: {hint}", status.message());
    }
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
    fn explains_untrusted_server_certificates() {
        let status = tonic::Status::unavailable("invalid peer certificate: UnknownIssuer");
        assert!(
            super::status_error(&status)
                .to_string()
                .contains("--ca-file")
        );
        assert!(super::tls_hint("connection refused").is_none());
        assert!(super::tls_hint("invalid peer certificate: NotValidForName").is_none());
        assert!(super::tls_hint("invalid peer certificate: Expired").is_none());
    }

    #[test]
    fn a_server_is_a_host_with_an_optional_port() {
        let n = |s: &str| super::normalize_server(s).expect(s);
        assert_eq!(n("limen.example.com"), "limen.example.com:443");
        assert_eq!(n("limen.example.com:8443"), "limen.example.com:8443");
        assert_eq!(n("https://limen.example.com/"), "limen.example.com:443");
        assert_eq!(n(" localhost:3443 "), "localhost:3443");
        assert_eq!(n("[::1]"), "[::1]:443");
        assert_eq!(n("[::1]:3443"), "[::1]:3443");
        assert_eq!(n("::1"), "[::1]:443");
        for bad in [
            "",
            "host:port",
            "host:99999",
            "a b",
            "user@host",
            "https://h/path",
            ":443",
        ] {
            assert!(super::normalize_server(bad).is_err(), "{bad}");
        }
    }

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
