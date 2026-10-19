//! `limen ssh`, `limen ssh-proxy`, and `limen config ssh` (design §5.1).
//!
//! `limen ssh` runs the system OpenSSH client with Limen as its
//! `ProxyCommand`. SSH then runs end to end between OpenSSH and the worker:
//! OpenSSH verifies the worker's per-session host certificate against the
//! Limen SSH host CA (in the profile's known_hosts), and authenticates with
//! the `none` method, because the stream underneath is already authenticated
//! by the user's certificate and authorized by the proxy.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use limen_proto::v1::resources_client::ResourcesClient;
use limen_proto::v1::{ListResourcesRequest, SessionRequest, SessionResponse};
use limen_tunnel::framing::{read_message, write_message};
use limen_tunnel::tls::client_config;

use crate::api;
use crate::profile::{self, Profile};

/// File in the profile directory that trusts the Limen SSH host CA.
pub const KNOWN_HOSTS: &str = "known_hosts";

/// Write the known_hosts file that trusts the SSH host CA for every host
/// reached through this proxy.
pub fn write_known_hosts(proxy: &str, host_ca_public_key: &str) -> anyhow::Result<()> {
    let key = host_ca_public_key.trim();
    if key.is_empty() || key.contains('\n') {
        bail!("the control plane returned an invalid SSH host CA key");
    }
    let path = profile::dir_for(proxy)?.join(KNOWN_HOSTS);
    std::fs::write(&path, format!("# Written by `limen login`. Trusts the Limen SSH host CA for hosts reached through {proxy}.\n@cert-authority * {key}\n"))
        .with_context(|| format!("writing {}", path.display()))
}

/// `[login@]resource`.
fn split_target(target: &str) -> (Option<&str>, &str) {
    match target.rsplit_once('@') {
        Some((login, resource)) => (Some(login), resource),
        None => (None, target),
    }
}

/// The login to use when the user didn't name one: the only one policy allows.
async fn default_login(proxy: Option<&str>, resource: &str) -> anyhow::Result<String> {
    let (_, channel) = api::authenticated(proxy)?;
    let resources = ResourcesClient::new(channel)
        .list_resources(ListResourcesRequest {})
        .await
        .map_err(|s| api::status_error(&s).context(format!("couldn't look up your logins for {resource}; name one: limen ssh <login>@{resource}")))?
        .into_inner()
        .resources;
    let found = resources
        .into_iter()
        .find(|r| r.name == resource && r.kind == "ssh")
        .with_context(|| format!("you have no SSH access to {resource:?}; see `limen ls`"))?;
    match found.principals.as_slice() {
        [only] => Ok(only.clone()),
        many => {
            let options: Vec<String> = many
                .iter()
                .map(|l| format!("  limen ssh {l}@{resource}"))
                .collect();
            bail!(
                "several logins are allowed on {resource}; pick one:\n{}",
                options.join("\n")
            )
        }
    }
}

/// The OpenSSH options `limen ssh` and `limen config ssh` use.
fn ssh_options(exe: &Path, proxy: &str, known_hosts: &Path) -> Vec<String> {
    let proxy_command = format!(
        "{} --proxy {proxy} ssh-proxy %r %h",
        shell_quote(&exe.display().to_string())
    );
    vec![
        format!("ProxyCommand={proxy_command}"),
        format!("UserKnownHostsFile={}", known_hosts.display()),
        "GlobalKnownHostsFile=/dev/null".into(),
        "StrictHostKeyChecking=yes".into(),
        // Authentication happens below SSH. Don't offer the user's keys or
        // passwords to the worker.
        "PubkeyAuthentication=no".into(),
        "PasswordAuthentication=no".into(),
        "KbdInteractiveAuthentication=no".into(),
        "GSSAPIAuthentication=no".into(),
        "IdentityAgent=none".into(),
        // Not supported through Limen (yet): refuse locally rather than fail remotely.
        "ForwardAgent=no".into(),
        "ForwardX11=no".into(),
        "ClearAllForwardings=yes".into(),
        "ServerAliveInterval=30".into(),
        // Limen prints its own errors (access denied, ...). Without this,
        // OpenSSH adds "Connection closed by UNKNOWN port 65535" after them.
        "LogLevel=ERROR".into(),
    ]
}

fn shell_quote(s: &str) -> String {
    if s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
    {
        s.to_owned()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

fn known_hosts_path(proxy: &str) -> anyhow::Result<PathBuf> {
    let path = profile::dir_for(proxy)?.join(KNOWN_HOSTS);
    if !path.exists() {
        bail!("no SSH host CA for {proxy} yet; run `limen login`");
    }
    Ok(path)
}

/// `limen ssh [login@]resource [command...]`: replace this process with OpenSSH.
pub async fn ssh(proxy: Option<&str>, target: &str, command: &[String]) -> anyhow::Result<()> {
    let proxy_addr = api::resolve_proxy(proxy)?;
    let profile = Profile::load(&proxy_addr)?
        .with_context(|| format!("not logged in to {proxy_addr}; run `limen login`"))?;
    profile.identity()?; // fail early on expired credentials
    let (login, resource) = split_target(target);
    let login = match login {
        Some(l) => l.to_owned(),
        None => default_login(proxy, resource).await?,
    };
    let exe = std::env::current_exe().context("locating the limen executable")?;
    let mut cmd = std::process::Command::new("ssh");
    for option in ssh_options(&exe, &proxy_addr, &known_hosts_path(&proxy_addr)?) {
        cmd.arg("-o").arg(option);
    }
    cmd.arg("-l").arg(&login).arg(resource);
    if !command.is_empty() {
        cmd.arg("--").args(command);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        Err(anyhow::Error::new(err).context("running ssh (is OpenSSH installed?)"))
    }
    #[cfg(not(unix))]
    {
        let status = cmd
            .status()
            .context("running ssh (is OpenSSH installed?)")?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

/// Open a session stream to the proxy on `alpn` for `principal` on `resource`
/// (`limen-ssh/1`, `limen-redis/1`, or `limen-mongo/1`). On success the stream carries the
/// protocol's own bytes. A refusal is returned as an error with the proxy's reason.
pub(crate) async fn open_session(
    proxy: Option<&str>,
    alpn: &[u8],
    resource: &str,
    principal: &str,
) -> anyhow::Result<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> {
    open_session_in(proxy, alpn, resource, principal, "", "").await
}

/// The same, for protocols whose session names a database (MongoDB), and with a
/// `group` that ties the sessions of one client run together in the console.
pub(crate) async fn open_session_in(
    proxy: Option<&str>,
    alpn: &[u8],
    resource: &str,
    principal: &str,
    database: &str,
    group: &str,
) -> anyhow::Result<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> {
    let proxy_addr = api::resolve_proxy(proxy)?;
    let profile = Profile::load(&proxy_addr)?
        .with_context(|| format!("not logged in to {proxy_addr}; run `limen login`"))?;
    let ca = profile::trusted_ca(&proxy_addr)?
        .with_context(|| format!("no CA pinned for {proxy_addr}"))?;
    let tls_config = client_config(
        &limen_tunnel::tls::certs_from_pem(&ca)?,
        Some(profile.identity()?),
        &[alpn],
    )?;
    let mut tls = limen_tunnel::connect::dial(
        &proxy_addr,
        api::server_name(&proxy_addr)?,
        std::sync::Arc::new(tls_config),
    )
    .await
    .with_context(|| format!("connecting to {proxy_addr}"))?;
    write_message(
        &mut tls,
        &SessionRequest {
            resource: resource.to_owned(),
            principal: principal.to_owned(),
            database: database.to_owned(),
            group: group.to_owned(),
        },
    )
    .await?;
    let response: SessionResponse = read_message(&mut tls)
        .await
        .context("reading the proxy's answer")?;
    if !response.ok {
        bail!("{}", response.error);
    }
    Ok(tls)
}

/// `limen ssh-proxy <login> <resource>`: OpenSSH's ProxyCommand. Opens the
/// session through the proxy, then pipes stdin and stdout.
pub async fn ssh_proxy(proxy: Option<&str>, login: &str, host: &str) -> anyhow::Result<()> {
    // `limen config ssh` sends hosts as <resource>.limen.
    let resource = host.strip_suffix(".limen").unwrap_or(host);
    let tls = open_session(proxy, limen_tunnel::alpn::SSH, resource, login).await?;
    let (mut from_proxy, mut to_proxy) = tokio::io::split(tls);
    let upload = async {
        let _ = tokio::io::copy(&mut tokio::io::stdin(), &mut to_proxy).await;
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut to_proxy).await;
    };
    let download = async {
        let mut stdout = tokio::io::stdout();
        let _ = tokio::io::copy(&mut from_proxy, &mut stdout).await;
        let _ = tokio::io::AsyncWriteExt::flush(&mut stdout).await;
    };
    // When the proxy side closes, the session is over.
    tokio::select! {
        () = download => {}
        () = async { upload.await; std::future::pending::<()>().await } => {}
    }
    // Exit now. Returning would make the runtime wait for the blocking stdin
    // read, so OpenSSH would never see our stdout close and would sit there
    // until its keepalive gave up: minutes after an admin ended the session.
    std::process::exit(0);
}

/// `limen config ssh`: an `ssh_config` block so plain `ssh <resource>.limen` works.
pub fn config(proxy: Option<&str>) -> anyhow::Result<()> {
    let proxy_addr = api::resolve_proxy(proxy)?;
    let exe = std::env::current_exe().context("locating the limen executable")?;
    println!("# Limen: add this to ~/.ssh/config, then `ssh <login>@<resource>.limen`.");
    println!("Host *.limen");
    for option in ssh_options(&exe, &proxy_addr, &known_hosts_path(&proxy_addr)?) {
        let (k, v) = option.split_once('=').unwrap_or((option.as_str(), ""));
        println!("    {k} {v}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_login_and_resource() {
        assert_eq!(split_target("ubuntu@web-1"), (Some("ubuntu"), "web-1"));
        assert_eq!(split_target("web-1"), (None, "web-1"));
    }

    #[test]
    fn options_never_offer_keys_or_forwarding() {
        let opts = ssh_options(
            Path::new("/usr/local/bin/limen"),
            "limen.example.com:443",
            Path::new("/home/a/.limen/known_hosts"),
        );
        for must in [
            "PubkeyAuthentication=no",
            "IdentityAgent=none",
            "ForwardAgent=no",
            "StrictHostKeyChecking=yes",
            "ClearAllForwardings=yes",
        ] {
            assert!(opts.iter().any(|o| o == must), "{must}");
        }
        assert!(opts.iter().any(|o| o.starts_with(
            "ProxyCommand=/usr/local/bin/limen --proxy limen.example.com:443 ssh-proxy %r %h"
        )));
    }

    #[test]
    fn quotes_paths_with_spaces() {
        assert_eq!(
            shell_quote("/Applications/My Tools/limen"),
            "'/Applications/My Tools/limen'"
        );
        assert_eq!(shell_quote("/usr/bin/limen"), "/usr/bin/limen");
    }
}
