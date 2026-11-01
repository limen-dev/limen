//! `limen doctor` (#118): why access doesn't work, in the order things go
//! wrong. Each check passes, warns, fails, or is skipped because one it
//! depends on failed, and a failure says how to fix it.
//!
//! Nothing secret is printed, in text or `--json`: no key, no certificate
//! body, no token. The output is meant for support tickets.

use std::path::Path;
use std::time::Duration;

use limen_proto::v1::auth_client::AuthClient;
use limen_proto::v1::{GetAuthConfigRequest, WhoAmIRequest};
use serde::Serialize;
use time::OffsetDateTime;

use crate::profile::{self, Profile};
use crate::{api, ui};

/// How long any one network step may take.
const STEP_TIMEOUT: Duration = Duration::from_secs(5);
/// Clock difference worth a warning, and one that breaks things: the CA
/// back-dates certificates by a minute, and IdP tokens allow little more.
const SKEW_WARN: i64 = 30;
const SKEW_FAIL: i64 = 120;
/// Credentials closer than this to expiring get a warning.
const EXPIRY_WARN: i64 = 5 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Pass,
    Warn,
    Fail,
    Skip,
}

#[derive(Debug, Serialize)]
struct Check {
    name: &'static str,
    status: Status,
    summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    fix: Option<String>,
}

#[derive(Debug, Default)]
struct Report {
    checks: Vec<Check>,
}

impl Report {
    fn add(&mut self, name: &'static str, status: Status, summary: impl Into<String>) {
        self.checks.push(Check {
            name,
            status,
            summary: summary.into(),
            fix: None,
        });
    }

    fn pass(&mut self, name: &'static str, summary: impl Into<String>) {
        self.add(name, Status::Pass, summary);
    }

    fn skip(&mut self, name: &'static str, why: &str) {
        self.add(name, Status::Skip, format!("skipped: {why}"));
    }

    fn problem(
        &mut self,
        name: &'static str,
        status: Status,
        summary: impl Into<String>,
        fix: impl Into<String>,
    ) {
        self.checks.push(Check {
            name,
            status,
            summary: summary.into(),
            fix: Some(fix.into()),
        });
    }

    fn fail(&mut self, name: &'static str, summary: impl Into<String>, fix: impl Into<String>) {
        self.problem(name, Status::Fail, summary, fix);
    }

    fn warn(&mut self, name: &'static str, summary: impl Into<String>, fix: impl Into<String>) {
        self.problem(name, Status::Warn, summary, fix);
    }

    fn failures(&self) -> usize {
        self.checks
            .iter()
            .filter(|c| c.status == Status::Fail)
            .count()
    }
}

/// `limen doctor [resource] [--json]`.
pub async fn run(flag: Option<&str>, resource: Option<&str>, json: bool) -> anyhow::Result<()> {
    let mut report = Report::default();
    let proxy = diagnose(&mut report, flag, resource).await;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "client_version": limen_core::VERSION,
                "proxy": proxy,
                "resource": resource,
                "ok": report.failures() == 0,
                "checks": report.checks,
            }))?
        );
    } else {
        anstream::println!("{}", render(&report));
    }
    match report.failures() {
        0 => {
            if !json {
                ui::success("No problems found.");
            }
            Ok(())
        }
        1 => anyhow::bail!("1 check failed"),
        n => anyhow::bail!("{n} checks failed"),
    }
}

/// Every check, in order. Returns the proxy, if one was found.
async fn diagnose(
    report: &mut Report,
    flag: Option<&str>,
    resource: Option<&str>,
) -> Option<String> {
    let Some(proxy) = check_proxy(report, flag) else {
        for name in ["ca", "network", "tls", "clock", "login", "session"] {
            report.skip(name, "no proxy");
        }
        return None;
    };
    let roots = check_ca(report, &proxy);
    let reachable = check_network(report, &proxy).await;
    let tls_ok = match (&roots, reachable) {
        (Some(roots), true) => check_tls(report, &proxy, roots).await,
        (None, _) => {
            report.skip("tls", "no CA pinned");
            false
        }
        (_, false) => {
            report.skip("tls", "proxy unreachable");
            false
        }
    };
    if tls_ok {
        check_server(report, &proxy).await;
    } else {
        report.skip("clock", "no TLS connection to the proxy");
    }
    let login = check_login(report, &proxy);
    match (login, tls_ok) {
        (Some(profile), true) => {
            if check_session(report, &proxy, &profile).await
                && let Some(name) = resource
            {
                check_resource(report, &proxy, name).await;
            }
        }
        (None, _) => report.skip("session", "no valid login"),
        (Some(_), false) => report.skip("session", "no TLS connection to the proxy"),
    }
    if resource.is_some() && !report.checks.iter().any(|c| c.name == "access") {
        report.skip("access", "needs a working session");
    }
    check_integrations(report);
    Some(proxy)
}

fn check_proxy(report: &mut Report, flag: Option<&str>) -> Option<String> {
    let Ok(proxy) = api::resolve_proxy(flag) else {
        report.fail(
            "proxy",
            "no proxy selected",
            "`limen login --proxy <host:port> --ca-file <ca.pem>`, or set LIMEN_PROXY",
        );
        return None;
    };
    if let Err(e) = api::server_name(&proxy) {
        report.fail(
            "proxy",
            format!("{proxy:?} is not a valid proxy address: {e}"),
            "use host:port, for example `--proxy limen.example.com:443`",
        );
        return None;
    }
    let source = if flag.is_some() {
        "from --proxy or LIMEN_PROXY"
    } else {
        "from the last login"
    };
    report.pass("proxy", format!("{proxy} ({source})"));
    Some(proxy)
}

/// The pinned CA, if there is one and it is usable.
fn check_ca(
    report: &mut Report,
    proxy: &str,
) -> Option<Vec<rustls_pki_types::CertificateDer<'static>>> {
    let fix = format!("`limen login --proxy {proxy} --ca-file <ca.pem>` with the proxy's CA");
    let pem = match profile::trusted_ca(proxy) {
        Ok(Some(pem)) => pem,
        Ok(None) => {
            report.fail("ca", format!("no CA is pinned for {proxy}"), fix);
            return None;
        }
        Err(e) => {
            report.fail("ca", format!("can't read the pinned CA: {e:#}"), fix);
            return None;
        }
    };
    let roots = match limen_tunnel::tls::certs_from_pem(&pem) {
        Ok(roots) if !roots.is_empty() => roots,
        Ok(_) | Err(_) => {
            report.fail("ca", "the pinned CA file holds no PEM certificate", fix);
            return None;
        }
    };
    let now = OffsetDateTime::now_utc().unix_timestamp();
    // A bundle can hold an old root next to its replacement during a rotation;
    // connections work through any valid one, so only all-expired is a failure.
    let expired: Vec<String> = roots
        .iter()
        .filter_map(|der| cert_subject_and_expiry(der))
        .filter(|(_, not_after)| *not_after <= now)
        .map(|(subject, _)| subject)
        .collect();
    if expired.len() == roots.len() {
        report.fail(
            "ca",
            format!("the pinned CA {} has expired", expired.join(", ")),
            fix,
        );
        return None;
    }
    if !expired.is_empty() {
        report.warn(
            "ca",
            format!(
                "the pinned bundle holds an expired CA ({}); the others still work",
                expired.join(", ")
            ),
            "`limen login` after the proxy's CA rotation drops the old one",
        );
    }
    let n = roots.len();
    report.pass(
        "ca",
        format!("{n} CA certificate{} pinned", if n == 1 { "" } else { "s" }),
    );
    Some(roots)
}

/// DNS and TCP, separately from TLS, so "unreachable" and "untrusted" read differently.
async fn check_network(report: &mut Report, proxy: &str) -> bool {
    let fix = "check the address, your VPN or network, and that the proxy is running";
    let addrs = match tokio::time::timeout(STEP_TIMEOUT, tokio::net::lookup_host(proxy)).await {
        Ok(Ok(addrs)) => addrs.collect::<Vec<_>>(),
        Ok(Err(e)) => {
            report.fail("network", format!("can't resolve {proxy}: {e}"), fix);
            return false;
        }
        Err(_) => {
            report.fail("network", format!("resolving {proxy} timed out"), fix);
            return false;
        }
    };
    let mut last = String::from("the name resolved to no address");
    for addr in &addrs {
        match tokio::time::timeout(STEP_TIMEOUT, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(_)) => {
                report.pass("network", format!("{addr} accepts connections"));
                return true;
            }
            Ok(Err(e)) => last = format!("{addr}: {e}"),
            Err(_) => last = format!("{addr}: timed out"),
        }
    }
    report.fail("network", format!("can't connect to {proxy} ({last})"), fix);
    false
}

async fn check_tls(
    report: &mut Report,
    proxy: &str,
    roots: &[rustls_pki_types::CertificateDer<'static>],
) -> bool {
    let attempt = async {
        let config = limen_tunnel::tls::client_config(roots, None, &[limen_tunnel::alpn::H2])?;
        let name = api::server_name(proxy)?;
        limen_tunnel::connect::dial(proxy, name, std::sync::Arc::new(config)).await?;
        anyhow::Ok(())
    };
    match tokio::time::timeout(STEP_TIMEOUT, attempt).await {
        Ok(Ok(())) => {
            report.pass("tls", "the proxy's certificate is signed by the pinned CA");
            true
        }
        Ok(Err(e)) => {
            let (summary, fix) = tls_problem(proxy, &format!("{e:#}"));
            report.fail("tls", summary, fix);
            false
        }
        Err(_) => {
            report.fail(
                "tls",
                "the TLS handshake timed out",
                "something between you and the proxy may not speak TLS; check the port",
            );
            false
        }
    }
}

/// A TLS failure in words, with the fix.
fn tls_problem(proxy: &str, error: &str) -> (String, String) {
    if let Some(hint) = api::tls_hint(error) {
        return (
            "the proxy's certificate isn't signed by the pinned CA".into(),
            hint.into(),
        );
    }
    if error.contains("NotValidForName") {
        let host = api::server_name(proxy).unwrap_or(proxy);
        return (
            format!("the proxy's certificate isn't valid for {host}"),
            "use the name on the proxy's certificate in --proxy".into(),
        );
    }
    if error.contains("Expired") || error.contains("NotValidYet") {
        return (
            format!("the proxy's certificate is outside its validity period ({error})"),
            "check this machine's clock; if it is right, the proxy's certificate needs renewing"
                .into(),
        );
    }
    (
        format!("TLS handshake failed: {error}"),
        "check that --proxy names the Limen proxy's TLS port".into(),
    )
}

/// Clock and version, from an unauthenticated call any client may make.
async fn check_server(report: &mut Report, proxy: &str) {
    let call = async {
        let channel = api::connect(proxy, None)?;
        let before = OffsetDateTime::now_utc();
        let response = AuthClient::new(channel)
            .get_auth_config(GetAuthConfigRequest {})
            .await
            .map_err(anyhow::Error::new)?;
        let after = OffsetDateTime::now_utc();
        let midpoint: OffsetDateTime = before + (after - before) / 2;
        anyhow::Ok((response, midpoint))
    };
    let (response, local) = match tokio::time::timeout(STEP_TIMEOUT, call).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            server_call_failed(report, &e);
            return;
        }
        Err(_) => {
            report.fail(
                "clock",
                "the proxy didn't answer within 5 seconds",
                "the control plane behind it may be down; try again shortly or tell an admin",
            );
            return;
        }
    };
    let remote = response
        .metadata()
        .get("date")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_http_date);
    match remote {
        Some(remote) => clock_result(report, (remote - local).whole_seconds()),
        None => report.skip("clock", "the proxy didn't send its time"),
    }
    let server = response.into_inner().server_version;
    if !server.is_empty() && minor(&server) != minor(limen_core::VERSION) {
        report.warn(
            "version",
            format!(
                "this client is {}, the server is {server}",
                limen_core::VERSION
            ),
            "install the client that matches the server",
        );
    }
}

/// Why the unauthenticated call failed, in words. Only a reply that isn't
/// gRPC at all suggests the wrong service; a refusal from Limen says so.
fn server_call_failed(report: &mut Report, error: &anyhow::Error) {
    let Some(status) = error.downcast_ref::<tonic::Status>() else {
        report.fail(
            "clock",
            format!("couldn't ask the proxy: {error:#}"),
            "try again shortly; if it persists, tell an admin",
        );
        return;
    };
    match status.code() {
        tonic::Code::ResourceExhausted => report.warn(
            "clock",
            format!(
                "not checked: the proxy is rate-limiting this address ({})",
                status.message()
            ),
            "wait a minute and run `limen doctor` again",
        ),
        tonic::Code::Unavailable => report.fail(
            "clock",
            format!(
                "the proxy can't reach the control plane: {}",
                status.message()
            ),
            "the control plane may be restarting; try again shortly or tell an admin",
        ),
        tonic::Code::Unimplemented | tonic::Code::Unknown | tonic::Code::Internal => report.fail(
            "clock",
            format!(
                "the proxy answered TLS but not Limen's API: {}",
                status.message()
            ),
            "check that --proxy names the Limen proxy, not another service",
        ),
        _ => report.fail(
            "clock",
            api::status_error(status).to_string(),
            "try again shortly; if it persists, tell an admin",
        ),
    }
}

fn clock_result(report: &mut Report, skew: i64) {
    let ahead = if skew > 0 { "behind" } else { "ahead of" };
    let summary = format!(
        "this machine's clock is {}s {ahead} the proxy's",
        skew.abs()
    );
    let fix = "turn on automatic time (NTP) on this machine";
    match skew.abs() {
        s if s >= SKEW_FAIL => report.fail("clock", summary, fix),
        s if s >= SKEW_WARN => report.warn("clock", summary, fix),
        _ => report.pass("clock", "in step with the proxy"),
    }
}

/// `1.2` of `1.2.3-rc.1`.
fn minor(version: &str) -> String {
    version.split('.').take(2).collect::<Vec<_>>().join(".")
}

/// An HTTP `Date` header (`Sun, 06 Nov 1994 08:49:37 GMT`).
fn parse_http_date(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &time::format_description::well_known::Rfc2822).ok()
}

/// The local login: present, intact, and not expired.
fn check_login(report: &mut Report, proxy: &str) -> Option<Profile> {
    let fix = "`limen login`";
    let profile = match Profile::load(proxy) {
        Ok(Some(p)) => p,
        Ok(None) => {
            report.fail("login", format!("not logged in to {proxy}"), fix);
            return None;
        }
        Err(e) => {
            report.fail("login", format!("can't read the login: {e:#}"), fix);
            return None;
        }
    };
    let parsed = limen_tunnel::tls::certs_from_pem(&profile.cert_pem)
        .ok()
        .and_then(|c| c.into_iter().next());
    let Some(cert) = parsed else {
        report.fail("login", "the login certificate can't be read", fix);
        return None;
    };
    if !key_matches(&cert, profile.key_pem.expose()) {
        report.fail(
            "login",
            "the login certificate doesn't belong to the local key",
            "`limen logout`, then `limen login`",
        );
        return None;
    }
    let not_after = cert_subject_and_expiry(&cert).map_or(profile.meta.expires_at_unix, |(_, t)| t);
    let left = not_after - OffsetDateTime::now_utc().unix_timestamp();
    let who = &profile.meta.username;
    if left <= 0 {
        report.fail(
            "login",
            format!("the login for {who} expired {} ago", human(-left)),
            fix,
        );
        return None;
    }
    let summary = format!("{who}, expires in {}", human(left));
    if left < EXPIRY_WARN {
        report.warn(
            "login",
            summary,
            "`limen login` again before a long session",
        );
    } else {
        report.pass("login", summary);
    }
    check_permissions(report, proxy);
    Some(profile)
}

/// Warn if the private key or its directory can be read by others.
fn check_permissions(report: &mut Report, proxy: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let Ok(dir) = profile::dir_for(proxy) else {
            return;
        };
        let mode = |p: &Path| std::fs::metadata(p).map(|m| m.permissions().mode() & 0o777);
        let key = dir.join("key.pem");
        if let (Ok(k), Ok(d)) = (mode(&key), mode(&dir))
            && (k & 0o077 != 0 || d & 0o077 != 0)
        {
            report.warn(
                "files",
                format!("the private key or its directory can be read by others ({k:o}, {d:o})"),
                format!("chmod 700 {} && chmod 600 {}", dir.display(), key.display()),
            );
        }
    }
    #[cfg(not(unix))]
    let _ = proxy;
}

/// Whether the certificate's public key is the local private key's.
fn key_matches(cert: &[u8], key_pem: &str) -> bool {
    use rcgen::PublicKeyData as _;
    let Ok(key) = rcgen::KeyPair::from_pem(key_pem) else {
        return false;
    };
    x509_parser::parse_x509_certificate(cert)
        .is_ok_and(|(_, c)| c.tbs_certificate.subject_pki.raw == key.subject_public_key_info())
}

fn cert_subject_and_expiry(der: &[u8]) -> Option<(String, i64)> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    Some((
        cert.subject().to_string(),
        cert.validity().not_after.timestamp(),
    ))
}

/// The server's view of the login: ended, revoked, or locked show up here.
async fn check_session(report: &mut Report, proxy: &str, profile: &Profile) -> bool {
    let call = async {
        let channel = api::connect(proxy, Some(profile.identity()?))?;
        AuthClient::new(channel)
            .who_am_i(WhoAmIRequest {})
            .await
            .map_err(anyhow::Error::new)
    };
    match tokio::time::timeout(STEP_TIMEOUT, call).await {
        Ok(Ok(r)) => {
            let me = r.into_inner();
            let roles = if me.roles.is_empty() {
                "no roles".to_owned()
            } else {
                format!("roles {}", me.roles.join(", "))
            };
            report.pass(
                "session",
                format!("the proxy accepts you as {} ({roles})", me.username),
            );
            true
        }
        Ok(Err(e)) => {
            let (summary, fix) = match e.downcast_ref::<tonic::Status>() {
                Some(s) if s.code() == tonic::Code::Unauthenticated => (
                    format!("the proxy refused your login: {}", s.message()),
                    "it was ended (`limen logout` elsewhere) or revoked; run `limen login`"
                        .to_owned(),
                ),
                Some(s) if s.code() == tonic::Code::PermissionDenied => (
                    format!("the proxy refused you: {}", s.message()),
                    "you may be locked; ask an admin (`limen admin locks`)".to_owned(),
                ),
                Some(s) => (
                    api::status_error(s).to_string(),
                    "try again shortly; if it persists, tell an admin".to_owned(),
                ),
                None => (format!("{e:#}"), "`limen login`".to_owned()),
            };
            report.fail("session", summary, fix);
            false
        }
        Err(_) => {
            report.fail(
                "session",
                "the proxy didn't answer within 5 seconds",
                "the control plane behind it may be down; try again shortly or tell an admin",
            );
            false
        }
    }
}

/// Whether policy gives you `name` (and if not, why and how to get it),
/// whether a grant is about to end, whether a worker serves it, and what you
/// need locally to open it.
async fn check_resource(report: &mut Report, proxy: &str, name: &str) {
    let listed = match super::fetch_all(Some(proxy)).await {
        Ok(r) => r,
        Err(e) => {
            report.fail(
                "access",
                format!("can't list your resources: {e:#}"),
                "try again shortly",
            );
            return;
        }
    };
    // The server's own words (ADR-0028); older control planes have none.
    let (explained, explain_error) = match tokio::time::timeout(
        STEP_TIMEOUT,
        super::access::explain_for(Some(proxy), name, ""),
    )
    .await
    {
        Ok(Ok(r)) => (Some(r), None),
        Ok(Err(e)) => (None, Some(format!("{e:#}"))),
        Err(_) => (None, Some("timed out".to_owned())),
    };
    let Some(r) = listed.resources.iter().find(|r| r.name == name) else {
        access_denied(report, &listed, explained.as_ref(), name);
        return;
    };
    report.pass(
        "access",
        format!("{} ({}), as {}", r.name, r.kind, r.principals.join(", ")),
    );
    check_grant(report, r.grant_expires_at_unix);
    match explained.as_ref().and_then(|e| e.worker_connected) {
        Some(true) => report.pass("worker", "a worker that can reach it is connected"),
        Some(false) => report.fail(
            "worker",
            format!("no worker that can reach {name} is connected"),
            "sessions fail until one is; tell an admin (the worker is down, or no worker's labels match the resource's worker_selector)",
        ),
        None => match &explain_error {
            // Say what went wrong; an old control plane that doesn't report it is the other case.
            Some(why) => report.skip("worker", &format!("couldn't ask the control plane: {why}")),
            None => report.skip("worker", "the control plane doesn't report it"),
        },
    }
    match r.kind.as_str() {
        "ssh" => {
            let known_hosts = profile::dir_for(proxy).map(|d| d.join(super::ssh::KNOWN_HOSTS));
            if !known_hosts.as_ref().is_ok_and(|p| p.exists()) {
                report.fail(
                    "client",
                    "no SSH host CA in the profile, so OpenSSH can't verify the worker",
                    "`limen login` writes it",
                );
            } else if on_path("ssh") {
                report.pass("client", "OpenSSH (ssh) is installed");
            } else {
                report.fail(
                    "client",
                    "OpenSSH (ssh) isn't on PATH",
                    "install the OpenSSH client",
                );
            }
        }
        "kubernetes" if !on_path("kubectl") => report.warn(
            "client",
            "kubectl isn't on PATH",
            "install kubectl, or use any Kubernetes client with `limen kube login`",
        ),
        _ => {}
    }
}

/// `name` isn't yours: say why, in the server's words when it has them, and
/// how to get it (#120).
fn access_denied(
    report: &mut Report,
    listed: &limen_proto::v1::ListResourcesResponse,
    explained: Option<&limen_proto::v1::ExplainResponse>,
    name: &str,
) {
    let requestable = listed.requestable.iter().any(|r| r.name == name);
    let summary = if requestable {
        format!("you don't have {name} yet, but you can request it")
    } else {
        format!("policy gives you no access to {name:?} (or there is no such resource)")
    };
    let near: Vec<_> = listed
        .resources
        .iter()
        .filter(|r| r.name.contains(name) || name.contains(r.name.as_str()))
        .map(|r| r.name.as_str())
        .collect();
    let mut fix = match explained {
        Some(e) if !e.lines.is_empty() => e.lines.join("\n"),
        _ if requestable => format!("`limen request {name} --for 30m --reason \"...\"`"),
        _ => {
            "check the name with `limen ls`; if it's right, ask an admin for a role that grants it"
                .to_owned()
        }
    };
    if !near.is_empty() && !requestable {
        fix = format!("did you mean {}?\n{fix}", near.join(", "));
    }
    report.fail("access", summary, fix);
}

/// Access through an approved request ends; warn before it does.
fn check_grant(report: &mut Report, expires_at_unix: i64) {
    if expires_at_unix == 0 {
        return;
    }
    let left = expires_at_unix - OffsetDateTime::now_utc().unix_timestamp();
    if left <= 2 * EXPIRY_WARN {
        report.warn(
            "grant",
            format!("your access request's grant ends in {}", human(left.max(0))),
            "ask again (`limen request`) if you need longer",
        );
    } else {
        report.pass(
            "grant",
            format!("through an approved request, ends in {}", human(left)),
        );
    }
}

/// The ssh_config and kubeconfig integrations, when installed.
fn check_integrations(report: &mut Report) {
    let Ok(home) = profile::home() else { return };
    if home.join("ssh_config").exists() {
        match super::tools::ssh_installed(None) {
            Ok(true) => report.pass("ssh-config", "~/.ssh/config includes Limen's hosts"),
            _ => report.warn(
                "ssh-config",
                "Limen's ssh_config exists but ~/.ssh/config doesn't include it",
                "`limen config ssh --install`",
            ),
        }
    }
    let kubeconfig = home.join("kubeconfig");
    if kubeconfig.exists() {
        let listed = std::env::var_os("KUBECONFIG")
            .is_some_and(|v| std::env::split_paths(&v).any(|p| p == kubeconfig));
        if listed {
            report.pass("kubeconfig", "KUBECONFIG includes Limen's contexts");
        } else {
            report.warn(
                "kubeconfig",
                "KUBECONFIG doesn't include Limen's kubeconfig",
                format!(
                    "export KUBECONFIG=\"${{KUBECONFIG:-$HOME/.kube/config}}:{}\"",
                    kubeconfig.display()
                ),
            );
        }
    }
}

fn on_path(program: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|dir| {
            let p = dir.join(program);
            p.is_file() || p.with_extension("exe").is_file()
        })
    })
}

/// `2h 5m`, `42m`, `30s`.
fn human(secs: i64) -> String {
    let (h, m, s) = (secs / 3600, secs % 3600 / 60, secs % 60);
    match (h, m) {
        (0, 0) => format!("{s}s"),
        (0, m) => format!("{m}m"),
        (h, 0) => format!("{h}h"),
        (h, m) => format!("{h}h {m}m"),
    }
}

fn render(report: &Report) -> String {
    let width = report
        .checks
        .iter()
        .map(|c| c.name.len())
        .max()
        .unwrap_or(0);
    let mut out = Vec::new();
    for c in &report.checks {
        let (glyph, summary) = match c.status {
            Status::Pass => (ui::green("✔"), c.summary.clone()),
            Status::Warn => (ui::yellow("!"), c.summary.clone()),
            Status::Fail => (ui::red("✖"), ui::bold(&c.summary)),
            Status::Skip => (ui::dim("–"), ui::dim(&c.summary)),
        };
        out.push(format!(
            "{glyph} {}  {summary}",
            ui::dim(&format!("{:<width$}", c.name))
        ));
        if let Some(fix) = &c.fix {
            for (i, line) in fix.lines().enumerate() {
                let arrow = if i == 0 { "→" } else { " " };
                out.push(format!(
                    "  {}  {}",
                    " ".repeat(width),
                    ui::dim(&format!("{arrow} {line}"))
                ));
            }
        }
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_dates_parse() {
        let t = parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT").expect("parses");
        assert_eq!(t.unix_timestamp(), 784_111_777);
        assert!(parse_http_date("yesterday").is_none());
    }

    #[test]
    fn clock_skew_thresholds() {
        let status = |skew| {
            let mut r = Report::default();
            clock_result(&mut r, skew);
            (r.checks[0].status, r.checks[0].summary.clone())
        };
        assert_eq!(status(3).0, Status::Pass);
        assert_eq!(status(-45).0, Status::Warn);
        let (s, text) = status(600);
        assert_eq!(s, Status::Fail);
        assert!(text.contains("600s behind"), "{text}");
        assert!(status(-600).1.contains("ahead of"));
    }

    #[test]
    fn tls_failures_say_what_to_do() {
        let (summary, fix) = tls_problem("p:443", "invalid peer certificate: UnknownIssuer");
        assert!(summary.contains("pinned CA") && fix.contains("--ca-file"));
        let (summary, _) = tls_problem(
            "limen.example:443",
            "invalid peer certificate: NotValidForName",
        );
        assert!(summary.contains("limen.example"));
        let (_, fix) = tls_problem("p:443", "invalid peer certificate: Expired");
        assert!(fix.contains("clock"));
    }

    #[test]
    fn server_errors_are_told_apart() {
        let status = |code, message: &str| {
            let mut r = Report::default();
            server_call_failed(
                &mut r,
                &anyhow::Error::new(tonic::Status::new(code, message)),
            );
            (r.checks[0].status, r.checks[0].summary.clone())
        };
        let (s, text) = status(
            tonic::Code::ResourceExhausted,
            "too many requests; slow down",
        );
        assert_eq!(s, Status::Warn, "a rate limit is not a broken setup");
        assert!(text.contains("rate-limiting"));
        assert!(
            status(tonic::Code::Unavailable, "x")
                .1
                .contains("control plane")
        );
        assert!(
            status(tonic::Code::Unimplemented, "x")
                .1
                .contains("not Limen's API")
        );
    }

    #[test]
    fn versions_compare_by_minor() {
        assert_eq!(minor("0.1.0-rc.1"), "0.1");
        assert_eq!(minor("1.12.3"), "1.12");
    }

    #[test]
    fn durations_read_like_status() {
        assert_eq!(human(30), "30s");
        assert_eq!(human(42 * 60 + 5), "42m");
        assert_eq!(human(2 * 3600), "2h");
        assert_eq!(human(2 * 3600 + 5 * 60), "2h 5m");
    }

    #[test]
    fn the_key_must_match_the_certificate() {
        let key = rcgen::KeyPair::generate().expect("key");
        let other = rcgen::KeyPair::generate().expect("key");
        let cert = rcgen::CertificateParams::new(vec!["u".into()])
            .expect("params")
            .self_signed(&key)
            .expect("cert");
        assert!(key_matches(cert.der(), &key.serialize_pem()));
        assert!(!key_matches(cert.der(), &other.serialize_pem()));
        assert!(!key_matches(cert.der(), "not a key"));
        let (_, not_after) = cert_subject_and_expiry(cert.der()).expect("parse");
        assert!(not_after > OffsetDateTime::now_utc().unix_timestamp());
    }

    #[test]
    fn json_report_carries_no_secret_fields_and_fixes_only_on_problems() {
        let mut r = Report::default();
        r.pass("proxy", "p:443");
        r.fail("login", "not logged in to p:443", "`limen login`");
        r.skip("session", "no valid login");
        let v = serde_json::to_value(&r.checks).expect("json");
        assert_eq!(
            v[0],
            serde_json::json!({"name": "proxy", "status": "pass", "summary": "p:443"})
        );
        assert_eq!(v[1]["status"], "fail");
        assert_eq!(v[1]["fix"], "`limen login`");
        assert_eq!(r.failures(), 1);
        let text = ui::plain(&render(&r));
        assert!(text.contains("✖ login    not logged in"), "{text}");
        assert!(text.contains("→ `limen login`"));
    }

    fn listed(mine: &[&str], requestable: &[&str]) -> limen_proto::v1::ListResourcesResponse {
        limen_proto::v1::ListResourcesResponse {
            resources: mine
                .iter()
                .map(|n| limen_proto::v1::Resource {
                    name: (*n).to_owned(),
                    ..Default::default()
                })
                .collect(),
            requestable: requestable
                .iter()
                .map(|n| limen_proto::v1::RequestableResource {
                    name: (*n).to_owned(),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn a_denial_says_why_and_how_to_get_access() {
        // The server's explanation is the fix, line by line.
        let explained = limen_proto::v1::ExplainResponse {
            lines: vec![
                "You can't reach `orders-prod` yet, but you can ask for it.".into(),
                "Run: limen request orders-prod --for 30m --reason \"...\"".into(),
            ],
            ..Default::default()
        };
        let mut r = Report::default();
        access_denied(
            &mut r,
            &listed(&[], &["orders-prod"]),
            Some(&explained),
            "orders-prod",
        );
        assert_eq!(
            r.checks[0].summary,
            "you don't have orders-prod yet, but you can request it"
        );
        let text = ui::plain(&render(&r));
        assert!(text.contains("→ You can't reach"), "{text}");
        assert!(text.contains("  Run: limen request orders-prod"), "{text}");

        // An older control plane: still the command.
        let mut r = Report::default();
        access_denied(&mut r, &listed(&[], &["orders-prod"]), None, "orders-prod");
        assert!(
            r.checks[0]
                .fix
                .as_deref()
                .unwrap_or_default()
                .contains("limen request orders-prod")
        );

        // A near miss is suggested first.
        let mut r = Report::default();
        access_denied(
            &mut r,
            &listed(&["web-staging-1"], &[]),
            None,
            "web-staging",
        );
        assert!(
            r.checks[0]
                .fix
                .as_deref()
                .unwrap_or_default()
                .starts_with("did you mean web-staging-1?")
        );
    }

    #[test]
    fn grants_warn_before_they_end() {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let mut r = Report::default();
        check_grant(&mut r, 0);
        assert!(r.checks.is_empty(), "standing access has no grant");
        check_grant(&mut r, now + 3600);
        check_grant(&mut r, now + 120);
        assert_eq!(r.checks[0].status, Status::Pass);
        assert_eq!(r.checks[1].status, Status::Warn);
        assert!(r.checks[1].summary.contains("ends in"));
    }
}
