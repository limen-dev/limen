//! `limen kube login` and `limen kube credentials` (ADR-0038).
//!
//! `login` writes a kubeconfig whose only credential is an exec plugin that
//! runs `limen kube credentials`. That prints the user's short-lived Limen
//! certificate for kubectl to present to the proxy. Nothing long-lived is
//! ever written into the kubeconfig.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use base64::Engine as _;
use limen_proto::v1::ListResourcesRequest;
use limen_proto::v1::resources_client::ResourcesClient;
use serde_json::json;
use time::format_description::well_known::Rfc3339;

use crate::profile::{self, Profile};
use crate::{api, ui};

/// `limen kube login <cluster>`.
pub async fn login(
    proxy: Option<&str>,
    cluster: &str,
    kubeconfig: Option<&Path>,
    print: bool,
) -> anyhow::Result<()> {
    let (profile, channel) = api::authenticated(proxy)?;
    let resources = ResourcesClient::new(channel)
        .list_resources(ListResourcesRequest {})
        .await
        .map_err(|s| api::status_error(&s))?
        .into_inner()
        .resources;
    let Some(found) = resources
        .iter()
        .find(|r| r.name == cluster && r.kind == "kubernetes")
    else {
        bail!("you have no Kubernetes access to {cluster:?}; see `limen ls`");
    };
    let proxy_addr = profile.meta.proxy.clone();
    let exe = std::env::current_exe().context("finding the limen executable")?;
    let config = kubeconfig_json(
        &proxy_addr,
        cluster,
        profile::trusted_ca(&proxy_addr)?.as_deref(),
        &exe,
        std::env::var_os("LIMEN_HOME").map(PathBuf::from).as_deref(),
    );
    let text = serde_json::to_string_pretty(&config)?;
    if print {
        anstream::println!("{text}");
        return Ok(());
    }
    let path = match kubeconfig {
        Some(p) => p.to_owned(),
        None => profile::dir_for(&proxy_addr)?.join(format!("kubeconfig-{cluster}.json")),
    };
    write_private(&path, &text)?;
    ui::success(&format!(
        "Wrote a kubeconfig for {} (groups: {}).",
        ui::bold(cluster),
        found.principals.join(", ")
    ));
    ui::hint(&format!(
        "Use it with `export KUBECONFIG={}`, or `kubectl --kubeconfig {} get pods`.",
        path.display(),
        path.display()
    ));
    Ok(())
}

/// The kubeconfig, as JSON (kubectl reads JSON as readily as YAML).
///
/// `home` is `$LIMEN_HOME` when it is set. kubectl runs the plugin in its own
/// environment, which need not have it, so it is written into the plugin's.
fn kubeconfig_json(
    proxy: &str,
    cluster: &str,
    ca_pem: Option<&str>,
    exe: &Path,
    home: Option<&Path>,
) -> serde_json::Value {
    let mut cluster_entry = json!({ "server": format!("https://{proxy}/k8s/{cluster}") });
    if let Some(ca) = ca_pem {
        cluster_entry["certificate-authority-data"] =
            json!(base64::engine::general_purpose::STANDARD.encode(ca));
    }
    let name = format!("limen-{cluster}");
    let mut exec = json!({
        "apiVersion": "client.authentication.k8s.io/v1",
        "command": exe.display().to_string(),
        "args": ["--proxy", proxy, "kube", "credentials"],
        "interactiveMode": "Never",
        "provideClusterInfo": false,
    });
    if let Some(home) = home {
        exec["env"] = json!([{ "name": "LIMEN_HOME", "value": home.display().to_string() }]);
    }
    json!({
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [{ "name": name, "cluster": cluster_entry }],
        "users": [{
            "name": "limen",
            "user": { "exec": exec },
        }],
        "contexts": [{ "name": name, "context": { "cluster": name, "user": "limen" } }],
        "current-context": name,
    })
}

/// `limen kube credentials`: the exec plugin. Writes an `ExecCredential` to
/// standard output, and nothing else there.
#[allow(clippy::print_stdout)]
pub fn credentials(proxy: Option<&str>) -> anyhow::Result<()> {
    let proxy = api::resolve_proxy(proxy)?;
    let profile = Profile::load(&proxy)?
        .with_context(|| format!("not logged in to {proxy}; run `limen login`"))?;
    println!("{}", exec_credential(&profile)?);
    Ok(())
}

fn exec_credential(profile: &Profile) -> anyhow::Result<String> {
    if profile.is_expired() {
        bail!(
            "your Limen credentials for {} expired at {}; run `limen login`",
            profile.meta.proxy,
            profile.expires_at()
        );
    }
    Ok(serde_json::to_string(&json!({
        "apiVersion": "client.authentication.k8s.io/v1",
        "kind": "ExecCredential",
        "status": {
            "expirationTimestamp": profile.expires_at().format(&Rfc3339)?,
            "clientCertificateData": profile.cert_pem,
            "clientKeyData": profile.key_pem.expose(),
        },
    }))?)
}

fn write_private(path: &Path, text: &str) -> anyhow::Result<()> {
    use std::io::Write as _;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    file.write_all(text.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::ProfileMeta;
    use limen_core::secret::Secret;

    fn profile(expires_in: i64) -> Profile {
        Profile {
            meta: ProfileMeta {
                proxy: "limen.example:8443".into(),
                username: "dev".into(),
                roles: vec![],
                login_id: "l".into(),
                expires_at_unix: time::OffsetDateTime::now_utc().unix_timestamp() + expires_in,
            },
            key_pem: Secret::new("KEY".into()),
            cert_pem: "CERT".into(),
        }
    }

    #[test]
    fn kubeconfig_points_at_the_proxy_and_holds_no_secret() {
        let cfg = kubeconfig_json(
            "limen.example:8443",
            "eks-dev",
            Some("CA"),
            Path::new("/bin/limen"),
            Some(Path::new("/h")),
        );
        assert_eq!(
            cfg["clusters"][0]["cluster"]["server"],
            "https://limen.example:8443/k8s/eks-dev"
        );
        assert_eq!(cfg["users"][0]["user"]["exec"]["args"][3], "credentials");
        assert_eq!(cfg["users"][0]["user"]["exec"]["env"][0]["value"], "/h");
        let text = cfg.to_string();
        assert!(!text.contains("KEY") && !text.contains("token"));
    }

    #[test]
    fn exec_credential_carries_the_certificate_until_it_expires() {
        let out: serde_json::Value =
            serde_json::from_str(&exec_credential(&profile(600)).expect("valid")).expect("json");
        assert_eq!(out["kind"], "ExecCredential");
        assert_eq!(out["status"]["clientCertificateData"], "CERT");
        assert_eq!(out["status"]["clientKeyData"], "KEY");
        assert!(
            out["status"]["expirationTimestamp"]
                .as_str()
                .is_some_and(|t| t.ends_with('Z'))
        );
        let err = exec_credential(&profile(-5)).expect_err("expired");
        assert!(err.to_string().contains("limen login"));
    }
}
