//! Runs a Limen deployment in this process in front of a *real* cluster, so
//! the real `kubectl` and the real `limen` binary can be pointed at it.
//!
//! Not a normal test: it is ignored, and it runs until a `stop` file appears.
//! `demos/demo-phase8.sh` drives it. Needs a cluster (kind), the worker's
//! service account (`deploy/kubernetes/access/limen-kube-worker.yaml`), and these variables:
//!
//! - `KIND_API_SERVER`, `KIND_CA_FILE`, `KIND_TOKEN_FILE`: how to reach it
//! - `KIND_CLUSTER`: the cluster's name in policy (default `kind`)
//! - `KIND_OUT`: a directory for the profiles (`home-ops`, `home-viewer`, `home-admin`)
//!   and the `ready`, `stop`, and audit files

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use limen_e2e::{Deployment, eventually};
use limen_proto::v1::admin_client::AdminClient;
use limen_proto::v1::{ApplyPolicyRequest, CreateJoinTokenRequest, PolicySource};
use limen_testkit::users::{ADMIN, DEVELOPER, GUEST};

fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
}

/// Write what `limen` keeps for a login, so the real CLI can use it.
fn write_profile(home: &std::path::Path, proxy: &str, user: &str, cert: &str, key: &str, ca: &str) {
    let dir = home.join("profiles").join(proxy.replace(':', "_"));
    std::fs::create_dir_all(&dir).expect("profile dir");
    std::fs::write(dir.join("key.pem"), key).expect("key");
    std::fs::write(dir.join("cert.pem"), cert).expect("cert");
    std::fs::write(dir.join("proxy-ca.pem"), ca).expect("ca");
    let expires = time::OffsetDateTime::now_utc().unix_timestamp() + 4 * 3600 - 60;
    std::fs::write(
        dir.join("profile.json"),
        serde_json::json!({
            "proxy": proxy, "username": user, "roles": [], "login_id": "kind-bridge",
            "expires_at_unix": expires,
        })
        .to_string(),
    )
    .expect("profile");
    std::fs::write(home.join("current"), proxy).expect("current");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a real cluster; run by demos/demo-phase8.sh"]
#[allow(clippy::too_many_lines)]
async fn serve_a_cluster_until_stopped() {
    // KIND_CONSOLE=1 also serves the web console on the proxy's port. The mock
    // IdP signs the browser in as whoever `browser-user` names (see below).
    let console = std::env::var_os("KIND_CONSOLE").is_some();
    let started = if console {
        Deployment::start_with_console().await
    } else {
        Deployment::start().await
    };
    let Some(d) = started else {
        panic!("LIMEN_TEST_DATABASE_URL is required");
    };
    let out = PathBuf::from(var("KIND_OUT"));
    let cluster = std::env::var("KIND_CLUSTER").unwrap_or_else(|_| "kind".into());
    let policy = format!(
        r#"
kind: role
version: v1
metadata: {{ name: ops }}
spec:
  cert_ttl: 4h
  allow:
    - resources: {{ kind: [kubernetes] }}
      kube: {{ groups: ["limen:edit"] }}
---
kind: role
version: v1
metadata: {{ name: viewer }}
spec:
  cert_ttl: 4h
  allow:
    - resources: {{ kind: [kubernetes] }}
      kube: {{ groups: ["limen:view"] }}
---
kind: role
version: v1
metadata: {{ name: cluster-admin }}
spec:
  cert_ttl: 4h
  allow:
    - resources: {{ kind: [kubernetes] }}
      kube: {{ groups: ["limen:admin"] }}
---
kind: role_mapping
version: v1
metadata: {{ name: idp }}
spec:
  - {{ idp_group: ops, roles: [ops] }}
  - {{ idp_group: viewers, roles: [viewer] }}
  - {{ idp_group: admins, roles: [cluster-admin] }}
---
kind: resource
version: v1
metadata: {{ name: kind-dev, labels: {{ env: dev }} }}
spec:
  kubernetes: {{ cluster_name: {cluster} }}
  worker_selector: {{ pool: dev }}
"#
    );
    let admin_user = d.login(ADMIN, &["admins"]).await.expect("admin");
    let mut admin = AdminClient::new(d.proxy_channel(Some(admin_user)));
    let applied = admin
        .apply_policy(ApplyPolicyRequest {
            source: String::new(),
            require_tests: false,
            sources: vec![PolicySource {
                name: "policy.yaml".into(),
                content: policy,
            }],
            dry_run: false,
            source_ref: String::new(),
        })
        .await
        .expect("apply")
        .into_inner();
    let token = admin
        .create_join_token(CreateJoinTokenRequest {
            kind: "worker".into(),
            ttl_seconds: 600,
            labels: HashMap::from([("pool".to_owned(), "dev".to_owned())]),
            dns_names: vec![],
            name: String::new(),
        })
        .await
        .expect("token")
        .into_inner()
        .token;
    let worker = d
        .start_worker_with(
            &token,
            "worker",
            &[
                &format!("--kube-cluster={cluster}"),
                &format!("--kube-api-server={}", var("KIND_API_SERVER")),
                &format!("--kube-ca-file={}", var("KIND_CA_FILE")),
                &format!("--kube-token-file={}", var("KIND_TOKEN_FILE")),
            ],
        )
        .await;
    eventually(Duration::from_secs(20), "worker and policy", || async {
        d.proxy().tunnels.summaries().len() == 2
            && d.proxy().policy_version() == Some(applied.version)
            && worker.worker.policy_version() == Some(applied.version)
    })
    .await;

    let proxy = format!("localhost:{}", d.proxy_addr.port());
    let ca = std::fs::read_to_string(d.ca_file()).expect("ca");
    // Three users, signed in like `limen login` would. `touch relogin` in the
    // output directory signs all three in again (after a `limen logout`, say).
    let users = [
        ("home-ops", DEVELOPER, ["ops"]),
        ("home-viewer", GUEST, ["viewers"]),
        ("home-admin", ADMIN, ["admins"]),
    ];
    for (home, user, groups) in &users {
        let (cert, key) = d.login_pem(user, groups).await.expect("login");
        write_profile(&out.join(home), &proxy, user, &cert, &key, &ca);
    }
    std::fs::write(
        out.join("audit-path"),
        d.dir
            .path()
            .join("audit/control-plane.jsonl")
            .display()
            .to_string(),
    )
    .expect("audit path");
    std::fs::write(
        out.join("recordings-path"),
        d.dir.path().join("recordings").display().to_string(),
    )
    .expect("recordings path");
    std::fs::write(out.join("ready"), &proxy).expect("ready");
    eprintln!("kind bridge ready on {proxy}");

    // Who the console signs in next: write "email group" to `browser-user`.
    let browser_user = out.join("browser-user");
    if console {
        d.idp.set_browser_user(ADMIN, &["admins"]);
        std::fs::write(&browser_user, format!("{ADMIN} admins")).expect("browser user");
    }
    let stop = out.join("stop");
    let relogin = out.join("relogin");
    let mut last = String::new();
    while !stop.exists() {
        if relogin.exists() {
            for (home, user, groups) in &users {
                let (cert, key) = d.login_pem(user, groups).await.expect("login");
                write_profile(&out.join(home), &proxy, user, &cert, &key, &ca);
            }
            // Removed last: whoever touched it waits for this.
            let _ = std::fs::remove_file(&relogin);
            eprintln!("kind bridge: signed everyone in again");
        }
        if console
            && let Ok(text) = std::fs::read_to_string(&browser_user)
            && text != last
        {
            if let Some((email, group)) = text.trim().split_once(' ') {
                d.idp.set_browser_user(email, &[group]);
            }
            last = text;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    worker.stop().await;
}
