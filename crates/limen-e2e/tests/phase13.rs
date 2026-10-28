//! Phase 13 end to end: access that exists only when asked for and approved,
//! search that lands on the recording, resources that find themselves, and a
//! live session someone can watch. Real control plane, proxy, and worker, a
//! real SSH target, and the real console.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use limen_e2e::{Deployment, eventually, ssh_client};
use limen_proto::v1::access_client::AccessClient;
use limen_proto::v1::admin_client::AdminClient;
use limen_proto::v1::audit_search_client::AuditSearchClient;
use limen_proto::v1::{
    ApplyPolicyRequest, CreateJoinTokenRequest, DecideAccessRequestRequest,
    ListAccessGrantsRequest, ListAccessRequestsRequest, PolicySource, RequestAccessRequest,
    RevokeAccessGrantRequest, SearchRequest,
};
use limen_testkit::ssh_target::SshTarget;
use limen_testkit::users::{ADMIN, AUDITOR, DEVELOPER, ONCALL};
use sqlx::Connection;

fn policy(target_addr: &str, host_key: &str) -> Vec<PolicySource> {
    let yaml = format!(
        r#"
kind: resource
version: v1
metadata: {{ name: web-prod, labels: {{ env: prod }} }}
spec:
  ssh: {{ address: "{target_addr}", host_key: "{host_key}" }}
  worker_selector: {{ pool: dev }}
---
kind: role
version: v1
metadata: {{ name: dev }}
spec:
  allow:
    - resources: {{ kind: [ssh], labels: {{ env: [staging] }} }}
      ssh: {{ logins: [ubuntu] }}
---
kind: role
version: v1
metadata: {{ name: prod-ssh, description: requestable }}
spec:
  notify_observed: true
  allow:
    - resources: {{ kind: [ssh], labels: {{ env: [prod] }} }}
      ssh: {{ logins: [ubuntu] }}
  request:
    who: [developers]
    approvers: [leads]
    max_duration: 2h
    ticket_pattern: '^INC-[0-9]+'
---
kind: role
version: v1
metadata: {{ name: emergency }}
spec:
  break_glass: true
  allow:
    - resources: {{ kind: [ssh], labels: {{ env: [prod] }} }}
      ssh: {{ logins: [ubuntu] }}
  request: {{ who: [developers] }}
---
kind: role_mapping
version: v1
metadata: {{ name: idp }}
spec:
  - {{ idp_group: developers, roles: [dev] }}
  - {{ idp_group: auditors, roles: ['limen:auditor'] }}
---
kind: policy_test
version: v1
metadata: {{ name: prod-is-locked-down }}
spec:
  cases:
    - name: developers can only ask for prod
      who: {{ groups: [developers] }}
      resource: web-prod
      principal: {{ login: ubuntu }}
      expect: request
"#
    );
    vec![PolicySource {
        name: "policy.yaml".into(),
        content: yaml,
    }]
}

fn read_jsonl(d: &Deployment, file: &str) -> Vec<serde_json::Value> {
    std::fs::read_to_string(d.dir.path().join(file))
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).expect("json"))
        .collect()
}

const AUDIT: &str = "audit/control-plane.jsonl";

struct Rig {
    d: Deployment,
    /// Held so the SSH target outlives the test.
    _target: SshTarget,
    host_ca: String,
    ca_pem: String,
    proxy_addr: String,
    _worker: limen_e2e::RunningWorker,
    /// One login per person: logging in is rate limited, as it should be.
    logins: std::sync::Mutex<HashMap<String, (String, String)>>,
}

async fn rig(worker_args: &[&str]) -> Option<Rig> {
    Box::pin(rig_with(worker_args, false)).await
}

async fn rig_with(worker_args: &[&str], console: bool) -> Option<Rig> {
    let d = if console {
        Deployment::start_with_console().await?
    } else {
        Deployment::start().await?
    };
    let target = SshTarget::start(&d.public_ca("ssh-user-ca.pub")).await;
    let host_ca = d.public_ca("ssh-host-ca.pub");
    let ca_pem = std::fs::read_to_string(d.ca_file()).expect("ca");
    let proxy_addr = d.proxy_addr.to_string();
    let admin_user = d.login(ADMIN, &["admins"]).await.expect("admin");
    let mut admin = AdminClient::new(d.proxy_channel(Some(admin_user)));
    let applied = admin
        .apply_policy(ApplyPolicyRequest {
            require_tests: true,
            sources: policy(&target.addr.to_string(), &target.host_key),
            dry_run: false,
            source_ref: String::new(),
        })
        .await
        .expect("apply with its own tests passing")
        .into_inner();
    assert!(applied.applied);
    assert_eq!(applied.test_results.len(), 1);
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
    let worker = d.start_worker_with(&token, "worker", worker_args).await;
    eventually(Duration::from_secs(15), "tunnels", || async {
        d.proxy().tunnels.summaries().len() == 2
    })
    .await;
    eventually(Duration::from_secs(15), "policy everywhere", || async {
        d.proxy().policy_version() == Some(applied.version)
            && worker.worker.policy_version() == Some(applied.version)
    })
    .await;
    Some(Rig {
        d,
        _target: target,
        host_ca,
        ca_pem,
        proxy_addr,
        _worker: worker,
        logins: std::sync::Mutex::default(),
    })
}

impl Rig {
    async fn identity(&self, user: &str, groups: &[&str]) -> limen_tunnel::tls::Identity {
        let known = self.logins.lock().expect("lock").get(user).cloned();
        let (cert, key) = match known {
            Some(pair) => pair,
            None => {
                let pair = self.d.login_pem(user, groups).await.expect("login");
                self.logins
                    .lock()
                    .expect("lock")
                    .insert(user.to_owned(), pair.clone());
                pair
            }
        };
        limen_tunnel::tls::Identity::from_pem(&cert, &key).expect("identity")
    }

    async fn ssh(
        &self,
        user: &str,
        groups: &[&str],
    ) -> Result<russh::client::Handle<ssh_client::HostCheck>, String> {
        let id = self.identity(user, groups).await;
        ssh_client::connect(
            &self.proxy_addr,
            &self.ca_pem,
            id,
            &self.host_ca,
            "web-prod",
            "ubuntu",
        )
        .await
    }

    /// Keep trying until the grant has reached the proxy and the worker
    /// (their snapshots refresh every second here, ten in production).
    async fn ssh_when_allowed(
        &self,
        user: &str,
        groups: &[&str],
    ) -> russh::client::Handle<ssh_client::HostCheck> {
        for _ in 0..80 {
            match self.ssh(user, groups).await {
                Ok(c) => return c,
                Err(_) => tokio::time::sleep(Duration::from_millis(250)).await,
            }
        }
        panic!("the grant never reached the proxy and the worker");
    }

    async fn access(
        &self,
        user: &str,
        groups: &[&str],
    ) -> AccessClient<limen_tunnel::connect::TracedChannel> {
        let id = self.identity(user, groups).await;
        AccessClient::new(self.d.proxy_channel(Some(id)))
    }
}

#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread")]
async fn asked_for_approved_used_found_and_ended() {
    let Some(r) = Box::pin(rig(&[])).await else {
        return;
    };

    // Without a grant, prod is closed to a developer.
    let err = r
        .ssh(DEVELOPER, &["developers"])
        .await
        .err()
        .expect("no access yet");
    assert!(err.contains("denied"), "{err}");

    // They ask, for a stated reason; a bad reason is refused.
    let mut dev = r.access(DEVELOPER, &["developers"]).await;
    let bad = dev
        .request_access(RequestAccessRequest {
            resource: "web-prod".into(),
            role: String::new(),
            duration_seconds: 1800,
            reason: "please".into(),
            break_glass: false,
        })
        .await
        .expect_err("no ticket");
    assert!(bad.message().contains("ticket"), "{}", bad.message());
    let asked = dev
        .request_access(RequestAccessRequest {
            resource: "web-prod".into(),
            role: String::new(),
            duration_seconds: 1800,
            reason: "INC-123 disk full on web-prod".into(),
            break_glass: false,
        })
        .await
        .expect("ask")
        .into_inner();
    assert_eq!(asked.status, "pending");
    // Still nothing: asking is not access.
    assert!(r.ssh(DEVELOPER, &["developers"]).await.is_err());

    // An approver decides, signed in. They can't decide their own.
    let own = dev
        .decide_access_request(DecideAccessRequestRequest {
            id: asked.id.clone(),
            approve: true,
            comment: String::new(),
        })
        .await
        .expect_err("not your own");
    assert_eq!(own.code(), tonic::Code::PermissionDenied);
    let mut lead = r.access(ONCALL, &["leads"]).await;
    let queue = lead
        .list_access_requests(ListAccessRequestsRequest {
            scope: "approvable".into(),
            status: String::new(),
            limit: 0,
        })
        .await
        .expect("queue")
        .into_inner()
        .requests;
    assert_eq!(queue.len(), 1);
    assert_eq!(queue[0].reason, "INC-123 disk full on web-prod");
    lead.decide_access_request(DecideAccessRequestRequest {
        id: asked.id.clone(),
        approve: true,
        comment: "go ahead".into(),
    })
    .await
    .expect("approve");

    // Now the session works, and tells the user it may be observed.
    let conn = r.ssh_when_allowed(DEVELOPER, &["developers"]).await;
    let (out, status) = ssh_client::exec(&conn, "systemctl status nginx")
        .await
        .expect("exec");
    assert_eq!(status, Some(0));
    assert!(out.contains("systemctl status nginx"), "{out}");

    // The session is recorded with *why it was allowed*. The command's own
    // event reaches the trail asynchronously, so wait for it as well.
    eventually(
        Duration::from_secs(15),
        "session.start with request_ids and ssh.exec",
        || async {
            let events = read_jsonl(&r.d, AUDIT);
            events.iter().any(|e| {
                e["kind"] == "session.start" && e["data"]["request_ids"][0] == asked.id.as_str()
            }) && events.iter().any(|e| e["kind"] == "ssh.exec")
        },
    )
    .await;
    let events = read_jsonl(&r.d, AUDIT);
    let kinds: Vec<&str> = events.iter().filter_map(|e| e["kind"].as_str()).collect();
    for want in [
        "access.request",
        "access.approve",
        "access.grant",
        "ssh.exec",
    ] {
        assert!(kinds.contains(&want), "{want} in {kinds:?}");
    }

    // An auditor finds the command by its text and lands on the session.
    let aud = r.identity(AUDITOR, &["auditors"]).await;
    let mut search = AuditSearchClient::new(r.d.proxy_channel(Some(aud)));
    let mut found = None;
    for _ in 0..60 {
        let resp = search
            .search(SearchRequest {
                query: "systemctl status nginx user:developer@example.com".into(),
                limit: 0,
            })
            .await
            .expect("search")
            .into_inner();
        if let Some(h) = resp.hits.into_iter().find(|h| h.kind == "ssh.exec") {
            found = Some(h);
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let hit = found.expect("the command is searchable");
    assert_eq!(hit.matched.to_lowercase(), "systemctl status nginx");
    assert_eq!(hit.resource, "web-prod");
    assert!(!hit.session_id.is_empty(), "a hit names its session");
    // A developer can't search.
    let dev_id = r.identity(DEVELOPER, &["developers"]).await;
    let err = AuditSearchClient::new(r.d.proxy_channel(Some(dev_id)))
        .search(SearchRequest {
            query: "nginx".into(),
            limit: 0,
        })
        .await
        .expect_err("not an auditor");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    // Revoking the grant ends the open session, and closes the door.
    let admin_id = r.identity(ADMIN, &["admins"]).await;
    let mut admin = AccessClient::new(r.d.proxy_channel(Some(admin_id)));
    let grants = admin
        .list_access_grants(ListAccessGrantsRequest {
            include_ended: false,
        })
        .await
        .expect("grants")
        .into_inner()
        .grants;
    assert_eq!(grants.len(), 1);
    let revoked = admin
        .revoke_access_grant(RevokeAccessGrantRequest {
            request_id: asked.id.clone(),
            reason: "test".into(),
        })
        .await
        .expect("revoke")
        .into_inner();
    assert!(revoked.revoked);
    // The open connection ends on its own (the proxy sees the grant gone, or the kill).
    eventually(Duration::from_secs(30), "the session ends", || async {
        conn.is_closed() || ssh_client::exec(&conn, "id").await.is_err()
    })
    .await;
    eventually(
        Duration::from_secs(20),
        "new sessions are refused",
        || async { r.ssh(DEVELOPER, &["developers"]).await.is_err() },
    )
    .await;
    let ended = read_jsonl(&r.d, AUDIT).into_iter().any(|e| {
        e["kind"] == "session.end"
            && (e["data"]["reason"] == "access grant ended"
                || e["data"]["reason"] == "session killed")
    });
    assert!(ended || conn.is_closed());
}

#[tokio::test(flavor = "multi_thread")]
async fn break_glass_is_granted_at_once_and_loudly() {
    let Some(r) = Box::pin(rig(&[])).await else {
        return;
    };
    let mut dev = r.access(DEVELOPER, &["developers"]).await;
    let info = dev
        .request_access(RequestAccessRequest {
            resource: "web-prod".into(),
            role: String::new(),
            duration_seconds: 600,
            reason: "prod is down".into(),
            break_glass: true,
        })
        .await
        .expect("break-glass")
        .into_inner();
    assert_eq!(info.status, "approved");
    let conn = r.ssh_when_allowed(DEVELOPER, &["developers"]).await;
    let (out, _) = ssh_client::exec(&conn, "id").await.expect("exec");
    assert!(out.contains("command=id"), "{out}");
    eventually(Duration::from_secs(10), "break-glass events", || async {
        let kinds: Vec<String> = read_jsonl(&r.d, AUDIT)
            .iter()
            .filter_map(|e| e["kind"].as_str().map(str::to_owned))
            .collect();
        kinds.iter().any(|k| k == "access.break_glass") && kinds.iter().any(|k| k == "access.grant")
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn watching_a_live_session_streams_what_the_user_sees() {
    let Some(r) = Box::pin(rig(&[])).await else {
        return;
    };
    let mut dev = r.access(DEVELOPER, &["developers"]).await;
    dev.request_access(RequestAccessRequest {
        resource: "web-prod".into(),
        role: String::new(),
        duration_seconds: 600,
        reason: "prod is down".into(),
        break_glass: true,
    })
    .await
    .expect("break-glass");
    let conn = r.ssh_when_allowed(DEVELOPER, &["developers"]).await;
    let mut db = sqlx::PgConnection::connect(&r.d.db_url).await.expect("db");
    // Wait for the session to appear in the console's table, then stand in
    // for the console: a watcher row, as `live::begin` writes it.
    let mut session: Option<uuid::Uuid> = None;
    for _ in 0..80 {
        session = sqlx::query_scalar("SELECT session_id FROM sessions WHERE resource = 'web-prod' AND ended_at IS NULL AND worker_id IS NOT NULL LIMIT 1")
            .fetch_optional(&mut db)
            .await
            .expect("query");
        if session.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let session = session.expect("the session is listed");
    sqlx::query(
        "INSERT INTO session_watches (id, session_id, observer) VALUES (gen_random_uuid(), $1, $2)",
    )
    .bind(session)
    .bind(ADMIN)
    .execute(&mut db)
    .await
    .expect("watch");
    // The worker notices within a couple of seconds, then ships output. Keep
    // the watcher alive like the stream would.
    let mut seen = String::new();
    for i in 0..60 {
        let _ = ssh_client::exec(&conn, &format!("echo watched-{i}")).await;
        sqlx::query("UPDATE session_watches SET last_seen_at = now() WHERE session_id = $1")
            .bind(session)
            .execute(&mut db)
            .await
            .expect("heartbeat");
        let texts: Vec<String> =
            sqlx::query_scalar("SELECT text FROM watch_chunks WHERE session_id = $1 ORDER BY seq")
                .bind(session)
                .fetch_all(&mut db)
                .await
                .expect("chunks");
        seen = texts.join("");
        if seen.contains("echo watched-") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        seen.contains("command=echo watched-"),
        "the watcher saw: {seen:?}"
    );
    // Output only: what the client typed as commands is not input to the terminal here,
    // and nothing is published once nobody watches.
    sqlx::query("UPDATE session_watches SET stopped_at = now() WHERE session_id = $1")
        .bind(session)
        .execute(&mut db)
        .await
        .expect("stop");
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM watch_chunks WHERE session_id = $1")
        .bind(session)
        .fetch_one(&mut db)
        .await
        .expect("count");
    for i in 0..4 {
        let _ = ssh_client::exec(&conn, &format!("echo after-{i}")).await;
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM watch_chunks WHERE session_id = $1")
        .bind(session)
        .fetch_one(&mut db)
        .await
        .expect("count");
    assert_eq!(
        before, after,
        "nothing is published when nobody is watching"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn a_discovered_instance_is_reachable_only_once_an_admin_accepts_it() {
    let Some(base) = limen_testkit::database_url() else {
        return;
    };
    let _ = base;
    let (aws_url, world) = limen_testkit::fake_aws::start("111122223333").await;
    let Some(d) = Deployment::start().await else {
        return;
    };
    let target = SshTarget::start(&d.public_ca("ssh-user-ca.pub")).await;
    let host_ca = d.public_ca("ssh-host-ca.pub");
    let ca_pem = std::fs::read_to_string(d.ca_file()).expect("ca");
    let proxy_addr = d.proxy_addr.to_string();
    world.lock().expect("lock").instances = vec![limen_testkit::fake_aws::Instance {
        id: "i-0abc".into(),
        ip: "127.0.0.1".into(),
        state: "running".into(),
        tags: BTreeMap::from([
            ("Name".to_owned(), "found-host".to_owned()),
            ("limen/managed".to_owned(), "true".to_owned()),
            ("env".to_owned(), "prod".to_owned()),
        ]),
        host_key: Some(target.host_key.clone()),
    }];
    let yaml = format!(
        r#"
kind: discovery
version: v1
metadata: {{ name: aws }}
spec:
  provider: aws
  accounts: [{{ role_arn: "arn:aws:iam::111122223333:role/limen-discovery" }}]
  regions: [eu-west-1]
  worker_selector: {{ pool: dev }}
  match:
    - type: ec2
      tags: {{ limen/managed: ["true"] }}
      labels_from_tags: [env]
      ssh: {{ port: {} }}
---
kind: role
version: v1
metadata: {{ name: ops }}
spec:
  allow:
    - resources: {{ kind: [ssh], labels: {{ env: [prod] }} }}
      ssh: {{ logins: [ubuntu] }}
---
kind: role_mapping
version: v1
metadata: {{ name: idp }}
spec:
  - {{ idp_group: ops, roles: [ops] }}
"#,
        target.addr.port()
    );
    let admin_id = d.login(ADMIN, &["admins"]).await.expect("admin");
    let mut admin = AdminClient::new(d.proxy_channel(Some(admin_id)));
    let applied = admin
        .apply_policy(ApplyPolicyRequest {
            require_tests: false,
            sources: vec![PolicySource {
                name: "p.yaml".into(),
                content: yaml,
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
    let endpoint = format!("--discovery-endpoint-url={aws_url}");
    let worker = d
        .start_worker_with(&token, "worker", &["--discovery", &endpoint])
        .await;
    eventually(Duration::from_secs(15), "worker is up", || async {
        d.proxy().tunnels.summaries().len() == 2
            && worker.worker.policy_version() == Some(applied.version)
    })
    .await;

    // The worker looks, and the control plane holds what it finds.
    let mut found = None;
    for _ in 0..80 {
        let items = admin
            .list_discovered(limen_proto::v1::ListDiscoveredRequest {
                state: String::new(),
            })
            .await
            .expect("list")
            .into_inner()
            .items;
        if let Some(i) = items.into_iter().next() {
            found = Some(i);
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let item = found.expect("discovery found the instance");
    assert_eq!(item.state, "pending");
    assert_eq!(item.name, "found-host");
    assert_eq!(item.labels["env"], "prod");
    assert!(item.blockers.is_empty(), "{:?}", item.blockers);

    // Pending: nobody can reach it, whatever their role says.
    let ops = || async { d.login(DEVELOPER, &["ops"]).await.expect("ops user") };
    let err = ssh_client::connect(
        &proxy_addr,
        &ca_pem,
        ops().await,
        &host_ca,
        "found-host",
        "ubuntu",
    )
    .await
    .err()
    .expect("not accepted yet");
    assert!(err.contains("denied") || err.contains("unknown"), "{err}");

    // An admin accepts it.
    admin
        .review_discovered(limen_proto::v1::ReviewDiscoveredRequest {
            key: item.key.clone(),
            accept: true,
            note: "checked".into(),
        })
        .await
        .expect("accept");
    let mut conn = None;
    for _ in 0..80 {
        match ssh_client::connect(
            &proxy_addr,
            &ca_pem,
            ops().await,
            &host_ca,
            "found-host",
            "ubuntu",
        )
        .await
        {
            Ok(c) => {
                conn = Some(c);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    }
    let conn = conn.expect("reachable once accepted");
    let (out, status) = ssh_client::exec(&conn, "whoami").await.expect("exec");
    assert_eq!(status, Some(0));
    assert!(out.contains("login=ubuntu"), "{out}");
    let kinds: Vec<String> = read_jsonl(&d, AUDIT)
        .iter()
        .filter_map(|e| e["kind"].as_str().map(str::to_owned))
        .collect();
    assert!(
        kinds.iter().any(|k| k == "resource.discovered"),
        "{kinds:?}"
    );
    assert!(kinds.iter().any(|k| k == "resource.review"));
}

// ---------------------------------------------------------------------------
// The console, driven the way a person would.

/// Just enough browser: cookies, manual redirects, form posts.
struct Browser {
    http: reqwest::Client,
    cookies: BTreeMap<String, String>,
    base: String,
}

struct Page {
    status: u16,
    headers: reqwest::header::HeaderMap,
    body: String,
    url: String,
}

impl Browser {
    fn new(d: &Deployment, http1_only: bool) -> Self {
        let ca = std::fs::read(d.ca_file()).expect("ca");
        let mut builder = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(&ca).expect("cert"))
            .resolve("localhost", d.proxy_addr)
            .redirect(reqwest::redirect::Policy::none());
        if http1_only {
            builder = builder.http1_only();
        }
        Self {
            http: builder.build().expect("client"),
            cookies: BTreeMap::new(),
            base: format!("https://localhost:{}", d.proxy_addr.port()),
        }
    }

    fn cookie_header(&self) -> String {
        self.cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn absorb(&mut self, headers: &reqwest::header::HeaderMap) {
        for v in headers.get_all("set-cookie") {
            let v = v.to_str().expect("cookie");
            let (pair, attrs) = v.split_once(';').unwrap_or((v, ""));
            let (name, value) = pair.split_once('=').expect("name=value");
            if value.is_empty() || attrs.contains("Max-Age=0") {
                self.cookies.remove(name);
            } else {
                self.cookies.insert(name.to_owned(), value.to_owned());
            }
        }
    }

    /// Send one request without following redirects.
    async fn send(&mut self, req: reqwest::RequestBuilder) -> Page {
        let resp = req
            .header("cookie", self.cookie_header())
            .send()
            .await
            .expect("request");
        self.absorb(resp.headers());
        let url = resp.url().to_string();
        Page {
            status: resp.status().as_u16(),
            headers: resp.headers().clone(),
            body: resp.text().await.expect("body"),
            url,
        }
    }

    async fn get_once(&mut self, url: &str) -> Page {
        let req = self.http.get(url);
        self.send(req).await
    }

    /// GET, following redirects the way a browser would.
    async fn get(&mut self, path_or_url: &str) -> Page {
        let mut url = if path_or_url.starts_with("http") {
            path_or_url.to_owned()
        } else {
            format!("{}{path_or_url}", self.base)
        };
        for _ in 0..10 {
            let page = self.get_once(&url).await;
            if (300..400).contains(&page.status) {
                let location = page.headers["location"].to_str().expect("location");
                url = if location.starts_with("http") {
                    location.to_owned()
                } else {
                    format!("{}{location}", self.base)
                };
                continue;
            }
            return page;
        }
        panic!("too many redirects");
    }

    /// POST a form with the console's own Origin, without following the redirect.
    async fn post(&mut self, path: &str, fields: &[(&str, &str)]) -> Page {
        let req = self
            .http
            .post(format!("{}{path}", self.base))
            .header("origin", self.base.clone())
            .form(fields);
        self.send(req).await
    }

    async fn post_with_origin(
        &mut self,
        path: &str,
        origin: &str,
        fields: &[(&str, &str)],
    ) -> Page {
        let req = self
            .http
            .post(format!("{}{path}", self.base))
            .header("origin", origin)
            .form(fields);
        self.send(req).await
    }

    /// Sign in through the IdP as `email`.
    async fn login(&mut self, d: &Deployment, email: &str, groups: &[&str]) -> Page {
        d.idp.set_browser_user(email, groups);
        self.get("/console/login").await
    }

    /// The CSRF token embedded in the page's forms.
    fn csrf(page: &Page) -> String {
        let marker = "name=\"csrf\" value=\"";
        let start = page.body.find(marker).expect("a csrf field") + marker.len();
        page.body[start..]
            .split('"')
            .next()
            .expect("value")
            .to_owned()
    }
}

fn csrf_of(page: &Page) -> String {
    Browser::csrf(page)
}

async fn signed_in(r: &Rig, email: &str, groups: &[&str]) -> Browser {
    let mut b = Browser::new(&r.d, true);
    let page = b.login(&r.d, email, groups).await;
    assert_eq!(page.status, 200, "{email}: {}", page.body);
    assert!(page.url.ends_with("/console/"), "{}", page.url);
    b
}

#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread")]
async fn the_console_pages_for_the_workflows() {
    let Some(r) = Box::pin(rig_with(&[], true)).await else {
        return;
    };
    let mut dev = signed_in(&r, DEVELOPER, &["developers"]).await;
    let mut lead = signed_in(&r, ONCALL, &["leads"]).await;
    let mut admin = signed_in(&r, ADMIN, &["admins"]).await;
    let mut auditor = signed_in(&r, AUDITOR, &["auditors"]).await;

    // ---- the developer asks, in the console -------------------------------
    let page = dev.get("/console/access").await;
    assert_eq!(page.status, 200);
    assert!(
        page.body.contains("Ask for access") && page.body.contains("web-prod"),
        "{}",
        page.body
    );
    let resource = dev.get("/console/resources/web-prod").await;
    assert_eq!(
        resource.status, 200,
        "a requestable resource has a page for the person who can ask"
    );
    assert!(resource.body.contains("Request access"));
    assert!(
        !resource.body.contains("Who can reach it"),
        "that is for admins and auditors"
    );
    let csrf = csrf_of(&page);
    let posted = dev
        .post(
            "/console/access/request",
            &[
                ("csrf", &csrf),
                ("resource", "web-prod"),
                ("duration", "30m"),
                ("reason", "INC-77 disk full"),
                ("role", ""),
            ],
        )
        .await;
    assert_eq!(posted.status, 303, "{}", posted.body);
    let location = posted.headers["location"]
        .to_str()
        .expect("location")
        .to_owned();
    assert!(
        location.starts_with("/console/access/") && location.contains("done=requested"),
        "{location}"
    );
    let id = location
        .trim_start_matches("/console/access/")
        .split('?')
        .next()
        .expect("id")
        .to_owned();
    let detail = dev.get(&location).await;
    assert!(detail.body.contains("pending") && detail.body.contains("INC-77 disk full"));
    assert!(
        !detail.body.contains("Your decision"),
        "you never decide your own"
    );
    // A request that breaks the role's rules says why, on the page.
    let bad = dev
        .post(
            "/console/access/request",
            &[
                ("csrf", &csrf),
                ("resource", "web-prod"),
                ("duration", "30m"),
                ("reason", "no ticket"),
                ("role", ""),
            ],
        )
        .await;
    let back = dev
        .get(bad.headers["location"].to_str().expect("location"))
        .await;
    assert!(back.body.contains("ticket"), "{}", back.body);
    // Forged posts are refused.
    let forged = dev
        .post_with_origin(
            "/console/access/request",
            "https://evil.example",
            &[
                ("csrf", &csrf),
                ("resource", "web-prod"),
                ("reason", "INC-1 x"),
            ],
        )
        .await;
    assert_eq!(forged.status, 403);

    // ---- the approver sees it and decides ---------------------------------
    let queue = lead.get("/console/access?tab=approvals").await;
    assert!(
        queue.body.contains("INC-77 disk full") && queue.body.contains("Decide"),
        "{}",
        queue.body
    );
    let page = lead.get(&format!("/console/access/{id}")).await;
    assert!(page.body.contains("Your decision") && page.body.contains("Past 30 days"));
    let done = lead
        .post(
            &format!("/console/access/{id}/decide"),
            &[
                ("csrf", &csrf_of(&page)),
                ("decision", "approve"),
                ("comment", "ok"),
            ],
        )
        .await;
    assert_eq!(done.status, 303);
    let page = dev.get(&format!("/console/access/{id}")).await;
    assert!(page.body.contains("approved"), "{}", page.body);

    // ---- and the grant is real: a session, with its reason on the page -----
    let conn = r.ssh_when_allowed(DEVELOPER, &["developers"]).await;
    let (out, _) = ssh_client::exec(&conn, "echo for-the-watcher")
        .await
        .expect("exec");
    assert!(out.contains("for-the-watcher"));
    let mut session: Option<String> = None;
    for _ in 0..60 {
        let sessions = admin.get("/console/sessions?filter=active").await;
        if let Some(i) = sessions.body.find("/console/sessions/") {
            let rest = &sessions.body[i + "/console/sessions/".len()..];
            let candidate: String = rest
                .chars()
                .take_while(|c| c.is_ascii_hexdigit() || *c == '-')
                .collect();
            if candidate.len() == 36 {
                session = Some(candidate);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let session = session.expect("a live session is listed");
    let page = admin.get(&format!("/console/sessions/{session}")).await;
    assert!(
        page.body.contains(&id),
        "the session links to the request that allowed it"
    );
    assert!(
        page.body.contains("Watch it"),
        "an admin can watch a live SSH session"
    );
    assert!(
        !dev.get(&format!("/console/sessions/{session}/watch"))
            .await
            .body
            .contains("data-src"),
        "the user can't watch"
    );

    // ---- watching: the stream carries what is on screen -------------------
    let watch = admin
        .get(&format!("/console/sessions/{session}/watch"))
        .await;
    assert_eq!(watch.status, 200);
    assert!(
        watch
            .body
            .contains(&format!("/console/sessions/{session}/watch/stream"))
    );
    let mut stream = admin
        .http
        .get(format!(
            "{}/console/sessions/{session}/watch/stream",
            admin.base
        ))
        .header("cookie", admin.cookie_header())
        .send()
        .await
        .expect("stream");
    assert_eq!(stream.status().as_u16(), 200);
    assert_eq!(stream.headers()["content-type"], "text/event-stream");
    let mut body = String::new();
    let started = std::time::Instant::now();
    while !body.contains("for-the-watcher") && started.elapsed() < Duration::from_secs(30) {
        let _ = ssh_client::exec(&conn, "echo for-the-watcher").await;
        if let Ok(Some(chunk)) = tokio::time::timeout(Duration::from_secs(2), stream.chunk())
            .await
            .map(|c| c.ok().flatten())
        {
            body.push_str(&String::from_utf8_lossy(&chunk));
        }
    }
    assert!(
        body.contains("\"width\""),
        "the player is told the screen size first: {body}"
    );
    assert!(body.contains("for-the-watcher"), "{body}");
    drop(stream);
    eventually(
        Duration::from_secs(20),
        "the watch is audited, start and stop",
        || async {
            let kinds: Vec<String> = read_jsonl(&r.d, AUDIT)
                .iter()
                .filter_map(|e| e["kind"].as_str().map(str::to_owned))
                .collect();
            kinds.iter().any(|k| k == "session.watch.start")
                && kinds.iter().any(|k| k == "session.watch.stop")
        },
    )
    .await;
    let after = dev.get(&format!("/console/sessions/{session}")).await;
    assert!(
        after.body.contains("Watched live"),
        "the user is told who watched"
    );

    // ---- admins and auditors: who can reach it, search, grants ------------
    let page = admin.get("/console/resources/web-prod").await;
    assert!(page.body.contains("Who can reach it") && page.body.contains("by request"));
    assert!(page.body.contains("prod-ssh"));
    let grants = admin.get("/console/access?tab=grants").await;
    assert!(grants.body.contains("INC-77 disk full") && grants.body.contains("Revoke"));
    let grants = auditor.get("/console/access?tab=grants").await;
    assert!(
        grants.body.contains("INC-77 disk full") && !grants.body.contains("Revoke"),
        "auditors read, they don't revoke"
    );

    let mut hit = None;
    for _ in 0..60 {
        let page = auditor.get("/console/audit?find=for-the-watcher").await;
        assert_eq!(page.status, 200);
        if page.body.contains("<mark>for-the-watcher</mark>") {
            hit = Some(page);
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let hit = hit.expect("the command is found in the console");
    assert!(
        hit.body.contains("/console/sessions/"),
        "a hit links to its session"
    );
    assert_eq!(
        dev.get("/console/audit").await.status,
        403,
        "the audit trail is not for developers"
    );
    assert_eq!(dev.get("/console/audit?q=anything").await.status, 403);
    // The search was audited.
    assert!(
        read_jsonl(&r.d, AUDIT)
            .iter()
            .any(|e| e["kind"] == "audit.search" && e["data"]["query"] == "for-the-watcher")
    );

    // ---- policy: simulator and the effective-access diff -------------------
    let page = admin.get("/console/policy").await;
    assert!(page.body.contains("Access simulator"));
    let sim = admin
        .post(
            "/console/policy/simulate",
            &[
                ("csrf", &csrf_of(&page)),
                ("groups", "developers"),
                ("bot", ""),
            ],
        )
        .await;
    assert_eq!(sim.status, 200, "{}", sim.body);
    assert!(
        sim.body.contains("could ask for") && sim.body.contains("web-prod"),
        "{}",
        sim.body
    );
    let dry = admin
        .post("/console/policy/dry-run", &[("csrf", &csrf_of(&page)), ("yaml", "kind: role\nversion: v1\nmetadata: { name: everything }\nspec:\n  allow:\n    - resources: { kind: [ssh], labels: { \"*\": [\"*\"] } }\n      ssh: { logins: [ubuntu] }\n---\nkind: role_mapping\nversion: v1\nmetadata: { name: m }\nspec:\n  - { idp_group: developers, roles: [everything] }\n")])
        .await;
    assert_eq!(dry.status, 200, "{}", dry.body);
    assert!(
        dry.body.contains("Who gains or loses access") || dry.body.contains("No changes"),
        "{}",
        dry.body
    );

    // ---- reviews and evidence ---------------------------------------------
    let page = admin.get("/console/reviews").await;
    assert!(page.body.contains("Start a review"));
    let start = admin
        .post(
            "/console/reviews/start",
            &[
                ("csrf", &csrf_of(&page)),
                ("name", "Smoke review"),
                ("due_days", "14"),
                ("override_days", "30"),
            ],
        )
        .await;
    assert_eq!(start.status, 303, "{}", start.body);
    let review = admin
        .get(start.headers["location"].to_str().expect("location"))
        .await;
    assert!(
        review.body.contains("Smoke review") && review.body.contains("prod-ssh")
            || review.body.contains("dev"),
        "{}",
        review.body
    );
    assert_eq!(
        dev.get("/console/reviews").await.status,
        200,
        "everyone has a page of their own items"
    );
    let today = time::OffsetDateTime::now_utc().date();
    let pack = auditor
        .get(&format!(
            "/console/reviews/evidence?from={}&to={}",
            today - time::Duration::days(1),
            today + time::Duration::days(1)
        ))
        .await;
    assert_eq!(pack.status, 200);
    assert!(
        pack.headers["content-disposition"]
            .to_str()
            .expect("header")
            .contains("limen-evidence.json")
    );
    assert!(pack.body.contains("limen-evidence/1"));
    assert_eq!(
        dev.get(&format!(
            "/console/reviews/evidence?from={today}&to={today}"
        ))
        .await
        .status,
        403
    );

    // ---- discovered resources are an admin's tab --------------------------
    assert_eq!(admin.get("/console/discovered").await.status, 200);
    assert_eq!(dev.get("/console/discovered").await.status, 403);
    let resources = admin.get("/console/resources").await;
    assert!(resources.body.contains("/console/discovered"));
    // Pages the grant made reachable; revoke from the console ends the access.
    let grants = admin.get("/console/access?tab=grants").await;
    let revoke = admin
        .post(
            &format!("/console/access/grants/{id}/revoke"),
            &[("csrf", &csrf_of(&grants)), ("reason", "smoke test")],
        )
        .await;
    assert_eq!(revoke.status, 303, "{}", revoke.body);
    eventually(Duration::from_secs(30), "the grant is gone", || async {
        r.ssh(DEVELOPER, &["developers"]).await.is_err()
    })
    .await;
}
