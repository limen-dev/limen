//! The web console end to end (ADR-0017): a browser-like client logs in
//! through the mock IdP's authorization code flow, talks to the proxy over
//! TLS, and drives the pages the way a person would.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use limen_e2e::{Deployment, eventually, ssh_client};
use limen_proto::v1::admin_client::AdminClient;
use limen_proto::v1::{ApplyPolicyRequest, CreateJoinTokenRequest, PolicySource};
use limen_testkit::idp::WorkloadToken;
use limen_testkit::ssh_target::SshTarget;
use limen_testkit::users::{ADMIN, ADMIN_ENC, DEVELOPER, DEVELOPER_ENC, GUEST};

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

/// Poll a check that needs `&mut` (a browser), up to `secs` seconds.
async fn wait_until(what: &str, secs: u64, mut check: impl AsyncFnMut() -> bool) {
    for _ in 0..secs * 4 {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("timed out waiting for {what}");
}

fn policy(target_addr: &str, host_key: &str, issuer: &str) -> Vec<PolicySource> {
    let yaml = format!(
        r#"
kind: role
version: v1
metadata: {{ name: ops }}
spec:
  allow:
    - resources: {{ kind: [ssh], labels: {{ env: [test] }} }}
      ssh: {{ logins: [ubuntu] }}
---
kind: bot
version: v1
metadata: {{ name: deploy-e2e, description: "the e2e deploy job" }}
spec:
  join:
    method: github_actions
    issuer: {issuer}
    match: {{ repository: acme/infra, ref: refs/heads/main }}
  roles: [ops]
---
kind: role_mapping
version: v1
metadata: {{ name: idp }}
spec:
  - {{ idp_group: ops, roles: [ops] }}
---
kind: resource
version: v1
metadata: {{ name: secret-db, labels: {{ env: prod }} }}
spec:
  postgres: {{ endpoint: "db.internal.example:5432", iam_auth: false }}
  worker_selector: {{ pool: prod }}
---
kind: resource
version: v1
metadata: {{ name: web-1, labels: {{ env: test }} }}
spec:
  ssh: {{ address: "{target_addr}", host_key: "{host_key}" }}
  worker_selector: {{ pool: dev }}
"#
    );
    vec![PolicySource {
        name: "policy.yaml".into(),
        content: yaml,
    }]
}

fn read_jsonl(d: &Deployment) -> Vec<serde_json::Value> {
    std::fs::read_to_string(d.dir.path().join("audit/control-plane.jsonl"))
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).expect("json"))
        .collect()
}

#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread")]
async fn console_end_to_end() {
    let Some(d) = Deployment::start_with_console().await else {
        return;
    };
    let target = SshTarget::start(&d.public_ca("ssh-user-ca.pub")).await;
    let host_ca = d.public_ca("ssh-host-ca.pub");
    let ca_pem = std::fs::read_to_string(d.ca_file()).expect("ca");
    let proxy_addr = d.proxy_addr.to_string();

    // Policy and a worker, through the API as in production.
    let admin_cli = d.login(ADMIN, &["admins"]).await.expect("admin");
    let mut admin = AdminClient::new(d.proxy_channel(Some(admin_cli)));
    let applied = admin
        .apply_policy(ApplyPolicyRequest {
            source: String::new(),
            require_tests: false,
            sources: policy(&target.addr.to_string(), &target.host_key, &d.idp.issuer),
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
            // An exact name: the worker gets it without asking.
            name: "console-worker-1".into(),
        })
        .await
        .expect("token")
        .into_inner()
        .token;
    let worker = d.start_worker(&token, "worker").await;
    assert_eq!(worker.worker.name().as_deref(), Some("console-worker-1"));
    eventually(Duration::from_secs(15), "worker tunnel", || async {
        d.proxy().tunnels.summaries().len() == 2
    })
    .await;
    eventually(Duration::from_secs(15), "policy everywhere", || async {
        d.proxy().policy_version() == Some(applied.version)
            && worker.worker.policy_version() == Some(applied.version)
    })
    .await;

    // ---- not signed in: everything goes to the login page ------------------
    let mut anon = Browser::new(&d, true);
    let page = anon.get_once(&format!("{}/console/", anon.base)).await;
    assert_eq!(page.status, 303);
    assert_eq!(page.headers["location"], "/console/signin");
    let signin = anon.get("/console/signin").await;
    assert_eq!(signin.status, 200, "the sign-in page is public");
    assert!(signin.body.contains("href=\"/console/login\""));
    assert!(!signin.body.contains("csrf"), "and carries no session data");
    let page = anon
        .get_once(&format!(
            "{}/console/sessions/anything/recording",
            anon.base
        ))
        .await;
    assert_eq!(page.status, 303, "recordings need a session too");

    // ---- an admin signs in (HTTP/1.1) ------------------------------------------
    let mut admin_user = Browser::new(&d, true);
    let page = admin_user.login(&d, ADMIN, &["admins"]).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.url.ends_with("/console/"), "{}", page.url);
    assert!(page.body.contains(ADMIN));
    assert!(page.body.contains("admin"));
    for header in [
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "strict-transport-security",
        "referrer-policy",
    ] {
        assert!(page.headers.contains_key(header), "missing {header}");
    }
    let csp = page.headers["content-security-policy"]
        .to_str()
        .expect("csp");
    assert!(csp.contains("script-src 'self' ") && csp.contains("frame-ancestors 'none'"));
    let script_src = csp
        .split(';')
        .map(str::trim)
        .find(|d| d.starts_with("script-src "))
        .expect("script-src");
    assert_eq!(
        script_src, "script-src 'self' 'wasm-unsafe-eval'",
        "no inline scripts, no JS eval (WebAssembly only, for the player): {csp}"
    );
    assert!(
        !csp.contains("http:") && !csp.contains("https:") && !csp.contains('*'),
        "no third-party origins: {csp}"
    );
    assert_eq!(page.headers["cache-control"], "no-store");
    assert!(
        !page.body.contains("<script>"),
        "pages carry no inline script"
    );
    let cookie = admin_user
        .cookies
        .keys()
        .next()
        .expect("a session cookie")
        .clone();
    assert_eq!(cookie, "__Host-limen_console");
    assert_eq!(admin_user.cookies.len(), 1, "the login cookie is cleared");

    // The cookie is HttpOnly, Secure, and SameSite=Lax.
    let page = admin_user
        .get_once(&format!("{}/console/login", admin_user.base))
        .await;
    assert!(page.headers.contains_key("set-cookie"));
    let set = page.headers["set-cookie"]
        .to_str()
        .expect("cookie")
        .to_owned();
    for attr in ["HttpOnly", "Secure", "SameSite=Lax", "Path=/"] {
        assert!(set.contains(attr), "{attr} in {set}");
    }
    assert!(!set.contains("Domain"), "host-only cookie");
    // Finish that second, unfinished login so the session cookie isn't confused:
    admin_user.cookies.remove("__Host-limen_login");

    // ---- a session happens, then shows up with its recording --------------------
    let developer_cli = d.login(DEVELOPER, &["ops"]).await.expect("developer");
    let conn = ssh_client::connect(
        &proxy_addr,
        &ca_pem,
        developer_cli.clone(),
        &host_ca,
        "web-1",
        "ubuntu",
    )
    .await
    .expect("ssh");
    let (out, _) = ssh_client::exec(&conn, "whoami").await.expect("exec");
    assert!(out.contains("login=ubuntu"));
    drop(conn);
    wait_until("the session and its recording", 20, async || {
        let page = admin_user.get("/console/sessions").await;
        page.body.contains(DEVELOPER) && page.body.contains("recmark")
    })
    .await;
    let page = admin_user.get("/console/sessions").await;
    assert!(page.body.contains("web-1") && page.body.contains("ended"));
    let id = page
        .body
        .split("/console/sessions/")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("a session link")
        .to_owned();
    let detail = admin_user.get(&format!("/console/sessions/{id}")).await;
    assert_eq!(detail.status, 200);
    assert!(
        detail.body.contains("console-worker-1") && detail.body.contains(&worker.worker.id()),
        "the worker's name is shown beside its id"
    );
    assert!(detail.body.contains("asciinema-player.min.js"));
    assert!(
        detail
            .body
            .contains(&format!("/console/sessions/{id}/recording"))
    );
    let cast = admin_user
        .get(&format!("/console/sessions/{id}/recording"))
        .await;
    assert_eq!(cast.status, 200);
    assert_eq!(cast.headers["content-type"], "application/x-asciicast");
    assert!(cast.body.starts_with('{') && cast.body.contains("login=ubuntu command=whoami"));

    // Static assets are served from the binary.
    let js = admin_user
        .get("/console/static/asciinema-player.min.js")
        .await;
    assert_eq!(js.status, 200);
    assert!(js.body.contains("AsciinemaPlayer"));
    assert_eq!(
        admin_user.get("/console/static/console.css").await.status,
        200
    );
    // Assets are looked up by exact name in an embedded table; there is no
    // file system path to traverse.
    for hostile in [
        "%2e%2e%2fconsole.css",
        "..%2f..%2fetc%2fpasswd",
        "console.css%00",
    ] {
        assert_eq!(
            admin_user
                .get(&format!("/console/static/{hostile}"))
                .await
                .status,
            404,
            "{hostile}"
        );
    }

    // ---- dev_user signs in over HTTP/2: he sees only his own things --------------------
    let mut dev_user = Browser::new(&d, false);
    let page = dev_user.login(&d, DEVELOPER, &["ops"]).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("web-1"), "his resources");
    assert!(page.body.contains("limen ssh web-1"));
    assert!(!page.body.contains(">Users<"), "no admin navigation");
    assert!(!page.body.contains("active sessions"), "no admin stats");
    for path in [
        "/console/bots",
        "/console/users",
        "/console/workers",
        "/console/policy",
        "/console/audit",
        "/console/audit/kubernetes",
        "/console/dashboards",
    ] {
        let page = dev_user.get(path).await;
        assert_eq!(page.status, 403, "{path}");
    }
    // His own session is visible; he cannot reach others' by guessing.
    let mine = dev_user.get("/console/sessions").await;
    assert!(mine.body.contains("web-1"));
    assert_eq!(
        dev_user
            .get(&format!("/console/sessions/{id}"))
            .await
            .status,
        200
    );
    let admin_only = "00000000-0000-7000-8000-000000000000";
    assert_eq!(
        dev_user
            .get(&format!("/console/sessions/{admin_only}"))
            .await
            .status,
        404
    );

    // guest_user has a session of her own that dev_user must not see.
    let guest_cli = d.login(GUEST, &["ops"]).await.expect("guest");
    let conn = ssh_client::connect(&proxy_addr, &ca_pem, guest_cli, &host_ca, "web-1", "ubuntu")
        .await
        .expect("ssh");
    let _ = ssh_client::exec(&conn, "hostname").await.expect("exec");
    drop(conn);
    wait_until("guest's session in the admin view", 20, async || {
        // (The user filter's suggestions name her too, so look in the table.)
        admin_user
            .get("/console/sessions")
            .await
            .body
            .split("<tbody>")
            .nth(1)
            .is_some_and(|table| table.contains(GUEST))
    })
    .await;
    let all = admin_user.get("/console/sessions").await;
    // (The user filter's suggestions also name her, so look at the table rows.)
    let guest_id = all
        .body
        .split("<tr")
        .find(|row| row.contains(GUEST) && row.contains("/console/sessions/"))
        .and_then(|row| row.split("/console/sessions/").nth(1))
        .and_then(|s| s.split('"').next())
        .expect("guest's session id")
        .to_owned();
    assert_eq!(
        dev_user
            .get(&format!("/console/sessions/{guest_id}"))
            .await
            .status,
        404,
        "another user's session is hidden"
    );
    assert_eq!(
        dev_user
            .get(&format!("/console/sessions/{guest_id}/recording"))
            .await
            .status,
        404
    );
    assert!(!dev_user.get("/console/sessions").await.body.contains(GUEST));
    let page = dev_user
        .get(&format!("/console/sessions?user={GUEST}"))
        .await;
    assert!(
        !page.body.contains(GUEST),
        "the user filter is ignored for non-admins"
    );

    // ---- resources: admins see all, others only their own ----------------------------
    let all = admin_user.get("/console/resources").await;
    assert_eq!(all.status, 200);
    assert!(all.body.contains("web-1") && all.body.contains("secret-db"));
    assert!(
        all.body.contains("db.internal.example:5432"),
        "admins see targets"
    );
    assert!(
        all.body.contains("none"),
        "a resource no worker can serve is flagged"
    );
    let only_pg = admin_user.get("/console/resources?kind=postgres").await;
    assert!(only_pg.body.contains("secret-db") && !only_pg.body.contains("web-1"));
    let none = admin_user.get("/console/resources?q=does-not-exist").await;
    assert!(none.body.contains("No resources match"));
    let detail = admin_user.get("/console/resources/secret-db").await;
    assert_eq!(detail.status, 200);
    assert!(
        detail.body.contains("Nobody. No role that selects it"),
        "{}",
        detail.body
    );
    let web = admin_user.get("/console/resources/web-1").await;
    assert!(web.body.contains("ops") && web.body.contains("pool=dev"));
    let mine = dev_user.get("/console/resources").await;
    assert!(mine.body.contains("web-1"));
    assert!(
        !mine.body.contains("secret-db"),
        "hidden from people without access"
    );
    assert!(
        !mine.body.contains(&target.addr.to_string()),
        "no internal addresses for non-admins"
    );
    assert_eq!(
        dev_user.get("/console/resources/secret-db").await.status,
        404
    );
    let searched = dev_user.get("/console/resources?q=secret").await;
    assert!(
        !searched.body.contains("secret-db"),
        "a search can't reveal it either"
    );
    let bobs = dev_user.get("/console/resources/web-1").await;
    assert_eq!(bobs.status, 200);
    assert!(!bobs.body.contains(&target.addr.to_string()));
    assert!(bobs.body.contains("limen ssh web-1"));

    // ---- CSRF and origin checks --------------------------------------------------
    let home = admin_user.get("/console/users").await;
    assert_eq!(home.status, 200);
    assert!(home.body.contains(DEVELOPER));
    let csrf = Browser::csrf(&home);
    let page = admin_user
        .post(
            &format!("/console/users/{DEVELOPER_ENC}/lock"),
            &[("csrf", "wrong"), ("reason", "x")],
        )
        .await;
    assert_eq!(page.status, 403, "wrong CSRF token");
    let page = admin_user
        .post_with_origin(
            &format!("/console/users/{DEVELOPER_ENC}/lock"),
            "https://evil.example",
            &[("csrf", &csrf), ("reason", "x")],
        )
        .await;
    assert_eq!(page.status, 403, "foreign origin");
    let page = admin_user
        .send(
            admin_user
                .http
                .post(format!(
                    "{}/console/users/{DEVELOPER_ENC}/lock",
                    admin_user.base
                ))
                .form(&[("csrf", csrf.as_str()), ("reason", "x")]),
        )
        .await;
    assert_eq!(page.status, 403, "no origin at all");
    assert!(
        !read_jsonl(&d).iter().any(|e| e["kind"] == "user.lock"),
        "refused requests change nothing"
    );
    let page = admin_user
        .post(
            &format!("/console/users/{ADMIN_ENC}/lock"),
            &[("csrf", &csrf), ("reason", "oops")],
        )
        .await;
    assert_eq!(page.status, 400, "admins can't lock themselves out");

    // ---- lock dev_user from the console: his browser session and SSH end ------------------
    let page = admin_user
        .post(
            &format!("/console/users/{DEVELOPER_ENC}/lock"),
            &[("csrf", &csrf), ("reason", "stolen laptop")],
        )
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    // The Kubernetes tab renders for admins, empty when there is no cluster traffic.
    let kube_tab = admin_user.get("/console/audit/kubernetes").await;
    assert_eq!(kube_tab.status, 200, "{}", kube_tab.body);
    assert!(kube_tab.body.contains("No Kubernetes requests match."));
    assert!(kube_tab.body.contains("Refused or failed"));
    let user_page = admin_user
        .get(&format!("/console/users/{DEVELOPER_ENC}"))
        .await;
    assert!(user_page.body.contains("locked") && user_page.body.contains("stolen laptop"));
    let page = dev_user
        .get_once(&format!("{}/console/", dev_user.base))
        .await;
    assert_eq!(
        (
            page.status,
            page.headers["location"].to_str().unwrap_or_default()
        ),
        (303, "/console/signin"),
        "locking deletes the user's browser sessions"
    );
    let err = ssh_client::connect(
        &proxy_addr,
        &ca_pem,
        developer_cli.clone(),
        &host_ca,
        "web-1",
        "ubuntu",
    )
    .await
    .err()
    .expect("locked");
    assert!(err.contains("user locked"), "{err}");
    let page = dev_user.login(&d, DEVELOPER, &["ops"]).await;
    assert_eq!(page.status, 403, "locked users can't sign in");
    // Unlock.
    let csrf = Browser::csrf(
        &admin_user
            .get(&format!("/console/users/{DEVELOPER_ENC}"))
            .await,
    );
    let page = admin_user
        .post(
            &format!("/console/users/{DEVELOPER_ENC}/unlock"),
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(page.status, 303);
    assert_eq!(dev_user.login(&d, DEVELOPER, &["ops"]).await.status, 200);

    // ---- a bot: a CI job's session, with the run behind it ----------------------------
    let bot_token = d.idp.workload_token(&WorkloadToken::github(
        "acme/infra",
        "refs/heads/main",
        None,
    ));
    let bot_cli = d
        .bot_login("github_actions", bot_token)
        .await
        .expect("bot login");
    let conn = ssh_client::connect(
        &proxy_addr,
        &ca_pem,
        bot_cli.clone(),
        &host_ca,
        "web-1",
        "ubuntu",
    )
    .await
    .expect("the bot's ssh");
    let (out, _) = ssh_client::exec(&conn, "whoami").await.expect("exec");
    assert!(out.contains("login=ubuntu"));
    drop(conn);
    let bots_page = admin_user.get("/console/bots").await;
    assert_eq!(bots_page.status, 200);
    for needle in [
        "bot:deploy-e2e",
        "acme/infra",
        "github_actions",
        "the e2e deploy job",
        "424242",
    ] {
        assert!(bots_page.body.contains(needle), "Bots page lacks {needle}");
    }
    assert!(
        bots_page
            .body
            .contains("https://github.com/acme/infra/actions/runs/424242")
    );
    // A user's page lists what their roles reach.
    let detail = admin_user
        .get(&format!("/console/users/{DEVELOPER_ENC}"))
        .await;
    assert_eq!(detail.status, 200);
    assert!(
        detail.body.contains("What they can reach"),
        "user access section"
    );
    // Search narrows the list pages.
    let hit = admin_user.get("/console/bots?q=github+acme").await;
    assert!(hit.body.contains("bot:deploy-e2e"), "bot search finds it");
    let miss = admin_user.get("/console/bots?q=no-such-bot-zzz").await;
    assert!(
        !miss.body.contains("bot:deploy-e2e") && miss.body.contains("No bot matches"),
        "bot search misses cleanly"
    );
    let miss = admin_user.get("/console/users?q=no-such-user-zzz").await;
    assert!(miss.body.contains("No user matches"), "user search misses");
    let miss = admin_user
        .get("/console/workers?q=no-such-worker-zzz")
        .await;
    assert!(
        miss.body.contains("No component matches"),
        "worker search misses"
    );
    let miss = admin_user.get("/console/policy?q=no-such-doc-zzz").await;
    assert!(
        miss.body.contains("No policy document matches"),
        "policy search misses"
    );
    let people_page = admin_user.get("/console/users").await;
    assert!(
        !people_page.body.contains("bot%3Adeploy-e2e")
            && !people_page.body.contains("bot:deploy-e2e"),
        "bots are not listed among people"
    );
    wait_until("the bot's session in the admin view", 20, async || {
        // (Suggestions in the filter name users too, so look in the table.)
        admin_user
            .get("/console/sessions")
            .await
            .body
            .split("<tbody>")
            .nth(1)
            .is_some_and(|table| table.contains("bot:deploy-e2e"))
    })
    .await;
    let sessions = admin_user
        .get("/console/sessions?user=bot%3Adeploy-e2e")
        .await;
    assert!(
        sessions.body.contains("class=\"pill bot\""),
        "marked as a bot"
    );
    let bot_session = sessions
        .body
        .split("/console/sessions/")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("a session link")
        .to_owned();
    let detail = admin_user
        .get(&format!("/console/sessions/{bot_session}"))
        .await;
    assert_eq!(detail.status, 200);
    assert!(detail.body.contains("The CI run") && detail.body.contains("acme/infra"));
    let events = read_jsonl(&d);
    let start = events
        .iter()
        .find(|e| e["kind"] == "session.start" && e["user"] == "bot:deploy-e2e")
        .expect("the bot's session.start");
    assert_eq!(start["data"]["actor_type"], "bot");
    assert_eq!(start["data"]["ci"]["repository"], "acme/infra");
    let people_start = events
        .iter()
        .find(|e| e["kind"] == "session.start" && e["user"] == DEVELOPER)
        .expect("a person's session.start");
    assert_eq!(people_start["data"]["actor_type"], "user");
    assert!(people_start["data"].get("ci").is_none());
    // Locking a bot works like locking a person.
    let csrf = Browser::csrf(&detail);
    let page = admin_user
        .post(
            "/console/users/bot%3Adeploy-e2e/lock",
            &[("csrf", &csrf), ("reason", "suspicious run")],
        )
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    let err = ssh_client::connect(&proxy_addr, &ca_pem, bot_cli, &host_ca, "web-1", "ubuntu")
        .await
        .err()
        .expect("locked bot");
    assert!(err.contains("user locked"), "{err}");
    let relogin = d
        .bot_login(
            "github_actions",
            d.idp.workload_token(&WorkloadToken::github(
                "acme/infra",
                "refs/heads/main",
                None,
            )),
        )
        .await
        .expect_err("a locked bot can't log in again");
    assert_eq!(relogin.code(), tonic::Code::PermissionDenied);

    // ---- workers: token and revoke -----------------------------------------------------
    let workers = admin_user.get("/console/workers").await;
    assert_eq!(workers.status, 200);
    assert!(workers.body.contains("pool=dev") && workers.body.contains("enrolled"));
    assert!(
        workers.body.contains("console-worker-1") && workers.body.contains(&worker.worker.id()),
        "name beside the id"
    );
    assert!(
        !workers.body.contains("limen.io/name="),
        "the name is not repeated as a label chip"
    );
    let csrf = Browser::csrf(&workers);
    let page = admin_user
        .post(
            "/console/workers/tokens",
            &[
                ("csrf", &csrf),
                ("kind", "worker"),
                ("labels", "pool=prod\nteam=db"),
                ("ttl_minutes", "5"),
                ("dns_names", ""),
                ("name", "prod-db-*"),
            ],
        )
        .await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("lmn_join_"), "the token is shown once");
    let after = admin_user.get("/console/workers").await;
    assert!(
        after.body.contains("Outstanding join tokens") && after.body.contains("team=db"),
        "the unused token is listed (without its value)"
    );
    assert!(
        after.body.contains("prod-db-*"),
        "with the names it approves"
    );
    let page = admin_user
        .post(
            "/console/workers/tokens",
            &[
                ("csrf", &csrf),
                ("kind", "worker"),
                ("labels", ""),
                ("ttl_minutes", "5"),
                ("dns_names", ""),
                ("name", "Prod-*"),
            ],
        )
        .await;
    assert_eq!(page.status, 400, "an invalid name pattern is refused");
    assert!(!after.body.contains("lmn_join_"));
    let page = admin_user
        .post(
            "/console/workers/tokens",
            &[
                ("csrf", &csrf),
                ("kind", "worker"),
                ("labels", "no-equals"),
                ("ttl_minutes", "5"),
                ("dns_names", ""),
            ],
        )
        .await;
    assert_eq!(page.status, 400);
    let worker_id = worker.worker.id();
    let page = admin_user
        .post(
            &format!("/console/workers/{worker_id}/revoke"),
            &[("csrf", &csrf), ("reason", "decommissioned")],
        )
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    assert!(
        admin_user
            .get("/console/workers")
            .await
            .body
            .contains("revoked")
    );
    eventually(
        Duration::from_secs(15),
        "the proxy drops the revoked worker's tunnels",
        || async { d.proxy().tunnels.summaries().is_empty() },
    )
    .await;

    // ---- the audit trail ------------------------------------------------------------------
    let mut trail = String::new();
    for _ in 0..40 {
        trail = admin_user.get("/console/audit").await.body;
        if trail.contains("auth.login") && trail.contains("join_token.create") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(trail.contains("auth.login"), "{trail}");
    assert!(trail.contains("join_token.create") && trail.contains("component.revoke"));
    let filtered = admin_user
        .get(&format!("/console/audit?kind=user.lock&user={ADMIN_ENC}"))
        .await;
    assert_eq!(filtered.status, 200);
    // (The kinds also appear as options in the filter, so look at the rows.)
    assert!(
        filtered.body.contains(">user.lock</span>"),
        "{}",
        filtered.body
    );
    assert!(filtered.body.contains(&format!("target_user={DEVELOPER}")));
    assert!(!filtered.body.contains(">join_token.create</span>"));
    let user_page = admin_user
        .get(&format!("/console/users/{DEVELOPER_ENC}"))
        .await;
    assert!(user_page.body.contains("Recent activity"));

    // ---- built-in dashboards -------------------------------------------------------------
    for range in ["24h", "7d", "30d", "nonsense"] {
        let page = admin_user
            .get(&format!("/console/dashboards?range={range}"))
            .await;
        assert_eq!(page.status, 200, "{range}: {}", page.body);
        assert!(page.body.contains("<svg class=\"chart\""), "{range}");
        assert!(page.body.contains("Busiest resources"));
    }
    // Every view and every panel runs its query against the real schema.
    for view in [
        "overview", "security", "sre", "bots", "usage", "all", "nonsense",
    ] {
        let page = admin_user
            .get(&format!("/console/dashboards?view={view}"))
            .await;
        assert_eq!(page.status, 200, "{view}: {}", page.body);
    }
    let all = admin_user.get("/console/dashboards?view=all").await;
    for title in [
        "Components gone quiet",
        "Kubernetes API errors",
        "Out-of-hours access",
        "Data transferred",
    ] {
        assert!(all.body.contains(&format!("<h2>{title}</h2>")), "{title}");
    }
    let picked = admin_user
        .get("/console/dashboards?p=kinds&p=worker-load")
        .await;
    assert!(
        picked.body.contains("<h2>Sessions by kind</h2>")
            && picked.body.contains("<h2>Tunnels per worker</h2>")
            && !picked.body.contains("<h2>Busiest resources</h2>"),
        "only the chosen panels are drawn"
    );
    let custom = admin_user
        .get("/console/dashboards?p=kinds&p=traffic&range=7d")
        .await;
    assert!(
        custom.body.contains("range=24h&#38;p=kinds&#38;p=traffic")
            || custom.body.contains("range=24h&amp;p=kinds&amp;p=traffic"),
        "changing the range keeps a custom selection: {}",
        custom.body
    );
    let dash = admin_user.get("/console/dashboards").await;
    assert!(
        dash.body.contains("web-1"),
        "the resource that had sessions shows up as busy"
    );
    assert!(dash.body.contains("<title>"), "bars carry tooltips");
    assert!(
        dash.body.contains("Bot sessions by repository") && dash.body.contains("acme/infra"),
        "the bot's session shows up under its repository"
    );

    // ---- drill-down: dashboard links and the filters behind them ------------------------------
    assert!(
        dash.body.contains("/console/audit?kind=auth.denied")
            && dash.body.contains("/console/audit?kind=auth.login")
            && dash.body.contains("/console/sessions?actor=bot"),
        "tiles lead to the records behind them"
    );
    let usage = admin_user.get("/console/dashboards?view=usage").await;
    assert!(
        usage.body.contains("/console/sessions?kind=ssh") && usage.body.contains("from=20"),
        "ranked rows lead to the sessions behind them, for the same period"
    );
    let bot_sessions = admin_user.get("/console/sessions?actor=bot").await;
    assert!(
        rows(&bot_sessions.body).contains("bot:deploy-e2e")
            && !rows(&bot_sessions.body).contains(DEVELOPER)
    );
    let people = admin_user.get("/console/sessions?actor=user").await;
    assert!(
        rows(&people.body).contains(DEVELOPER) && !rows(&people.body).contains("bot:deploy-e2e")
    );
    let one = admin_user
        .get("/console/sessions?kind=ssh&resource=web-1&end=nonsense")
        .await;
    assert_eq!(one.status, 200);
    assert!(
        !rows(&one.body).contains(DEVELOPER),
        "no session ended that way"
    );
    let future = admin_user.get("/console/sessions?from=2999-01-01").await;
    assert!(!rows(&future.body).contains("web-1"));
    let bad = admin_user
        .get("/console/sessions?from=yesterday&actor=robot")
        .await;
    assert!(bad.body.contains("Ignored") && rows(&bad.body).contains("web-1"));
    let chip = admin_user.get("/console/sessions?kind=ssh").await;
    assert!(chip.body.contains("Remove this filter") && chip.body.contains("Kind: ssh"));

    let prefix = admin_user.get("/console/audit?kind=user.*").await;
    assert!(prefix.body.contains(">user.lock</span>"));
    assert!(!prefix.body.contains(">join_token.create</span>"));
    let text = admin_user.get("/console/audit?q=TARGET_USER").await;
    assert!(
        text.body.contains(">user.lock</span>"),
        "text search ignores case"
    );
    let bot_events = admin_user.get("/console/audit?actor=bot").await;
    assert!(bot_events.body.contains("bot:deploy-e2e"));
    assert!(
        !bot_events
            .body
            .contains(&format!("/console/users/{DEVELOPER_ENC}\""))
    );
    let window = admin_user
        .get("/console/audit?kind=user.lock&from=2000-01-01&to=2999-01-01")
        .await;
    assert!(
        window.body.contains(">user.lock</span>") && window.body.contains("Remove this filter")
    );
    let past = admin_user.get("/console/audit?to=2000-01-01").await;
    assert!(past.body.contains("No events match"));
    let junk = admin_user
        .get("/console/audit?session=nope&from=soon&actor=x")
        .await;
    assert_eq!(junk.status, 200);
    assert_eq!(junk.body.matches("Ignored").count(), 3, "{}", junk.body);
    let recent = admin_user.get("/console/audit?since=24h").await;
    assert!(recent.body.contains(">user.lock</span>") && recent.body.contains("Period: 24 hours"));
    assert!(recent.body.contains("since=1h"), "quick ranges are offered");
    let sessions_recent = admin_user.get("/console/sessions?since=1h&kind=ssh").await;
    assert!(sessions_recent.body.contains("Period: Last hour"));
    let unknown = admin_user.get("/console/audit?since=forever").await;
    assert!(unknown.status == 200 && !unknown.body.contains("Period:"));
    let empty = admin_user.get("/console/sessions?resource=nope").await;
    assert!(
        empty.body.contains("clear all"),
        "an empty result offers a way out"
    );
    let trail = admin_user
        .get(&format!("/console/audit?session={id}"))
        .await;
    assert_eq!(trail.status, 200);
    assert!(!trail.body.contains("Ignored"));

    // ---- policy browsing and dry run -------------------------------------------------------
    let policy_page = admin_user.get("/console/policy").await;
    assert_eq!(policy_page.status, 200);
    assert!(policy_page.body.contains("web-1") && policy_page.body.contains("ops"));
    assert!(policy_page.body.contains("host_key"), "the YAML behind it");
    let csrf = Browser::csrf(&policy_page);
    let changed = "kind: role\nversion: v1\nmetadata: { name: ops }\nspec:\n  allow:\n    - resources: { kind: [ssh], labels: { env: [prod] } }\n      ssh: { logins: [ubuntu] }\n";
    let page = admin_user
        .post(
            "/console/policy/dry-run",
            &[("csrf", &csrf), ("yaml", changed)],
        )
        .await;
    assert_eq!(page.status, 200);
    assert!(
        page.body.contains("Dry run: nothing was applied."),
        "{}",
        page.body
            .split("<h2>Result</h2>")
            .nth(1)
            .unwrap_or(&page.body)
    );
    let result = page.body.split("<h2>Result</h2>").nth(1).expect("a result");
    assert!(
        result.contains("web-1"),
        "the removed resource is listed: {result}"
    );
    assert!(
        result.contains("ops"),
        "the changed role is listed: {result}"
    );
    let page = admin_user
        .post(
            "/console/policy/dry-run",
            &[("csrf", &csrf), ("yaml", "kind: nonsense")],
        )
        .await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains("class=\"error\""));
    assert_eq!(
        d.proxy().policy_version(),
        Some(applied.version),
        "a dry run applies nothing"
    );

    // ---- XSS: hostile text is escaped ---------------------------------------------------------
    let evil = "<script>alert(1)</script>";
    let page = admin_user
        .post(
            "/console/policy/dry-run",
            &[("csrf", &csrf), ("yaml", evil)],
        )
        .await;
    assert!(!page.body.contains(evil), "pasted text is escaped");
    assert!(
        page.body.contains("&#60;script&#62;") || page.body.contains("&lt;script&gt;"),
        "escaped, not dropped"
    );

    // ---- sign out ------------------------------------------------------------------------------
    // Opening the logout URL shows a confirmation; it signs nobody out by itself.
    let confirm = admin_user.get("/console/logout").await;
    assert_eq!(confirm.status, 200);
    assert!(confirm.body.contains("action=\"/console/logout\""));
    assert_eq!(
        admin_user.get("/console/").await.status,
        200,
        "still signed in"
    );
    let anon_logout = anon
        .get_once(&format!("{}/console/logout", anon.base))
        .await;
    assert_eq!(anon_logout.status, 303, "no session: sent to sign-in");
    let csrf = Browser::csrf(&confirm);
    let page = admin_user.post("/console/logout", &[("csrf", &csrf)]).await;
    assert_eq!(page.status, 200);
    assert!(admin_user.cookies.is_empty(), "the cookie is cleared");
    let page = admin_user
        .get_once(&format!("{}/console/", admin_user.base))
        .await;
    assert_eq!(page.status, 303);

    // ---- audit -----------------------------------------------------------------------------------
    let events = read_jsonl(&d);
    let find = |kind: &str| events.iter().find(|e| e["kind"] == kind).cloned();
    let lock = find("user.lock").expect("user.lock");
    assert_eq!(lock["data"]["via"], "console");
    assert_eq!(lock["user"], ADMIN);
    assert_eq!(lock["data"]["target_user"], DEVELOPER);
    assert!(find("user.unlock").is_some());
    let revoke = find("component.revoke").expect("component.revoke");
    assert_eq!(revoke["data"]["via"], "console");
    assert!(
        events
            .iter()
            .filter(|e| e["kind"] == "join_token.create")
            .any(|e| e["data"]["via"] == "console"),
        "token creation from the console is audited as such"
    );
    assert!(
        events
            .iter()
            .any(|e| e["kind"] == "auth.login" && e["data"]["flow"] == "console"),
        "console logins are audited"
    );
    assert!(events.iter().any(|e| e["kind"] == "auth.denied"
        && e["data"]["action"] == "console_login"
        && e["data"]["reason"] == "user locked"));
}

#[tokio::test(flavor = "multi_thread")]
async fn console_login_is_bound_to_the_browser_that_started_it() {
    let Some(d) = Deployment::start_with_console().await else {
        return;
    };
    // The attacker starts a login and gets a callback URL with a valid code.
    d.idp.set_browser_user(ADMIN, &["admins"]);
    let mut attacker = Browser::new(&d, true);
    let start = attacker
        .get_once(&format!("{}/console/login", attacker.base))
        .await;
    assert_eq!(start.status, 303);
    let to_idp = start.headers["location"]
        .to_str()
        .expect("location")
        .to_owned();
    assert!(to_idp.contains("code_challenge_method=S256") && to_idp.contains("state="));
    let back = attacker.get_once(&to_idp).await;
    let callback = back.headers["location"]
        .to_str()
        .expect("callback")
        .to_owned();
    assert!(callback.contains("/console/callback?code="));
    // A victim's browser, with no login cookie, is tricked into opening it.
    let mut victim = Browser::new(&d, true);
    let page = victim.get_once(&callback).await;
    assert_eq!(page.status, 403, "login CSRF is refused");
    assert!(victim.cookies.is_empty(), "no session was created");
    // The state is single use: even the attacker's own browser can't replay it.
    let page = attacker.get_once(&callback).await;
    assert_eq!(page.status, 303, "first use works for its own browser");
    let replay = attacker.get_once(&callback).await;
    assert_eq!(replay.status, 403, "a login can't be replayed");
}

/// The rows of a list page's table: the filter's suggestions above it name users and resources too.
fn rows(body: &str) -> &str {
    body.split("<tbody>").nth(1).unwrap_or("")
}

/// Where a POST redirected to.
fn location(page: &Page) -> String {
    assert_eq!(page.status, 303, "{}", page.body);
    page.headers["location"]
        .to_str()
        .expect("location")
        .to_owned()
}

/// The etag of an editable document on the policy page.
fn etag_of(body: &str, name: &str) -> String {
    let form = body
        .split("<form method=\"post\" action=\"/console/policy/documents\"")
        .find(|f| f.contains(&format!("name=\"name\" value=\"{name}\"")))
        .unwrap_or_else(|| panic!("no edit form for {name}"));
    let marker = "name=\"etag\" value=\"";
    let start = form.find(marker).expect("etag") + marker.len();
    form[start..].split('"').next().expect("value").to_owned()
}

#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread")]
async fn the_console_edits_what_it_owns_and_decides_held_changes() {
    let Some(d) = Deployment::start_with_console_args(&["--widening-approval=all"]).await else {
        return;
    };
    // With --widening-approval=all even the first apply waits for a second
    // admin: it gives people access they didn't have.
    let admin_cli = d.login(ADMIN, &["admins"]).await.expect("admin");
    let applied = AdminClient::new(d.proxy_channel(Some(admin_cli)))
        .apply_policy(ApplyPolicyRequest {
            source: String::new(),
            require_tests: false,
            sources: policy(
                "127.0.0.1:2222",
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAkWE808+SBJ5tbkLTrbcpmj4Qg2UvqRG/CYJgBwP1S",
                &d.idp.issuer,
            ),
            dry_run: false,
            source_ref: String::new(),
        })
        .await
        .expect("apply")
        .into_inner();
    assert!(!applied.applied, "held");
    let first = applied.pending_change_id;
    assert!(!first.is_empty());
    let mut admin = Browser::new(&d, true);
    assert_eq!(admin.login(&d, ADMIN, &["admins"]).await.status, 200);
    let mut second = Browser::new(&d, true);
    second
        .login(&d, "second-admin@example.com", &["admins"])
        .await;
    let detail = second.get(&format!("/console/changes/{first}")).await;
    assert!(
        detail.body.contains("replace git source"),
        "what a held apply writes"
    );
    let approved = second
        .post(
            &format!("/console/changes/{first}/decide"),
            &[
                ("csrf", &Browser::csrf(&detail)),
                ("decision", "approve"),
                ("note", ""),
            ],
        )
        .await;
    let page = second.get(&location(&approved)).await;
    assert!(
        page.body.contains(">applied</span>"),
        "the first apply, approved in the console"
    );

    // Every document shows its owner; files' documents are read-only.
    let page = admin.get("/console/policy").await;
    assert!(
        page.body.contains("git source") && page.body.contains("in namespace"),
        "owners shown"
    );
    assert!(
        page.body.contains("Managed by"),
        "read-only documents say where they live"
    );
    assert!(
        !page.body.contains("value=\"web-1\""),
        "no edit form for a file's document"
    );
    let csrf = Browser::csrf(&page);

    // A role the console will own: it gives nobody anything, so it applies.
    let role = "kind: role\nversion: v1\nmetadata: { name: console-viewers }\nspec:\n  allow:\n    - resources: { kind: [ssh], labels: { env: [test] } }\n      ssh: { logins: [ubuntu] }\n";
    let saved = admin
        .post(
            "/console/policy/documents",
            &[("csrf", &csrf), ("yaml", role)],
        )
        .await;
    let page = admin.get(&location(&saved)).await;
    assert!(
        page.body.contains("Applied: policy version"),
        "{}",
        page.url
    );
    assert!(page.body.contains("<span class=\"pill ok\">console</span>"));
    // Edited, with the etag it was read with.
    let etag = etag_of(&page.body, "console-viewers");
    let edited = role.replace("logins: [ubuntu]", "logins: [ubuntu, deploy]");
    let saved = admin
        .post(
            "/console/policy/documents",
            &[
                ("csrf", &csrf),
                ("yaml", &edited),
                ("kind", "role"),
                ("name", "console-viewers"),
                ("etag", &etag),
            ],
        )
        .await;
    let page = admin.get(&location(&saved)).await;
    assert!(page.body.contains("Applied"));
    // A stale etag, a file's document, or two documents are refused, with
    // what was typed kept for a new one.
    let stale = admin
        .post(
            "/console/policy/documents",
            &[
                ("csrf", &csrf),
                ("yaml", &edited),
                ("kind", "role"),
                ("name", "console-viewers"),
                ("etag", &etag),
            ],
        )
        .await;
    assert!(
        stale.body.contains("Not saved") && stale.body.contains("changed since it was read"),
        "{}",
        stale.status
    );
    let theirs = "kind: role\nversion: v1\nmetadata: { name: ops }\nspec: { allow: [] }\n";
    let refused = admin
        .post(
            "/console/policy/documents",
            &[("csrf", &csrf), ("yaml", theirs)],
        )
        .await;
    assert!(
        refused.body.contains("Not saved") && refused.body.contains("already exists"),
        "creating over a file's document"
    );
    let two = format!("{role}---\n{theirs}");
    let refused = admin
        .post(
            "/console/policy/documents",
            &[("csrf", &csrf), ("yaml", &two)],
        )
        .await;
    assert!(refused.body.contains("exactly one document"));
    assert!(
        refused.body.contains("console-viewers"),
        "the draft is kept"
    );
    let forged = admin
        .post_with_origin(
            "/console/policy/documents",
            "https://evil.example",
            &[("csrf", &csrf), ("yaml", role)],
        )
        .await;
    assert_eq!(forged.status, 403, "cross-site posts are refused");

    // A mapping that gives standing access waits for a second admin.
    let mapping = "kind: role_mapping\nversion: v1\nmetadata: { name: console-people }\nspec:\n  - { idp_group: viewers, roles: [console-viewers] }\n";
    let saved = admin
        .post(
            "/console/policy/documents",
            &[("csrf", &csrf), ("yaml", mapping)],
        )
        .await;
    let page = admin.get(&location(&saved)).await;
    let notice = page
        .body
        .split("Held for approval")
        .nth(1)
        .expect("held notice");
    let id = notice
        .split("change ")
        .nth(1)
        .and_then(|s| s.get(..36))
        .expect("change id")
        .to_owned();
    assert!(
        !page.body.contains("value=\"console-people\""),
        "nothing applied yet"
    );
    // Its author sees it but can't decide it.
    let mine = admin.get(&format!("/console/changes/{id}")).await;
    assert_eq!(mine.status, 200);
    assert!(
        mine.body.contains("its author can&#39;t decide it")
            || mine.body.contains("its author can't decide it")
            || mine.body.contains("its author can&#x27;t decide it"),
        "{}",
        mine.body.len()
    );
    assert!(!mine.body.contains("Approve and apply"));
    assert!(mine.body.contains("viewers"), "the access it gives");

    // Someone without an approver role doesn't see the page.
    let mut developer = Browser::new(&d, true);
    developer.login(&d, DEVELOPER, &["ops"]).await;
    let page = developer.get("/console/changes").await;
    assert_eq!(page.status, 403);
    assert!(!page.body.contains(&id));

    // A second admin approves it here.
    let mut second = Browser::new(&d, true);
    second
        .login(&d, "second-admin@example.com", &["admins"])
        .await;
    let list = second.get("/console/changes").await;
    assert!(list.body.contains(&id), "listed as waiting");
    assert!(list.body.contains("Policy changes"), "in the menu");
    let detail = second.get(&format!("/console/changes/{id}")).await;
    assert!(detail.body.contains("Approve and apply"));
    let csrf2 = Browser::csrf(&detail);
    let rejected = second
        .post(
            &format!("/console/changes/{id}/decide"),
            &[("csrf", &csrf2), ("decision", "reject")],
        )
        .await;
    assert!(
        rejected.body.contains("a note is required"),
        "rejecting needs a reason"
    );
    let approved = second
        .post(
            &format!("/console/changes/{id}/decide"),
            &[
                ("csrf", &csrf2),
                ("decision", "approve"),
                ("note", "viewers read test hosts"),
            ],
        )
        .await;
    let page = second.get(&location(&approved)).await;
    assert!(page.body.contains(">applied</span>"), "{}", page.body.len());
    let policy_page = admin.get("/console/policy").await;
    assert!(
        policy_page.body.contains("value=\"console-people\""),
        "applied, and the console owns it"
    );

    // The console deletes what it owns.
    let etag = etag_of(&policy_page.body, "console-people");
    let deleted = admin
        .post(
            "/console/policy/documents/delete",
            &[
                ("csrf", &csrf),
                ("kind", "role_mapping"),
                ("name", "console-people"),
                ("etag", &etag),
            ],
        )
        .await;
    let page = admin.get(&location(&deleted)).await;
    assert!(page.body.contains("Applied") && !page.body.contains("value=\"console-people\""));
}
