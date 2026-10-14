//! The web console end to end (ADR-0017): a browser-like client logs in
//! through the mock IdP's authorization code flow, talks to the proxy over
//! TLS, and drives the pages the way a person would.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use limen_e2e::{Deployment, eventually, ssh_client};
use limen_proto::v1::admin_client::AdminClient;
use limen_proto::v1::{ApplyPolicyRequest, CreateJoinTokenRequest, PolicySource};
use limen_testkit::ssh_target::SshTarget;

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

fn policy(target_addr: &str, host_key: &str) -> Vec<PolicySource> {
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
kind: role_mapping
version: v1
metadata: {{ name: idp }}
spec:
  - {{ idp_group: ops, roles: [ops] }}
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
    let alice_cli = d
        .login("alice@example.com", &["admins"])
        .await
        .expect("admin");
    let mut admin = AdminClient::new(d.proxy_channel(Some(alice_cli)));
    let applied = admin
        .apply_policy(ApplyPolicyRequest {
            sources: policy(&target.addr.to_string(), &target.host_key),
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
        })
        .await
        .expect("token")
        .into_inner()
        .token;
    let worker = d.start_worker(&token, "worker").await;
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
    let mut alice = Browser::new(&d, true);
    let page = alice.login(&d, "alice@example.com", &["admins"]).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.url.ends_with("/console/"), "{}", page.url);
    assert!(page.body.contains("alice@example.com"));
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
    let cookie = alice
        .cookies
        .keys()
        .next()
        .expect("a session cookie")
        .clone();
    assert_eq!(cookie, "__Host-limen_console");
    assert_eq!(alice.cookies.len(), 1, "the login cookie is cleared");

    // The cookie is HttpOnly, Secure, and SameSite=Lax.
    let page = alice
        .get_once(&format!("{}/console/login", alice.base))
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
    alice.cookies.remove("__Host-limen_login");

    // ---- a session happens, then shows up with its recording --------------------
    let bob_cli = d.login("bob@example.com", &["ops"]).await.expect("bob");
    let conn = ssh_client::connect(
        &proxy_addr,
        &ca_pem,
        bob_cli.clone(),
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
        let page = alice.get("/console/sessions").await;
        page.body.contains("bob@example.com") && page.body.contains("recmark")
    })
    .await;
    let page = alice.get("/console/sessions").await;
    assert!(page.body.contains("web-1") && page.body.contains("ended"));
    let id = page
        .body
        .split("/console/sessions/")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("a session link")
        .to_owned();
    let detail = alice.get(&format!("/console/sessions/{id}")).await;
    assert_eq!(detail.status, 200);
    assert!(detail.body.contains("asciinema-player.min.js"));
    assert!(
        detail
            .body
            .contains(&format!("/console/sessions/{id}/recording"))
    );
    let cast = alice
        .get(&format!("/console/sessions/{id}/recording"))
        .await;
    assert_eq!(cast.status, 200);
    assert_eq!(cast.headers["content-type"], "application/x-asciicast");
    assert!(cast.body.starts_with('{') && cast.body.contains("login=ubuntu command=whoami"));

    // Static assets are served from the binary.
    let js = alice.get("/console/static/asciinema-player.min.js").await;
    assert_eq!(js.status, 200);
    assert!(js.body.contains("AsciinemaPlayer"));
    assert_eq!(alice.get("/console/static/console.css").await.status, 200);
    // Assets are looked up by exact name in an embedded table; there is no
    // file system path to traverse.
    for hostile in [
        "%2e%2e%2fconsole.css",
        "..%2f..%2fetc%2fpasswd",
        "console.css%00",
    ] {
        assert_eq!(
            alice
                .get(&format!("/console/static/{hostile}"))
                .await
                .status,
            404,
            "{hostile}"
        );
    }

    // ---- bob signs in over HTTP/2: he sees only his own things --------------------
    let mut bob = Browser::new(&d, false);
    let page = bob.login(&d, "bob@example.com", &["ops"]).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("web-1"), "his resources");
    assert!(page.body.contains("limen ssh web-1"));
    assert!(!page.body.contains(">Users<"), "no admin navigation");
    assert!(!page.body.contains("active sessions"), "no admin stats");
    for path in ["/console/users", "/console/workers", "/console/policy"] {
        let page = bob.get(path).await;
        assert_eq!(page.status, 403, "{path}");
    }
    // His own session is visible; he cannot reach others' by guessing.
    let mine = bob.get("/console/sessions").await;
    assert!(mine.body.contains("web-1"));
    assert_eq!(
        bob.get(&format!("/console/sessions/{id}")).await.status,
        200
    );
    let alice_only = "00000000-0000-7000-8000-000000000000";
    assert_eq!(
        bob.get(&format!("/console/sessions/{alice_only}"))
            .await
            .status,
        404
    );

    // carol has a session of her own that bob must not see.
    let carol_cli = d.login("carol@example.com", &["ops"]).await.expect("carol");
    let conn = ssh_client::connect(&proxy_addr, &ca_pem, carol_cli, &host_ca, "web-1", "ubuntu")
        .await
        .expect("ssh");
    let _ = ssh_client::exec(&conn, "hostname").await.expect("exec");
    drop(conn);
    wait_until("carol's session in the admin view", 20, async || {
        alice
            .get("/console/sessions")
            .await
            .body
            .contains("carol@example.com")
    })
    .await;
    let all = alice.get("/console/sessions").await;
    let carol_id = all
        .body
        .split("carol@example.com")
        .nth(1)
        .and_then(|rest| rest.split("/console/sessions/").nth(1))
        .and_then(|s| s.split('"').next())
        .expect("carol's session id")
        .to_owned();
    assert_eq!(
        bob.get(&format!("/console/sessions/{carol_id}"))
            .await
            .status,
        404,
        "another user's session is hidden"
    );
    assert_eq!(
        bob.get(&format!("/console/sessions/{carol_id}/recording"))
            .await
            .status,
        404
    );
    assert!(
        !bob.get("/console/sessions")
            .await
            .body
            .contains("carol@example.com")
    );
    let page = bob.get("/console/sessions?user=carol@example.com").await;
    assert!(
        !page.body.contains("carol@example.com"),
        "the user filter is ignored for non-admins"
    );

    // ---- CSRF and origin checks --------------------------------------------------
    let home = alice.get("/console/users").await;
    assert_eq!(home.status, 200);
    assert!(home.body.contains("bob@example.com"));
    let csrf = Browser::csrf(&home);
    let page = alice
        .post(
            "/console/users/bob%40example.com/lock",
            &[("csrf", "wrong"), ("reason", "x")],
        )
        .await;
    assert_eq!(page.status, 403, "wrong CSRF token");
    let page = alice
        .post_with_origin(
            "/console/users/bob%40example.com/lock",
            "https://evil.example",
            &[("csrf", &csrf), ("reason", "x")],
        )
        .await;
    assert_eq!(page.status, 403, "foreign origin");
    let page = alice
        .send(
            alice
                .http
                .post(format!(
                    "{}/console/users/bob%40example.com/lock",
                    alice.base
                ))
                .form(&[("csrf", csrf.as_str()), ("reason", "x")]),
        )
        .await;
    assert_eq!(page.status, 403, "no origin at all");
    assert!(
        !read_jsonl(&d).iter().any(|e| e["kind"] == "user.lock"),
        "refused requests change nothing"
    );
    let page = alice
        .post(
            "/console/users/alice%40example.com/lock",
            &[("csrf", &csrf), ("reason", "oops")],
        )
        .await;
    assert_eq!(page.status, 400, "admins can't lock themselves out");

    // ---- lock bob from the console: his browser session and SSH end ------------------
    let page = alice
        .post(
            "/console/users/bob%40example.com/lock",
            &[("csrf", &csrf), ("reason", "stolen laptop")],
        )
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    let user_page = alice.get("/console/users/bob%40example.com").await;
    assert!(user_page.body.contains("locked") && user_page.body.contains("stolen laptop"));
    let page = bob.get_once(&format!("{}/console/", bob.base)).await;
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
        bob_cli.clone(),
        &host_ca,
        "web-1",
        "ubuntu",
    )
    .await
    .err()
    .expect("locked");
    assert!(err.contains("user locked"), "{err}");
    let page = bob.login(&d, "bob@example.com", &["ops"]).await;
    assert_eq!(page.status, 403, "locked users can't sign in");
    // Unlock.
    let csrf = Browser::csrf(&alice.get("/console/users/bob%40example.com").await);
    let page = alice
        .post(
            "/console/users/bob%40example.com/unlock",
            &[("csrf", &csrf)],
        )
        .await;
    assert_eq!(page.status, 303);
    assert_eq!(bob.login(&d, "bob@example.com", &["ops"]).await.status, 200);

    // ---- workers: token and revoke -----------------------------------------------------
    let workers = alice.get("/console/workers").await;
    assert_eq!(workers.status, 200);
    assert!(workers.body.contains("pool=dev") && workers.body.contains("enrolled"));
    let csrf = Browser::csrf(&workers);
    let page = alice
        .post(
            "/console/workers/tokens",
            &[
                ("csrf", &csrf),
                ("kind", "worker"),
                ("labels", "pool=prod\nteam=db"),
                ("ttl_minutes", "5"),
                ("dns_names", ""),
            ],
        )
        .await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("lmn_join_"), "the token is shown once");
    let page = alice
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
    let worker_id = workers
        .body
        .split("<div class=\"mono\">")
        .map(|s| s.split('<').next().unwrap_or_default())
        .find(|s| s.starts_with("worker-"))
        .expect("a worker id")
        .to_owned();
    let page = alice
        .post(
            &format!("/console/workers/{worker_id}/revoke"),
            &[("csrf", &csrf), ("reason", "decommissioned")],
        )
        .await;
    assert_eq!(page.status, 303, "{}", page.body);
    assert!(alice.get("/console/workers").await.body.contains("revoked"));
    eventually(
        Duration::from_secs(15),
        "the proxy drops the revoked worker's tunnels",
        || async { d.proxy().tunnels.summaries().is_empty() },
    )
    .await;

    // ---- policy browsing and dry run -------------------------------------------------------
    let policy_page = alice.get("/console/policy").await;
    assert_eq!(policy_page.status, 200);
    assert!(policy_page.body.contains("web-1") && policy_page.body.contains("ops"));
    assert!(policy_page.body.contains("host_key"), "the YAML behind it");
    let csrf = Browser::csrf(&policy_page);
    let changed = "kind: role\nversion: v1\nmetadata: { name: ops }\nspec:\n  allow:\n    - resources: { kind: [ssh], labels: { env: [prod] } }\n      ssh: { logins: [ubuntu] }\n";
    let page = alice
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
    let page = alice
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
    let page = alice
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
    let csrf = Browser::csrf(&alice.get("/console/").await);
    let page = alice.post("/console/logout", &[("csrf", &csrf)]).await;
    assert_eq!(page.status, 200);
    assert!(alice.cookies.is_empty(), "the cookie is cleared");
    let page = alice.get_once(&format!("{}/console/", alice.base)).await;
    assert_eq!(page.status, 303);

    // ---- audit -----------------------------------------------------------------------------------
    let events = read_jsonl(&d);
    let find = |kind: &str| events.iter().find(|e| e["kind"] == kind).cloned();
    let lock = find("user.lock").expect("user.lock");
    assert_eq!(lock["data"]["via"], "console");
    assert_eq!(lock["user"], "alice@example.com");
    assert_eq!(lock["data"]["target_user"], "bob@example.com");
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
    d.idp.set_browser_user("alice@example.com", &["admins"]);
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
