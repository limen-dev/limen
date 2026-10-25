//! Phase 8: what goes wrong, and what must not. Each test is one failure the
//! review of ADR-0038 looked for, against the stand-in API server.

mod common;

use std::time::Duration;

use common::{Env, connect, get, text};
use http::StatusCode;
use http_body_util::BodyExt as _;
use limen_e2e::eventually;
use limen_proto::v1::auth_client::AuthClient;
use limen_proto::v1::{LockUserRequest, LogoutRequest};
use limen_testkit::users::DEVELOPER;

/// A `watch` is one long response. A lock must end it, as it ends an SSH
/// session, and the API server must see the connection go.
#[tokio::test(flavor = "multi_thread")]
async fn a_lock_ends_a_streaming_response() {
    let Some(mut env) = Env::start().await else {
        return;
    };
    let dev = env.d.login(DEVELOPER, &["ops"]).await.expect("developer");
    let mut conn = connect(&env.d, env.d.proxy_addr, Some(dev.clone())).await;
    let response = conn
        .send_request(get("/k8s/eks-dev/api/v1/pods?watch=true"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    let first = body.frame().await.expect("a frame").expect("ok");
    assert!(first.into_data().is_ok_and(|d| d.starts_with(b"{")));
    assert_eq!(
        env.api.watching.load(std::sync::atomic::Ordering::SeqCst),
        1
    );

    env.admin
        .lock_user(LockUserRequest {
            username: DEVELOPER.into(),
            reason: "review".into(),
        })
        .await
        .expect("lock");
    let ended = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match body.frame().await {
                None | Some(Err(_)) => return,
                Some(Ok(_)) => {}
            }
        }
    })
    .await;
    assert!(ended.is_ok(), "the watch outlived the lock");
    eventually(
        Duration::from_secs(5),
        "the API server sees the watch go",
        || async { env.api.watching.load(std::sync::atomic::Ordering::SeqCst) == 0 },
    )
    .await;
}

/// `limen logout` ends the login everywhere: the proxy and workers refuse its
/// certificate, an open `watch` on it ends, the same user's other login is
/// untouched, and the logout is in the trail.
#[tokio::test(flavor = "multi_thread")]
async fn logout_ends_that_login_only() {
    let Some(env) = Env::start().await else {
        return;
    };
    let laptop = env
        .d
        .login(DEVELOPER, &["ops"])
        .await
        .expect("laptop login");
    let ci_box = env
        .d
        .login(DEVELOPER, &["ops"])
        .await
        .expect("second login");

    let mut conn = connect(&env.d, env.d.proxy_addr, Some(laptop.clone())).await;
    let response = conn
        .send_request(get("/k8s/eks-dev/api/v1/pods?watch=true"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    body.frame().await.expect("a frame").expect("ok");

    let ended = AuthClient::new(env.d.proxy_channel(Some(laptop.clone())))
        .logout(LogoutRequest {})
        .await
        .expect("logout")
        .into_inner();
    assert!(ended.revoked && !ended.login_id.is_empty());
    // Idempotent: a second logout is not an error.
    let again = AuthClient::new(env.d.proxy_channel(Some(laptop.clone())))
        .logout(LogoutRequest {})
        .await
        .expect("logout again")
        .into_inner();
    assert!(!again.revoked);

    // The open watch ends.
    let cut = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match body.frame().await {
                None | Some(Err(_)) => return,
                Some(Ok(_)) => {}
            }
        }
    })
    .await;
    assert!(cut.is_ok(), "the watch outlived the logout");

    // New requests with the logged-out certificate are refused, and say why.
    eventually(
        Duration::from_secs(20),
        "the proxy refuses the login",
        || async {
            let mut conn = connect(&env.d, env.d.proxy_addr, Some(laptop.clone())).await;
            let (status, body) = text(
                conn.send_request(get("/k8s/eks-dev/api/v1/namespaces/dev/pods"))
                    .await
                    .expect("response"),
            )
            .await;
            status == StatusCode::FORBIDDEN && body.contains("logged out")
        },
    )
    .await;

    // The same user's other login carries on.
    let mut conn = connect(&env.d, env.d.proxy_addr, Some(ci_box)).await;
    let (status, body) = text(
        conn.send_request(get("/k8s/eks-dev/api/v1/namespaces/dev/pods"))
            .await
            .expect("response"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    eventually(
        Duration::from_secs(20),
        "auth.logout is audited",
        || async {
            common::read_jsonl(&env.d).iter().any(|e| {
                e["kind"] == "auth.logout"
                    && e["user"] == DEVELOPER
                    && e["data"]["login_id"] == ended.login_id
            })
        },
    )
    .await;
}

/// A worker that is shutting down gives its sessions until the drain timeout.
/// An exec is a stream that outlives the request, so it needs its own end:
/// the session's drain handling stops at the upgrade.
#[tokio::test(flavor = "multi_thread")]
async fn a_worker_drain_ends_open_exec_streams() {
    let Some(env) = Env::start().await else {
        return;
    };
    let dev = env.d.login(DEVELOPER, &["ops"]).await.expect("developer");
    let mut conn = connect(&env.d, env.d.proxy_addr, Some(dev)).await;
    let mut response = conn
        .send_request(common::exec_upgrade(
            "/k8s/eks-dev/api/v1/namespaces/dev/pods/web/exec?command=sh&stdout=true",
        ))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    let mut io =
        hyper_util::rt::TokioIo::new(hyper::upgrade::on(&mut response).await.expect("upgrade"));
    let mut buf = [0u8; 1024];
    tokio::io::AsyncReadExt::read(&mut io, &mut buf)
        .await
        .expect("first frames");

    // SIGTERM: the e2e worker drains for one second, then ends what is left.
    // Without its own end the stream lingers well past that (about 15 s).
    env.worker.begin_stop();
    let ended = tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            match tokio::io::AsyncReadExt::read(&mut io, &mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    })
    .await;
    assert!(ended.is_ok(), "the exec outlived the worker's drain");
}

/// Hanging up on an idle watch must close the worker's connection to the API
/// server, even though the watch never sends a frame to notice it with.
#[tokio::test(flavor = "multi_thread")]
async fn hanging_up_closes_the_upstream_watch() {
    let Some(env) = Env::start().await else {
        return;
    };
    let dev = env.d.login(DEVELOPER, &["ops"]).await.expect("developer");
    let mut conns = Vec::new();
    for _ in 0..8 {
        let mut conn = connect(&env.d, env.d.proxy_addr, Some(dev.clone())).await;
        let response = conn
            .send_request(get("/k8s/eks-dev/api/v1/pods?watch=true&idle=1"))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        conns.push((conn, response));
    }
    eventually(Duration::from_secs(5), "eight open watches", || async {
        env.api.watching.load(std::sync::atomic::Ordering::SeqCst) == 8
    })
    .await;
    drop(conns);
    eventually(
        Duration::from_secs(10),
        "the watches close upstream",
        || async { env.api.watching.load(std::sync::atomic::Ordering::SeqCst) == 0 },
    )
    .await;
}

/// The audit trail and the API server must read a path the same way.
#[tokio::test(flavor = "multi_thread")]
async fn odd_paths_never_reach_the_cluster() {
    let Some(env) = Env::start().await else {
        return;
    };
    let dev = env.d.login(DEVELOPER, &["ops"]).await.expect("developer");
    let before = env.api.seen().len();
    for path in [
        "/k8s/eks-dev/api/v1/../../x",
        "/k8s/eks-dev/api/./v1/pods",
        "/k8s/eks-dev/api//v1/pods",
        "/k8s/eks-dev/api/v1/namespaces/dev/pods/%2e%2e/%2e%2e/secrets",
        "/k8s/eks-dev/api/v1/%2Fpods",
    ] {
        let mut conn = connect(&env.d, env.d.proxy_addr, Some(dev.clone())).await;
        let (status, _) = text(conn.send_request(get(path)).await.expect("response")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
    }
    assert_eq!(env.api.seen().len(), before);
}

/// A broken worker is a 503 the operator can act on, not a "Forbidden" that
/// sends the user to ask for access they have.
#[tokio::test(flavor = "multi_thread")]
async fn worker_problems_are_service_errors_not_denials() {
    let Some(mut env) = Env::start().await else {
        return;
    };
    let dev = env.d.login(DEVELOPER, &["ops"]).await.expect("developer");

    // The token file is gone (the first request has not cached it yet).
    std::fs::remove_file(&env.token_file).expect("remove token");
    let mut conn = connect(&env.d, env.d.proxy_addr, Some(dev.clone())).await;
    let (status, body) = text(
        conn.send_request(get("/k8s/eks-dev/api/v1/namespaces/dev/pods"))
            .await
            .expect("response"),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(env.api.seen().is_empty(), "the cluster was not called");

    // A cluster this worker is not configured for.
    let mut conn = connect(&env.d, env.d.proxy_addr, Some(dev.clone())).await;
    let (status, body) = text(
        conn.send_request(get("/k8s/eks-other/api/v1/pods"))
            .await
            .expect("response"),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(body.contains("serves the cluster"), "{body}");

    // A worker that serves no cluster at all.
    let _plain = env.start_plain_worker().await;
    let mut conn = connect(&env.d, env.d.proxy_addr, Some(dev)).await;
    let (status, body) = text(
        conn.send_request(get("/k8s/eks-nokube/api/v1/pods"))
            .await
            .expect("response"),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(body.contains("does not serve Kubernetes"), "{body}");
    assert!(
        env.api.seen().is_empty(),
        "none of them reached the cluster"
    );
}

/// The API server refusing the worker's own token is the operator's fault.
/// A 401 passed through would make kubectl re-run the login plugin and tell
/// the user to log in again.
#[tokio::test(flavor = "multi_thread")]
async fn a_rejected_worker_token_is_a_service_error() {
    let Some(env) = Env::start().await else {
        return;
    };
    let dev = env.d.login(DEVELOPER, &["ops"]).await.expect("developer");
    std::fs::write(&env.token_file, "revoked-token\n").expect("rotate token");
    let mut conn = connect(&env.d, env.d.proxy_addr, Some(dev)).await;
    let (status, body) = text(
        conn.send_request(get("/k8s/eks-dev/api/v1/namespaces/dev/pods"))
            .await
            .expect("response"),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(body.contains("rejected the worker's credential"), "{body}");
}

/// A user named like a built-in identity would inherit that identity's RBAC
/// (`system:kube-scheduler`, `system:serviceaccount:…`). Whatever the IdP
/// says, the cluster must not see the name.
#[tokio::test(flavor = "multi_thread")]
async fn built_in_identities_cannot_be_impersonated() {
    let Some(env) = Env::start().await else {
        return;
    };
    for name in [
        "system:kube-scheduler",
        "system:serviceaccount:kube-system:x",
    ] {
        let who = env.d.login(name, &["ops"]).await.expect("login");
        let mut conn = connect(&env.d, env.d.proxy_addr, Some(who)).await;
        let (status, body) = text(
            conn.send_request(get("/k8s/eks-dev/api/v1/namespaces/dev/pods"))
                .await
                .expect("response"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{name}: {body}");
    }
    assert!(env.api.seen().is_empty(), "the cluster saw none of them");
}

/// Names are not always ASCII; the API server takes UTF-8 impersonation
/// headers as they are.
#[tokio::test(flavor = "multi_thread")]
async fn non_ascii_user_names_are_impersonated_intact() {
    let Some(env) = Env::start().await else {
        return;
    };
    let who = env
        .d
        .login("josé.müller@example.com", &["ops"])
        .await
        .expect("login");
    let mut conn = connect(&env.d, env.d.proxy_addr, Some(who)).await;
    let (status, body) = text(
        conn.send_request(get("/k8s/eks-dev/api/v1/namespaces/dev/pods"))
            .await
            .expect("response"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let seen = env.api.seen();
    assert_eq!(
        seen.last().expect("seen").headers_named("impersonate-user"),
        ["josé.müller@example.com"]
    );
}

/// The API server dies after taking a write. The user gets a 502, and the
/// request is in the trail: it may have been applied.
#[tokio::test(flavor = "multi_thread")]
async fn a_request_that_fails_upstream_is_still_audited() {
    let Some(env) = Env::start().await else {
        return;
    };
    let dev = env.d.login(DEVELOPER, &["ops"]).await.expect("developer");
    let mut conn = connect(&env.d, env.d.proxy_addr, Some(dev)).await;
    let (status, body) = text(
        conn.send_request(get("/k8s/eks-dev/api/v1/namespaces/dev/configmaps/reset"))
            .await
            .expect("response"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    eventually(
        Duration::from_secs(20),
        "the failed request is audited",
        || async {
            common::read_jsonl(&env.d).iter().any(|e| {
                e["kind"] == "kube.request"
                    && e["data"]["status"] == 502
                    && e["data"]["error"] == "request failed"
                    && e["data"]["name"] == "reset"
                    && e["user"] == DEVELOPER
            })
        },
    )
    .await;
}

/// ADR-0004: the worker is tunnelled to proxy A, the user lands on proxy B.
#[tokio::test(flavor = "multi_thread")]
async fn kubectl_through_a_peer_proxy() {
    let Some(env) = Env::start().await else {
        return;
    };
    let (proxy_b, addr_b) = env.d.start_extra_proxy("proxy-b").await;
    assert!(proxy_b.proxy.tunnels.summaries().is_empty());
    eventually(
        Duration::from_secs(15),
        "proxy B has the policy",
        || async { proxy_b.proxy.policy_version() == Some(env.policy_version) },
    )
    .await;
    let dev = env.d.login(DEVELOPER, &["ops"]).await.expect("developer");
    // Proxy A reports its tunnels within a moment; B caches the registry for 5s.
    let mut last = String::new();
    for _ in 0..40 {
        let mut conn = connect(&env.d, addr_b, Some(dev.clone())).await;
        let (status, body) = text(
            conn.send_request(get("/k8s/eks-dev/api/v1/namespaces/dev/pods"))
                .await
                .expect("response"),
        )
        .await;
        if status == StatusCode::OK {
            assert!(body.contains("PodList"));
            let seen = env.api.seen();
            assert_eq!(
                seen.last().expect("seen").headers_named("impersonate-user"),
                [DEVELOPER]
            );
            return;
        }
        last = format!("{status} {body}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("no answer through proxy B: {last}");
}

/// Many users' requests at once, over many connections: none lost, none
/// crossed, and every one audited.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_requests_are_all_served_and_audited() {
    let Some(env) = Env::start().await else {
        return;
    };
    let dev = env.d.login(DEVELOPER, &["ops"]).await.expect("developer");
    let mut tasks = Vec::new();
    for _ in 0..64 {
        let (d_addr, dev) = (env.d.proxy_addr, dev.clone());
        let ca = std::fs::read_to_string(env.d.ca_file()).expect("ca");
        tasks.push(tokio::spawn(async move {
            let roots = limen_tunnel::tls::certs_from_pem(&ca).expect("roots");
            let tls =
                limen_tunnel::tls::client_config(&roots, Some(dev), &[limen_tunnel::alpn::HTTP1])
                    .expect("tls");
            let tcp = tokio::net::TcpStream::connect(d_addr).await.expect("tcp");
            let tls = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls))
                .connect("localhost".try_into().expect("name"), tcp)
                .await
                .expect("handshake");
            let (mut sender, conn) =
                hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
                    .await
                    .expect("http");
            tokio::spawn(conn);
            let mut ok = 0;
            // Several requests on one connection: each is its own session.
            for _ in 0..5 {
                let (status, _) = text(
                    sender
                        .send_request(get("/k8s/eks-dev/api/v1/namespaces/dev/pods"))
                        .await
                        .expect("response"),
                )
                .await;
                if status == StatusCode::OK {
                    ok += 1;
                }
            }
            ok
        }));
    }
    let mut total = 0;
    for t in tasks {
        total += t.await.expect("task");
    }
    assert_eq!(total, 64 * 5, "every request was served");
    assert_eq!(env.api.seen().len(), 64 * 5);
    eventually(Duration::from_secs(20), "every request audited", || async {
        common::read_jsonl(&env.d)
            .iter()
            .filter(|e| e["kind"] == "kube.request" && e["data"]["status"] == 200)
            .count()
            == 64 * 5
    })
    .await;
}

/// The grant's lifetime (`max_session_ttl`) ends a watch and a recorded exec
/// stream, as it ends an SSH session.
#[tokio::test(flavor = "multi_thread")]
async fn a_short_grant_ends_streams() {
    let Some(env) = Env::start().await else {
        return;
    };
    let user = env
        .d
        .login("short@example.com", &["short"])
        .await
        .expect("login");

    let mut conn = connect(&env.d, env.d.proxy_addr, Some(user.clone())).await;
    let response = conn
        .send_request(get("/k8s/eks-dev/api/v1/pods?watch=true"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    let started = std::time::Instant::now();
    let ended = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match body.frame().await {
                None | Some(Err(_)) => return,
                Some(Ok(_)) => {}
            }
        }
    })
    .await;
    assert!(ended.is_ok(), "the watch outlived its grant");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "{:?}",
        started.elapsed()
    );

    let mut conn = connect(&env.d, env.d.proxy_addr, Some(user)).await;
    let mut response = conn
        .send_request(common::exec_upgrade(
            "/k8s/eks-dev/api/v1/namespaces/dev/pods/web/exec?command=sh&stdout=true",
        ))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    let _io = hyper::upgrade::on(&mut response).await.expect("upgrade");
    eventually(
        Duration::from_secs(20),
        "the stream ends at the grant's end",
        || async {
            common::read_jsonl(&env.d).iter().any(|e| {
                e["kind"] == "session.end"
                    && e["data"]["login"] == "exec"
                    && e["data"]["reason"] == "max_session_ttl reached"
            })
        },
    )
    .await;
}

/// Taking access away in policy applies to the very next request, with no
/// new login.
#[tokio::test(flavor = "multi_thread")]
async fn removing_access_applies_to_the_next_request() {
    let Some(mut env) = Env::start().await else {
        return;
    };
    let dev = env.d.login(DEVELOPER, &["ops"]).await.expect("developer");
    let mut conn = connect(&env.d, env.d.proxy_addr, Some(dev.clone())).await;
    let (status, _) = text(
        conn.send_request(get("/k8s/eks-dev/api/v1/namespaces/dev/pods"))
            .await
            .expect("response"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let revoked = common::POLICY.replacen(
        "- resources: { kind: [kubernetes], labels: { env: [test] } }\n      kube: { groups: [\"limen:view\", \"limen:edit\"] }",
        "- resources: { kind: [kubernetes], labels: { env: [nowhere] } }\n      kube: { groups: [\"limen:view\", \"limen:edit\"] }",
        1,
    );
    assert_ne!(revoked, common::POLICY, "the edit applied");
    let applied = env
        .admin
        .apply_policy(limen_proto::v1::ApplyPolicyRequest {
            require_tests: false,
            sources: vec![limen_proto::v1::PolicySource {
                name: "policy.yaml".into(),
                content: revoked,
            }],
            dry_run: false,
            source_ref: String::new(),
        })
        .await
        .expect("apply")
        .into_inner();
    eventually(
        Duration::from_secs(15),
        "the new policy everywhere",
        || async {
            env.d.proxy().policy_version() == Some(applied.version)
                && env.worker.worker.policy_version() == Some(applied.version)
        },
    )
    .await;
    let mut conn = connect(&env.d, env.d.proxy_addr, Some(dev)).await;
    let (status, _) = text(
        conn.send_request(get("/k8s/eks-dev/api/v1/namespaces/dev/pods"))
            .await
            .expect("response"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
