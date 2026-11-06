//! ADR-0011 for Kubernetes: with the control plane down, a new request is decided from the
//! cached policy snapshot inside the grace period and refused after it, and a long response that
//! is already streaming is not cut. Runs against the stand-in API server (`common::Env`).

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use common::{Env, connect, get, text};
use http::StatusCode;
use http_body_util::BodyExt as _;
use limen_testkit::users::DEVELOPER;

#[tokio::test(flavor = "multi_thread")]
async fn kube_requests_follow_the_grace_period_and_open_watches_survive() {
    let Some(mut env) = Env::start().await else {
        return;
    };
    let dev = env.d.login(DEVELOPER, &["ops"]).await.expect("developer");

    // A watch opened before the outage.
    let mut conn = connect(&env.d, env.d.proxy_addr, Some(dev.clone())).await;
    let response = conn
        .send_request(get("/k8s/eks-dev/api/v1/pods?watch=true"))
        .await
        .expect("watch response");
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    let first = body.frame().await.expect("a frame").expect("ok");
    assert!(first.into_data().is_ok_and(|d| d.starts_with(b"{")));

    env.d.stop_control_plane().await;

    // Inside the grace period (3s in tests) a new request, on a new connection, is allowed.
    let mut fresh = connect(&env.d, env.d.proxy_addr, Some(dev.clone())).await;
    let (status, reply) = text(
        fresh
            .send_request(get("/k8s/eks-dev/api/v1/namespaces/dev/pods"))
            .await
            .expect("response in grace"),
    )
    .await;
    eprintln!("kube in grace: {status} {reply}");
    assert_eq!(
        status,
        StatusCode::OK,
        "a new request inside the grace period: {reply}"
    );

    // Past it, nothing can be decided: refused, and never sent to the cluster.
    tokio::time::sleep(Duration::from_secs(5)).await;
    let before = env.api.seen().len();
    let mut late = connect(&env.d, env.d.proxy_addr, Some(dev)).await;
    let (status, reply) = text(
        late.send_request(get("/k8s/eks-dev/api/v1/namespaces/dev/pods"))
            .await
            .expect("response past the grace"),
    )
    .await;
    eprintln!("kube after grace: {status} {reply}");
    assert_ne!(status, StatusCode::OK, "past the grace period: {reply}");
    assert!(reply.contains("can't be decided"), "{reply}");
    assert_eq!(
        env.api.seen().len(),
        before,
        "a refused request never reaches the cluster"
    );

    // The watch that was open is still open, and the cluster still sees it.
    assert_eq!(env.api.watching.load(Ordering::SeqCst), 1);
    let next = tokio::time::timeout(Duration::from_millis(500), body.frame()).await;
    assert!(
        !matches!(next, Ok(None | Some(Err(_)))),
        "the open watch was not cut: {next:?}"
    );
}
