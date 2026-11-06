//! Phase 12/TB1: HTTP/2 stream abuse against the proxy's web listener,
//! before the client has any certificate. Pentest plan section 3, "Proxy
//! listener", the rapid-reset row (CVE-2023-44487 shape): a client opens many
//! streams and resets each one before reading the response, which on an
//! unguarded server can exhaust memory or CPU per reset faster than the
//! connection-level stream limit notices. `h2` is already a transitive
//! dependency of `hyper` (ADR-0012); this test drives it directly so it can
//! reset a stream mid-flight, which `hyper`'s own client never does.
//!
//! This does not cover a CONTINUATION flood or other malformed-frame attacks:
//! those need a frame built by hand, not a conforming client library, and are
//! tracked as not run in docs/pentest-plan.md.

use std::sync::Arc;
use std::time::Duration;

use h2::Reason;
use http::Request;
use hyper::body::Bytes;
use limen_e2e::Deployment;
use limen_tunnel::tls::client_config;

/// An anonymous (no client certificate) HTTP/2 connection to the proxy's web
/// listener, as a browser makes before sign-in.
async fn connect_h2(
    d: &Deployment,
) -> (h2::client::SendRequest<Bytes>, tokio::task::JoinHandle<()>) {
    let roots =
        limen_tunnel::tls::certs_from_pem(&std::fs::read_to_string(d.ca_file()).expect("ca"))
            .expect("roots");
    let tls = client_config(&roots, None, &[limen_tunnel::alpn::H2]).expect("tls");
    let tcp = tokio::net::TcpStream::connect(d.proxy_addr)
        .await
        .expect("tcp");
    let tls = tokio_rustls::TlsConnector::from(Arc::new(tls))
        .connect("localhost".try_into().expect("name"), tcp)
        .await
        .expect("tls handshake");
    let (send, conn) = h2::client::handshake(tls).await.expect("h2 handshake");
    let handle = tokio::spawn(async move {
        let _ = conn.await;
    });
    (send, handle)
}

fn get() -> Request<()> {
    Request::get("/")
        .header("host", "localhost")
        .body(())
        .expect("request")
}

/// Open many streams and cancel each one immediately, without reading the
/// response. The proxy must not wedge, panic, or stop accepting new
/// connections: the "fresh connection" check below is what the threat model
/// promises ("the proxy stays responsive").
#[tokio::test(flavor = "multi_thread")]
async fn rapid_stream_resets_do_not_wedge_the_proxy() {
    let Some(d) = Deployment::start().await else {
        return;
    };
    let (mut send, _conn) = connect_h2(&d).await;

    let attempted = 3_000;
    let mut opened = 0usize;
    for _ in 0..attempted {
        // The connection may refuse more streams (GOAWAY or a hit on h2's
        // own rapid-reset guard): stop, that is an acceptable refusal.
        let Ok(ready) = send.clone().ready().await else {
            break;
        };
        send = ready;
        let Ok((_response, mut stream)) = send.send_request(get(), true) else {
            break;
        };
        stream.send_reset(Reason::CANCEL);
        opened += 1;
    }
    assert!(opened > 0, "at least the first stream must open");

    // The proxy must still answer a well-behaved request, on a fresh
    // connection, promptly.
    let (mut send2, _conn2) = connect_h2(&d).await;
    let (response, _stream) = send2.send_request(get(), true).expect("send on fresh conn");
    let response = tokio::time::timeout(Duration::from_secs(5), response)
        .await
        .expect("the proxy answers within 5s of the abusive connection")
        .expect("a response, not a connection error");
    assert!(
        response.status().is_success()
            || response.status().is_redirection()
            || response.status() == http::StatusCode::NOT_FOUND,
        "the proxy serves a normal response after the reset flood: {}",
        response.status()
    );
}
