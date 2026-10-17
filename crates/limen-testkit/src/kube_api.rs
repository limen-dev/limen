//! A stand-in for a Kubernetes API server, for worker and end-to-end tests.
//!
//! It speaks TLS and HTTP/1.1, requires `Authorization: Bearer <token>`, and
//! records every request it sees (headers included) so tests can check what
//! the worker sent: its own credential, and the impersonation headers.
//!
//! - `GET /api/v1/namespaces/dev/pods` answers a `PodList`.
//! - A WebSocket upgrade on `.../exec` answers 101 and plays a short exec:
//!   `hello from pod` on stdout, `warning` on stderr, then a failure status
//!   with exit code 3. Whatever the client sends is kept in `client_bytes`.
//!
//! This is a test double. A real cluster (kind) is exercised by
//! `deploy/compose/demo-phase8.sh`.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper_util::rt::TokioIo;
use limen_kube::ws::{self, Sender};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// A request as the stand-in saw it.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub uri: String,
    /// Header names are lowercase. A header sent twice appears twice.
    pub headers: Vec<(String, String)>,
}

impl Seen {
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    #[must_use]
    pub fn headers_named(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct KubeApi {
    pub addr: SocketAddr,
    /// The certificate to trust, PEM. Valid for `localhost`.
    pub ca_pem: String,
    pub requests: Arc<Mutex<Vec<Seen>>>,
    /// Everything exec clients sent after the upgrade.
    pub client_bytes: Arc<Mutex<Vec<u8>>>,
}

impl KubeApi {
    /// # Panics
    /// On setup failures. Tests only.
    pub async fn start(token: &str) -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("cert");
        let ca_pem = cert.cert.pem();
        let key = rustls_pki_types::PrivateKeyDer::try_from(cert.signing_key.serialize_der())
            .expect("key");
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key)
        .expect("server config");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let api = Self {
            addr,
            ca_pem,
            requests: Arc::default(),
            client_bytes: Arc::default(),
        };
        let shared = api.clone();
        let token = token.to_owned();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (acceptor, shared, token) = (acceptor.clone(), shared.clone(), token.clone());
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let service = hyper::service::service_fn(move |req| {
                        let (shared, token) = (shared.clone(), token.clone());
                        async move { Ok::<_, Infallible>(shared.handle(&token, req)) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service)
                        .with_upgrades()
                        .await;
                });
            }
        });
        api
    }

    #[must_use]
    pub fn url(&self) -> String {
        format!("https://localhost:{}", self.addr.port())
    }

    #[must_use]
    pub fn seen(&self) -> Vec<Seen> {
        self.requests.lock().map(|r| r.clone()).unwrap_or_default()
    }

    fn handle(&self, token: &str, mut req: Request<Incoming>) -> Response<Full<Bytes>> {
        let seen = Seen {
            method: req.method().to_string(),
            uri: req.uri().to_string(),
            headers: req
                .headers()
                .iter()
                .map(|(n, v)| (n.as_str().to_owned(), v.to_str().unwrap_or("").to_owned()))
                .collect(),
        };
        if let Ok(mut all) = self.requests.lock() {
            all.push(seen.clone());
        }
        let reply = |status: StatusCode, body: &str| {
            let mut r = Response::new(Full::new(Bytes::from(body.to_owned())));
            *r.status_mut() = status;
            r
        };
        if seen.header("authorization") != Some(&format!("Bearer {token}")) {
            return reply(StatusCode::UNAUTHORIZED, r#"{"kind":"Status","code":401}"#);
        }
        let path = req.uri().path().to_owned();
        if path.ends_with("/exec") && seen.header("upgrade") == Some("websocket") {
            let on_upgrade = hyper::upgrade::on(&mut req);
            let client_bytes = Arc::clone(&self.client_bytes);
            tokio::spawn(async move {
                let Ok(upgraded) = on_upgrade.await else {
                    return;
                };
                let mut io = TokioIo::new(upgraded);
                let frame = |channel: u8, body: &[u8]| {
                    let mut payload = vec![channel];
                    payload.extend_from_slice(body);
                    ws::encode(Sender::Server, 0x2, &payload)
                };
                for wire in [
                    frame(1, b"hello from pod\r\n"),
                    frame(2, b"warning\r\n"),
                    frame(
                        3,
                        br#"{"status":"Failure","reason":"NonZeroExitCode","details":{"causes":[{"reason":"ExitCode","message":"3"}]}}"#,
                    ),
                ] {
                    if io.write_all(&wire).await.is_err() {
                        return;
                    }
                }
                let mut buf = [0u8; 1024];
                while let Ok(n) = io.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if let Ok(mut all) = client_bytes.lock() {
                        all.extend_from_slice(&buf[..n]);
                    }
                }
            });
            let mut r = Response::new(Full::new(Bytes::new()));
            *r.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
            let h = r.headers_mut();
            h.insert("connection", "Upgrade".parse().expect("header"));
            h.insert("upgrade", "websocket".parse().expect("header"));
            h.insert("sec-websocket-accept", "stub".parse().expect("header"));
            h.insert(
                "sec-websocket-protocol",
                "v4.channel.k8s.io".parse().expect("header"),
            );
            return r;
        }
        drop(req);
        match path.as_str() {
            "/api/v1/namespaces/dev/pods" => reply(
                StatusCode::OK,
                r#"{"kind":"PodList","apiVersion":"v1","items":[]}"#,
            ),
            _ => reply(StatusCode::NOT_FOUND, r#"{"kind":"Status","code":404}"#),
        }
    }
}
