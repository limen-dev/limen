//! ADR-0003: the worker dials the proxy, then serves gRPC on that connection.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures::{Stream, StreamExt};
use limen_ca::{CaPurpose, CertificateAuthority, ComponentCertRequest, FileSigner};
use limen_core::identity::ComponentKind;
use limen_proto::v1::worker_tunnel_client::WorkerTunnelClient;
use limen_proto::v1::worker_tunnel_server::{WorkerTunnel, WorkerTunnelServer};
use limen_proto::v1::{PingRequest, PingResponse, TunnelFrame, tunnel_frame::Frame};
use limen_tunnel::serve::{H2Settings, serve_h2};
use limen_tunnel::tls::{ClientAuth, Identity, client_config, server_config};
use limen_tunnel::tunnel::TunnelChannel;
use limen_tunnel::{PeerInfo, alpn};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tonic::{Request, Response, Status, Streaming};

struct Worker {
    id: String,
}

#[tonic::async_trait]
impl WorkerTunnel for Worker {
    type OpenSessionStream = Pin<Box<dyn Stream<Item = Result<TunnelFrame, Status>> + Send>>;

    async fn open_session(
        &self,
        request: Request<Streaming<TunnelFrame>>,
    ) -> Result<Response<Self::OpenSessionStream>, Status> {
        // Echo data frames back, uppercased, to prove both directions stream.
        let inbound = request.into_inner();
        let out = inbound.map(|frame| {
            let frame = frame?;
            Ok(match frame.frame {
                Some(Frame::Data(d)) => TunnelFrame {
                    frame: Some(Frame::Data(d.to_ascii_uppercase())),
                },
                other => TunnelFrame { frame: other },
            })
        });
        Ok(Response::new(Box::pin(out)))
    }

    async fn ping(&self, request: Request<PingRequest>) -> Result<Response<PingResponse>, Status> {
        let peer = request.extensions().get::<PeerInfo>().cloned();
        assert!(peer.is_some(), "PeerInfo must be attached to every request");
        Ok(Response::new(PingResponse {
            worker_id: self.id.clone(),
            draining: false,
        }))
    }
}

async fn identity(
    ca: &CertificateAuthority,
    kind: ComponentKind,
    id: &str,
    dns: &[&str],
) -> Identity {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
    let csr = CertificateParams::default()
        .serialize_request(&key)
        .expect("csr");
    let issued = ca
        .issue_component(ComponentCertRequest {
            csr_der: csr.der().to_vec(),
            kind,
            id: id.into(),
            dns_names: dns.iter().map(|s| (*s).to_owned()).collect(),
            labels: std::collections::BTreeMap::new(),
            ttl: Duration::from_secs(600),
        })
        .await
        .expect("issue");
    Identity::from_pem(&issued.pem, &key.serialize_pem()).expect("identity")
}

#[tokio::test]
async fn worker_serves_grpc_over_outbound_connection() {
    let ca = CertificateAuthority::create_self_signed(
        CaPurpose::Internal,
        Arc::new(FileSigner::generate().expect("key")),
    )
    .await
    .expect("ca");
    let roots = vec![ca.cert_der().clone()];
    let proxy_id = identity(&ca, ComponentKind::Proxy, "proxy-1", &["localhost"]).await;
    let worker_id = identity(&ca, ComponentKind::Worker, "worker-1", &[]).await;

    // Proxy side: accept one TLS connection and act as the gRPC client.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let acceptor = TlsAcceptor::from(Arc::new(
        server_config(proxy_id, &roots, ClientAuth::Required, &[alpn::TUNNEL])
            .expect("server config"),
    ));
    let ca_der = ca.cert_der().clone();
    let proxy = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let tls = acceptor.accept(tcp).await.expect("handshake");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(alpn::TUNNEL));
        let peer = PeerInfo::from_tls(&tls, None);
        let worker =
            limen_ca::verify::verify_component(peer.leaf().expect("client cert"), &ca_der, false)
                .expect("worker identity");
        assert_eq!(worker.kind, ComponentKind::Worker);

        let (channel, conn) = TunnelChannel::handshake(tls, H2Settings::default())
            .await
            .expect("h2 handshake");
        let conn = tokio::spawn(conn);
        let mut client = WorkerTunnelClient::new(channel.clone());

        let pong = client
            .ping(PingRequest {})
            .await
            .expect("ping")
            .into_inner();
        assert_eq!(pong.worker_id, "worker-1");

        let frames = tokio_stream::iter(["hello", "tunnel"].map(|s| TunnelFrame {
            frame: Some(Frame::Data(s.as_bytes().to_vec())),
        }));
        let mut replies = client
            .open_session(frames)
            .await
            .expect("open")
            .into_inner();
        let mut got = Vec::new();
        while let Some(frame) = replies.next().await {
            if let Some(Frame::Data(d)) = frame.expect("frame").frame {
                got.push(String::from_utf8(d).expect("utf8"));
            }
        }
        assert_eq!(got, ["HELLO", "TUNNEL"]);
        drop(client);
        drop(channel);
        conn.abort();
    });

    // Worker side: dial out, then serve.
    let connector = TlsConnector::from(Arc::new(
        client_config(&roots, Some(worker_id), &[alpn::TUNNEL]).expect("client config"),
    ));
    let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let tls = connector
        .connect("localhost".try_into().expect("name"), tcp)
        .await
        .expect("worker handshake");
    let routes = tonic::service::Routes::new(WorkerTunnelServer::new(Worker {
        id: "worker-1".into(),
    }))
    .prepare();
    let peer = PeerInfo {
        remote_addr: Some(addr),
        client_certs: vec![],
    };
    let served = tokio::time::timeout(
        Duration::from_secs(10),
        serve_h2(tls, peer, routes, H2Settings::default()),
    )
    .await;
    proxy.await.expect("proxy task");
    // The worker's serve loop returns once the proxy closes the connection,
    // which is the worker's signal to reconnect.
    assert!(
        served.is_ok(),
        "serve_h2 must return when the proxy goes away"
    );
}

#[tokio::test]
async fn proxy_rejects_worker_from_another_ca() {
    let ca = CertificateAuthority::create_self_signed(
        CaPurpose::Internal,
        Arc::new(FileSigner::generate().expect("key")),
    )
    .await
    .expect("ca");
    let rogue = CertificateAuthority::create_self_signed(
        CaPurpose::Internal,
        Arc::new(FileSigner::generate().expect("key")),
    )
    .await
    .expect("rogue ca");
    let proxy_id = identity(&ca, ComponentKind::Proxy, "proxy-1", &["localhost"]).await;
    let rogue_worker = identity(&rogue, ComponentKind::Worker, "evil", &[]).await;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let acceptor = TlsAcceptor::from(Arc::new(
        server_config(
            proxy_id,
            &[ca.cert_der().clone()],
            ClientAuth::Required,
            &[alpn::TUNNEL],
        )
        .expect("cfg"),
    ));
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        acceptor.accept(tcp).await.map(|_| ())
    });
    // The rogue worker trusts the real CA (so it accepts the proxy) but presents a rogue cert.
    let connector = TlsConnector::from(Arc::new(
        client_config(
            &[ca.cert_der().clone()],
            Some(rogue_worker),
            &[alpn::TUNNEL],
        )
        .expect("cfg"),
    ));
    let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let client_side = connector
        .connect("localhost".try_into().expect("name"), tcp)
        .await;
    let server_side = server.await.expect("join");
    // In TLS 1.3 the client may finish before the server rejects its cert, so
    // the server's result is what counts.
    assert!(
        server_side.is_err(),
        "server must reject a client cert from an unknown CA (client: {:?})",
        client_side.is_ok()
    );
}
