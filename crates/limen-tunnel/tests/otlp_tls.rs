//! OTLP export to an `https://` collector whose certificate is signed by a
//! private CA, trusted with `--otlp-ca-file`. The collector is a stand-in
//! TLS socket that records the request.

use std::sync::Arc;

use clap::Parser;
use limen_core::telemetry::LogArgs;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, PKCS_ECDSA_P256_SHA256,
    SanType,
};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;

#[derive(Parser)]
struct Cli {
    #[command(flatten)]
    log: LogArgs,
}

#[tokio::test(flavor = "multi_thread")]
async fn exports_to_an_https_collector_on_a_private_ca() {
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("ca key");
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "otlp test ca");
    let ca = ca_params.self_signed(&ca_key).expect("ca");
    let issuer = Issuer::new(ca_params, ca_key);

    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut leaf_params = CertificateParams::default();
    leaf_params.subject_alt_names = vec![SanType::IpAddress([127, 0, 0, 1].into())];
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).expect("leaf");

    let ca_file = std::env::temp_dir().join(format!("limen-otlp-ca-{}.pem", std::process::id()));
    std::fs::write(&ca_file, ca.pem()).expect("write ca");

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(leaf.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .expect("server config");
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let collector = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let mut tls = acceptor.accept(tcp).await.expect("tls handshake");
        let mut raw = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = tls.read(&mut buf).await.expect("read");
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
            if let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&raw[..end]).to_ascii_lowercase();
                let len = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length: "))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if raw.len() >= end + 4 + len {
                    break;
                }
            }
        }
        tls.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            .await
            .ok();
        tls.shutdown().await.ok();
        raw
    });

    let cli = Cli::parse_from([
        "x",
        "--otlp-endpoint",
        &format!("https://127.0.0.1:{port}"),
        "--otlp-ca-file",
        ca_file.to_str().expect("utf8 path"),
    ]);
    // The exporter flushes (a blocking call) when the guard drops.
    let flush = tokio::task::spawn_blocking(move || {
        let guard = cli.log.init("limen-otlp-tls-test");
        drop(limen_core::trace_span!("tls.check").entered());
        drop(guard);
    });
    flush.await.expect("flush");

    let raw = collector.await.expect("collector");
    std::fs::remove_file(&ca_file).ok();
    let text = String::from_utf8_lossy(&raw);
    assert!(text.starts_with("POST /v1/traces "), "{text}");
    assert!(raw.windows(9).any(|w| w == b"tls.check"));
}
