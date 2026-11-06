//! The manifest a restarted control plane resumes its audit chain from is
//! checked: signed by this writer's own certificate, valid as of the time the
//! manifest records. No network (the S3 client is never used).

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use base64::Engine as _;
use limen_ca::{CaPurpose, CertificateAuthority, ComponentCertRequest, FileSigner};
use limen_control_plane::sinks::{Manifest, S3Sink, SignedManifest};
use limen_core::identity::ComponentKind;
use limen_session::envelope::{EnvelopeSigner, Purpose};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

async fn signer(ca: &CertificateAuthority, id: &str) -> EnvelopeSigner {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
    let csr = CertificateParams::default()
        .serialize_request(&key)
        .expect("csr");
    let cert = ca
        .issue_component(ComponentCertRequest {
            csr_der: csr.der().to_vec(),
            kind: ComponentKind::ControlPlane,
            id: id.into(),
            dns_names: vec![],
            labels: BTreeMap::new(),
            ttl: Duration::from_secs(600),
        })
        .await
        .expect("issue");
    EnvelopeSigner::new(&key.serialize_pem(), cert.der.to_vec()).expect("signer")
}

fn manifest(writer: &str, created_at: time::OffsetDateTime) -> Manifest {
    Manifest {
        version: 1,
        writer: writer.into(),
        seq: 0,
        object: "events/x".into(),
        sha256: String::new(),
        count: 0,
        first_event_id: String::new(),
        last_event_id: String::new(),
        prev_manifest_sha256: String::new(),
        created_at: created_at
            .format(&time::format_description::well_known::Rfc3339)
            .expect("time"),
    }
}

fn file(by: &EnvelopeSigner, manifest: &Manifest) -> Vec<u8> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let body = serde_json::to_string(manifest).expect("json");
    let sealed = by
        .sign(Purpose::AuditManifest, body.clone().into_bytes())
        .expect("sign");
    serde_json::to_vec(&SignedManifest {
        manifest: body,
        signature: b64.encode(&sealed.signature),
        signer_cert: b64.encode(&sealed.signer_cert_der),
    })
    .expect("file")
}

#[tokio::test]
async fn the_manifest_a_restart_resumes_from_is_signed_by_this_writer_as_of_its_time() {
    let ca = CertificateAuthority::create_self_signed(
        CaPurpose::Internal,
        Arc::new(FileSigner::generate().expect("key")),
    )
    .await
    .expect("ca");
    let mine = signer(&ca, "cp-a").await;
    let other = signer(&ca, "cp-b").await;
    let client = limen_control_plane::sinks::s3_client(Some("http://127.0.0.1:1"), true).await;
    let sink = S3Sink::new(
        client,
        "bucket".into(),
        String::new(),
        None,
        "cp-a".into(),
        Arc::new(RwLock::new(None)),
    )
    .with_internal_ca(ca.cert_der().to_vec());
    let now = time::OffsetDateTime::now_utc();

    let good = manifest("cp-a", now);
    assert_eq!(sink.signature_problem(&file(&mine, &good), &good), None);

    // Another control plane's valid signature does not make it this writer's.
    assert!(
        sink.signature_problem(&file(&other, &good), &good)
            .is_some()
    );
    // A planted manifest: right shape, no valid signature.
    let mut forged: SignedManifest = serde_json::from_slice(&file(&mine, &good)).expect("parse");
    forged.signature = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
    let forged = serde_json::to_vec(&forged).expect("file");
    assert!(sink.signature_problem(&forged, &good).is_some());
    // Signed long after the certificate expired: not valid as of that time.
    let late = manifest("cp-a", now + time::Duration::hours(2));
    assert!(sink.signature_problem(&file(&mine, &late), &late).is_some());
    // A manifest judged as of its own time stays valid after the certificate
    // is gone: that is what the check is for (the verifier test covers it).
}
