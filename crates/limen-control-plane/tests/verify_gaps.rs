//! Phase 5: the verifier reports per-producer `seq` gaps (events lost between
//! a producer and S3) and counts distinct events, so the at-least-once
//! duplicates from retries and handoff neither hide a gap nor inflate counts.
//!
//! Needs `LIMEN_TEST_S3_ENDPOINT` and AWS credentials (see `audit_sinks.rs`).

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use limen_ca::{CaPurpose, CertificateAuthority, ComponentCertRequest, FileSigner};
use limen_control_plane::sinks::S3Sink;
use limen_control_plane::verify::{SeqGap, verify_bucket};
use limen_core::identity::ComponentKind;
use limen_session::envelope::EnvelopeSigner;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

fn event(component: &str, instance_id: &str, seq: u64) -> Vec<u8> {
    let producer = limen_audit::Producer {
        component: component.into(),
        instance_id: instance_id.into(),
        seq,
    };
    let event = limen_audit::Event::new(
        limen_audit::EventKind::SshExec,
        producer,
        serde_json::json!({ "seq": seq }),
    );
    serde_json::to_vec(&event).expect("json")
}

#[tokio::test(flavor = "multi_thread")]
async fn seq_gaps_are_reported_and_duplicates_are_not() {
    let Some(endpoint) = limen_testkit::s3_endpoint() else {
        return;
    };
    let client = limen_control_plane::sinks::s3_client(Some(&endpoint), true).await;
    let bucket = format!("limen-test-{}", uuid::Uuid::now_v7().simple());
    client
        .create_bucket()
        .bucket(&bucket)
        .send()
        .await
        .expect("create bucket");

    let ca = CertificateAuthority::create_self_signed(
        CaPurpose::Internal,
        Arc::new(FileSigner::generate().expect("key")),
    )
    .await
    .expect("ca");
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
    let csr = CertificateParams::default()
        .serialize_request(&key)
        .expect("csr");
    let cert = ca
        .issue_component(ComponentCertRequest {
            csr_der: csr.der().to_vec(),
            kind: ComponentKind::ControlPlane,
            id: "cp-test".into(),
            dns_names: vec![],
            labels: BTreeMap::new(),
            ttl: Duration::from_secs(600),
        })
        .await
        .expect("issue");
    let signer = EnvelopeSigner::new(&key.serialize_pem(), cert.der.to_vec()).expect("signer");
    let slot = Arc::new(RwLock::new(Some(Arc::new(signer))));

    // Two writers (as after a handoff). Producer proxy-1/a: seq 1, 2, 4 with
    // seq 2 shipped twice (same event, by both writers): one gap, 3..=3.
    // Producer proxy-1/b (the same proxy after a restart: new boot id, seq
    // from 0 again): 0, 1, no gap. Producer worker-1/a: 0, 3, 4, 7 -> 1..=2, 5..=6.
    let dup = event("proxy", "proxy-1/a", 2);
    let a = S3Sink::new(
        client.clone(),
        bucket.clone(),
        String::new(),
        None,
        "cp-a".into(),
        slot.clone(),
    );
    a.ship(vec![
        (0, event("proxy", "proxy-1/a", 1)),
        (1, dup.clone()),
        (2, event("proxy", "proxy-1/b", 0)),
        (3, event("worker", "worker-1/a", 0)),
        (4, event("worker", "worker-1/a", 3)),
    ])
    .await
    .expect("ship a");
    let b = S3Sink::new(
        client.clone(),
        bucket.clone(),
        String::new(),
        None,
        "cp-b".into(),
        slot,
    );
    b.ship(vec![
        (0, dup),
        (1, event("proxy", "proxy-1/a", 4)),
        (2, event("proxy", "proxy-1/b", 1)),
        (3, event("worker", "worker-1/a", 7)),
        (4, event("worker", "worker-1/a", 4)),
    ])
    .await
    .expect("ship b");

    let report = verify_bucket(&client, &bucket, "", ca.cert_der())
        .await
        .expect("verify");
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    assert_eq!(report.writers, 2);
    assert_eq!(report.records, 10, "every line in every batch");
    assert_eq!(report.events, 9, "the duplicate is counted once");
    let gap = |component: &str, instance_id: &str, from: u64, to: u64| SeqGap {
        component: component.into(),
        instance_id: instance_id.into(),
        missing_from: from,
        missing_to: to,
    };
    assert_eq!(
        report.seq_gaps,
        vec![
            gap("proxy", "proxy-1/a", 3, 3),
            gap("worker", "worker-1/a", 1, 2),
            gap("worker", "worker-1/a", 5, 6),
        ]
    );
    assert!(!report.ok(), "a gap fails verification");
}
