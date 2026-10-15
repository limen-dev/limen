//! Phase 3: audit to S3 and Datadog survives either sink going away, with
//! no event lost, and the S3 trail is tamper-evident.
//!
//! Needs `LIMEN_TEST_DATABASE_URL`, `LIMEN_TEST_S3_ENDPOINT` (`SeaweedFS` from
//! the dev stack: `http://localhost:8333`), and AWS credentials in the
//! environment (the dev stack's `SeaweedFS` accepts `test` / `test`, see
//! `deploy/compose/s3/s3.json`).

mod common;

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::time::Duration;

use common::Harness;
use limen_testkit::fake_datadog;
use limen_testkit::toggle_proxy::ToggleProxy;

const DD_KEY: &str = "test-dd-key";

async fn s3_ids(client: &aws_sdk_s3::Client, bucket: &str) -> BTreeSet<String> {
    use std::io::Read;
    let mut ids = BTreeSet::new();
    let list = client
        .list_objects_v2()
        .bucket(bucket)
        .prefix("events/")
        .send()
        .await
        .expect("list");
    for obj in list.contents() {
        let key = obj.key().expect("key");
        let body = client
            .get_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .expect("get")
            .body
            .collect()
            .await
            .expect("body")
            .into_bytes();
        let mut text = String::new();
        flate2::read::GzDecoder::new(&body[..])
            .read_to_string(&mut text)
            .expect("gunzip");
        for line in text.lines() {
            let v: serde_json::Value = serde_json::from_str(line).expect("json");
            ids.insert(v["event_id"].as_str().expect("id").to_owned());
        }
    }
    ids
}

async fn wait_for(what: &str, secs: u64, mut check: impl AsyncFnMut() -> bool) {
    for _ in 0..secs * 4 {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("timed out waiting for {what}");
}

#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread")]
async fn no_event_lost_when_s3_and_datadog_go_away_and_trail_is_tamper_evident() {
    let Some(endpoint) = limen_testkit::s3_endpoint() else {
        return;
    };
    let direct = limen_control_plane::sinks::s3_client(Some(&endpoint), true).await;
    let bucket = format!("limen-test-{}", uuid::Uuid::now_v7().simple());
    direct
        .create_bucket()
        .bucket(&bucket)
        .send()
        .await
        .expect("create bucket");

    // Prefer IPv4: containers publish on 127.0.0.1, while `localhost` may resolve to ::1 first.
    let mut addrs: Vec<std::net::SocketAddr> =
        tokio::net::lookup_host(endpoint.trim_start_matches("http://"))
            .await
            .expect("resolve")
            .collect();
    addrs.sort_by_key(|a| !a.is_ipv4());
    let target = addrs[0];
    let s3_link = ToggleProxy::start(target).await;
    let (datadog, dd_url) = fake_datadog::start(DD_KEY).await;

    let Some(h) = Harness::start_with(&[
        format!("--audit-s3-bucket={bucket}"),
        format!("--audit-s3-endpoint=http://{}", s3_link.addr),
        "--audit-s3-path-style".into(),
        "--audit-s3-flush=1s".into(),
        format!("--datadog-logs-url={dd_url}"),
        format!("--datadog-api-key={DD_KEY}"),
        "--environment=test".into(),
    ])
    .await
    else {
        return;
    };

    // Events come from logins (the control plane's own) and from a proxy's
    // ingest. Logins are rate limited per client, so most come via ingest.
    let (proxy_id, proxy) = h.enroll_proxy().await;
    let mut ingest =
        limen_proto::v1::audit_ingest_client::AuditIngestClient::new(h.channel(Some(proxy)));
    let proxy_events = |n: usize| {
        (0..n)
            .map(|i| {
                let producer = limen_audit::Producer {
                    component: "proxy".into(),
                    instance_id: format!("{proxy_id}/boot"),
                    seq: i as u64,
                };
                let event = limen_audit::Event::new(
                    limen_audit::EventKind::SessionStart,
                    producer,
                    serde_json::json!({ "resource": "web-1", "i": i }),
                );
                serde_json::to_vec(&event).expect("json")
            })
            .collect::<Vec<_>>()
    };

    // Healthy: events reach both sinks.
    for i in 0..3 {
        h.login(&format!("user{i}@example.com"), &["admins"])
            .await
            .expect("login");
    }
    ingest
        .ingest(limen_proto::v1::IngestRequest {
            events: proxy_events(20),
        })
        .await
        .expect("ingest");
    let expected = || async {
        h.audit_events()
            .await
            .iter()
            .map(|e| e.event_id.to_string())
            .collect::<BTreeSet<_>>()
    };
    let first = expected().await;
    assert!(first.len() >= 23);
    wait_for("first events in S3", 30, async || {
        s3_ids(&direct, &bucket).await.is_superset(&first)
    })
    .await;
    wait_for("first events in Datadog", 30, async || {
        let got: BTreeSet<String> = datadog
            .received()
            .iter()
            .filter_map(|e| e["event_id"].as_str().map(str::to_owned))
            .collect();
        got.is_superset(&first)
    })
    .await;
    let sample = datadog.received().into_iter().next().expect("one entry");
    assert_eq!(sample["ddsource"], "limen");
    assert!(
        sample["ddtags"]
            .as_str()
            .expect("tags")
            .contains("env:test")
    );

    // Both sinks go away. Logins still succeed: events are durable in the spool.
    s3_link.set_up(false);
    datadog.fail_with(503);
    for i in 3..5 {
        h.login(&format!("user{i}@example.com"), &["admins"])
            .await
            .expect("login during sink outage");
    }
    ingest
        .ingest(limen_proto::v1::IngestRequest {
            events: proxy_events(30),
        })
        .await
        .expect("ingest during sink outage");
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        h.state.pipeline.spool.pending("s3") > 0,
        "events wait in the spool while S3 is down"
    );
    assert!(h.state.pipeline.spool.pending("datadog") > 0);

    // Back up: everything is delivered, nothing lost.
    s3_link.set_up(true);
    datadog.fail_with(0);
    let all = expected().await;
    assert!(all.len() >= 55);
    wait_for("every event in S3", 60, async || {
        s3_ids(&direct, &bucket).await.is_superset(&all)
    })
    .await;
    wait_for("every event in Datadog", 60, async || {
        let got: BTreeSet<String> = datadog
            .received()
            .iter()
            .filter_map(|e| e["event_id"].as_str().map(str::to_owned))
            .collect();
        got.is_superset(&all)
    })
    .await;

    // The trail verifies...
    let ca = h.internal_ca();
    let report = limen_control_plane::verify::verify_bucket(&direct, &bucket, "", &ca)
        .await
        .expect("verify");
    assert!(report.ok(), "{:?}", report.problems);
    assert!(report.events >= u64::try_from(all.len()).expect("fits"));
    assert!(report.batches >= 2);

    // ...and tampering is detected: edit a batch, then delete a manifest.
    let list = direct
        .list_objects_v2()
        .bucket(&bucket)
        .prefix("events/")
        .send()
        .await
        .expect("list");
    let victim = list.contents()[0].key().expect("key").to_owned();
    direct
        .put_object()
        .bucket(&bucket)
        .key(&victim)
        .body(Vec::from(&b"forged"[..]).into())
        .send()
        .await
        .expect("tamper");
    let report = limen_control_plane::verify::verify_bucket(&direct, &bucket, "", &ca)
        .await
        .expect("verify");
    assert!(
        report.problems.iter().any(|p| p.contains("modified")),
        "{:?}",
        report.problems
    );

    let manifests = direct
        .list_objects_v2()
        .bucket(&bucket)
        .prefix("manifests/")
        .send()
        .await
        .expect("list");
    let first_manifest = manifests.contents()[0].key().expect("key").to_owned();
    direct
        .delete_object()
        .bucket(&bucket)
        .key(&first_manifest)
        .send()
        .await
        .expect("delete");
    let report = limen_control_plane::verify::verify_bucket(&direct, &bucket, "", &ca)
        .await
        .expect("verify");
    assert!(
        report
            .problems
            .iter()
            .any(|p| p.contains("missing") || p.contains("chain broken")),
        "{:?}",
        report.problems
    );
}

/// ADR-0009: when the spool is full (sinks down for long enough), the default
/// failure mode refuses the actions it can't audit; `degrade` lets them through.
#[tokio::test(flavor = "multi_thread")]
async fn full_spool_fails_closed_by_default() {
    let Some(endpoint) = limen_testkit::s3_endpoint() else {
        return;
    };
    let _ = endpoint;
    // S3 pointed at a closed port: nothing ever drains the spool.
    let dead = ToggleProxy::start("127.0.0.1:9".parse().expect("addr")).await;
    dead.set_up(false);
    let Some(h) = Harness::start_with(&[
        "--audit-s3-bucket=never".into(),
        format!("--audit-s3-endpoint=http://{}", dead.addr),
        "--audit-s3-path-style".into(),
        "--audit-spool-max-bytes=4000".into(),
    ])
    .await
    else {
        return;
    };
    let mut refused = None;
    for i in 0..20 {
        match h.login(&format!("user{i}@example.com"), &["admins"]).await {
            Ok(_) => {}
            Err(status) => {
                refused = Some(status);
                break;
            }
        }
    }
    let status = refused.expect("a login is refused once the spool is full");
    assert_eq!(status.code(), tonic::Code::Unavailable, "{status}");
    assert!(status.message().contains("audit"), "{status}");
}

/// Recordings are streamed from disk (aws-chunked, signed), unlike batches.
#[tokio::test(flavor = "multi_thread")]
async fn recordings_stream_to_s3() {
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
    let sink = limen_control_plane::sinks::S3Sink::new(
        client.clone(),
        bucket.clone(),
        String::new(),
        None,
        "cp-test".into(),
        std::sync::Arc::default(),
    );

    // Several MiB, so the SDK splits the upload into chunks.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("rec.cast");
    let mut body = String::from("{\"version\":3,\"term\":{\"cols\":80,\"rows\":24}}\n");
    for i in 0..120_000 {
        let _ = writeln!(body, "[0.01, \"o\", \"line {i}\\r\\n\"]");
    }
    std::fs::write(&path, &body).expect("write");

    let uri = sink.put_recording("sess-1", &path).await.expect("upload");
    let key = uri
        .strip_prefix(&format!("s3://{bucket}/"))
        .expect("s3 uri");
    assert!(key.starts_with("recordings/dt=") && key.ends_with("/sess-1.cast"));
    let stored = client
        .get_object()
        .bucket(&bucket)
        .key(key)
        .send()
        .await
        .expect("get")
        .body
        .collect()
        .await
        .expect("body")
        .into_bytes();
    assert_eq!(stored.len(), body.len());
    assert_eq!(stored, body.as_bytes());
}
