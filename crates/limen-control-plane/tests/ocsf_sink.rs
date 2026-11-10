//! ADR-0049: the OCSF projection reaches its own bucket with every event, and
//! a broken OCSF sink cannot hold the audit spool back.
//!
//! Needs `LIMEN_TEST_DATABASE_URL` and `LIMEN_TEST_S3_ENDPOINT` (the dev stack,
//! see `audit_sinks.rs`). Without them the tests return early (not a pass:
//! CI runs them).

mod common;

use std::collections::BTreeSet;
use std::io::Read as _;
use std::time::Duration;

use common::Harness;

async fn create_bucket(client: &aws_sdk_s3::Client, name: &str) {
    client
        .create_bucket()
        .bucket(name)
        .send()
        .await
        .expect("create bucket");
}

/// Remove a bucket this test made. The dev S3 grows volumes per bucket and
/// runs out after a few dozen, so tests tidy up (best effort).
async fn remove_bucket(client: &aws_sdk_s3::Client, name: &str) {
    if let Ok(list) = client.list_objects_v2().bucket(name).send().await {
        for obj in list.contents() {
            if let Some(key) = obj.key() {
                let _ = client.delete_object().bucket(name).key(key).send().await;
            }
        }
    }
    let _ = client.delete_bucket().bucket(name).send().await;
}

/// Every OCSF record in `bucket`.
async fn records(client: &aws_sdk_s3::Client, bucket: &str) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let list = client
        .list_objects_v2()
        .bucket(bucket)
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
        out.extend(
            text.lines()
                .map(|l| serde_json::from_str(l).expect("one JSON value per line")),
        );
    }
    out
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

fn producer(proxy_id: &str, seq: usize) -> limen_audit::Producer {
    limen_audit::Producer {
        component: "proxy".into(),
        instance_id: format!("{proxy_id}/boot"),
        seq: seq as u64,
    }
}

async fn ingest(h: &Harness, n: usize) {
    let (proxy_id, proxy) = h.enroll_proxy().await;
    let mut client =
        limen_proto::v1::audit_ingest_client::AuditIngestClient::new(h.channel(Some(proxy)));
    let events = (0..n)
        .map(|i| {
            let event = limen_audit::Event::new(
                limen_audit::EventKind::SessionStart,
                producer(&proxy_id, i),
                serde_json::json!({ "kind": "ssh", "resource": "web-1", "proxy_id": proxy_id, "i": i }),
            );
            serde_json::to_vec(&event).expect("json")
        })
        .collect();
    client
        .ingest(limen_proto::v1::IngestRequest { events })
        .await
        .expect("ingest");
}

#[tokio::test(flavor = "multi_thread")]
async fn every_event_is_projected_into_the_ocsf_bucket_and_only_there() {
    let Some(endpoint) = limen_testkit::s3_endpoint() else {
        return;
    };
    let direct = limen_verify::s3_client(Some(&endpoint), true).await;
    let id = uuid::Uuid::now_v7().simple();
    let (audit, siem) = (format!("limen-test-{id}"), format!("limen-siem-{id}"));
    create_bucket(&direct, &audit).await;
    create_bucket(&direct, &siem).await;

    let Some(h) = Harness::start_with(&[
        format!("--audit-s3-bucket={audit}"),
        format!("--audit-s3-endpoint={endpoint}"),
        "--audit-s3-path-style".into(),
        "--audit-s3-flush=1s".into(),
        format!("--audit-ocsf-s3-bucket={siem}"),
        "--audit-ocsf-s3-prefix=ocsf/".into(),
        "--audit-ocsf-s3-flush=1s".into(),
    ])
    .await
    else {
        return;
    };
    for i in 0..3 {
        h.login(&format!("user{i}@example.com"), &["admins"])
            .await
            .expect("login");
    }
    ingest(&h, 20).await;

    let expected: BTreeSet<String> = h
        .audit_events()
        .await
        .iter()
        .map(|e| e.event_id.to_string())
        .collect();
    assert!(expected.len() >= 23);
    wait_for("every event in the OCSF bucket", 60, async || {
        let got: BTreeSet<String> = records(&direct, &siem)
            .await
            .iter()
            .filter_map(|r| r["metadata"]["uid"].as_str().map(str::to_owned))
            .collect();
        got.is_superset(&expected)
    })
    .await;

    let all = records(&direct, &siem).await;
    for r in &all {
        for key in [
            "class_uid",
            "category_uid",
            "activity_id",
            "type_uid",
            "time",
            "severity_id",
            "metadata",
        ] {
            assert!(r.get(key).is_some(), "{r} lacks {key}");
        }
        assert_eq!(r["metadata"]["version"], limen_audit::ocsf::OCSF_VERSION);
        assert!(r["unmapped"]["limen"]["producer"]["seq"].is_u64());
    }
    // Logins became Authentication events for the right user.
    assert!(all.iter().any(|r| r["class_uid"] == 3002
        && r["user"]["name"] == "user1@example.com"
        && r["status_id"] == 1));
    // Session starts became Network Activity (Open).
    assert!(
        all.iter()
            .any(|r| r["class_uid"] == 4001 && r["type_uid"] == 400_101)
    );
    // The objects are under the prefix, and the audit bucket has no OCSF.
    let keys = direct
        .list_objects_v2()
        .bucket(&siem)
        .send()
        .await
        .expect("list");
    assert!(
        keys.contents()
            .iter()
            .all(|o| o.key().is_some_and(|k| k.starts_with("ocsf/dt=")))
    );
    let audit_keys = direct
        .list_objects_v2()
        .bucket(&audit)
        .send()
        .await
        .expect("list");
    assert!(audit_keys.contents().iter().all(|o| {
        o.key()
            .is_some_and(|k| k.starts_with("events/") || k.starts_with("manifests/"))
    }));
    // Native S3 trail unaffected: it still verifies.
    let ca = h.internal_ca();
    wait_for("the audit trail to hold everything", 60, async || {
        limen_verify::bucket::verify_bucket(&direct, &audit, "", &ca)
            .await
            .is_ok_and(|r| r.ok() && r.events >= expected.len() as u64)
    })
    .await;
    remove_bucket(&direct, &audit).await;
    remove_bucket(&direct, &siem).await;
}

/// An OCSF endpoint that goes away for a while, behind a switch of its own so
/// the audit bucket stays reachable.
struct Siem {
    link: limen_testkit::toggle_proxy::ToggleProxy,
    bucket: String,
}

async fn siem(direct: &aws_sdk_s3::Client, endpoint: &str) -> Siem {
    let bucket = format!("limen-siem-{}", uuid::Uuid::now_v7().simple());
    create_bucket(direct, &bucket).await;
    // Prefer IPv4: containers publish on 127.0.0.1, while `localhost` may resolve to ::1 first.
    let mut addrs: Vec<std::net::SocketAddr> =
        tokio::net::lookup_host(endpoint.trim_start_matches("http://"))
            .await
            .expect("resolve")
            .collect();
    addrs.sort_by_key(|a| !a.is_ipv4());
    Siem {
        link: limen_testkit::toggle_proxy::ToggleProxy::start(addrs[0]).await,
        bucket,
    }
}

fn flags(audit: &str, endpoint: &str, siem: &Siem, extra: &[&str]) -> Vec<String> {
    let mut f = vec![
        format!("--audit-s3-bucket={audit}"),
        format!("--audit-s3-endpoint={endpoint}"),
        "--audit-s3-path-style".into(),
        "--audit-s3-flush=1s".into(),
        format!("--audit-ocsf-s3-bucket={}", siem.bucket),
        format!("--audit-ocsf-s3-endpoint=http://{}", siem.link.addr),
        "--audit-ocsf-s3-flush=1s".into(),
    ];
    f.extend(extra.iter().map(|s| (*s).to_owned()));
    f
}

/// A SIEM endpoint that cannot be reached must not keep the audit spool from
/// draining once it is what holds the spool back; the projection skips (and
/// counts) instead, and the audit trail has everything.
#[tokio::test(flavor = "multi_thread")]
async fn a_broken_ocsf_sink_skips_once_it_holds_the_spool_back() {
    let Some(endpoint) = limen_testkit::s3_endpoint() else {
        return;
    };
    let direct = limen_verify::s3_client(Some(&endpoint), true).await;
    let audit = format!("limen-test-{}", uuid::Uuid::now_v7().simple());
    create_bucket(&direct, &audit).await;
    let siem = siem(&direct, &endpoint).await;
    siem.link.set_up(false);
    let Some(h) = Harness::start_with(&flags(
        &audit,
        &endpoint,
        &siem,
        &["--audit-ocsf-max-lag-bytes=1"],
    ))
    .await
    else {
        return;
    };
    ingest(&h, 20).await;
    let spool = h.state.pipeline.spool.clone();
    wait_for("the audit trail to drain", 60, async || {
        spool.pending("s3") == 0
    })
    .await;
    wait_for(
        "the OCSF sink to skip what it cannot write",
        60,
        async || spool.pending("ocsf") == 0,
    )
    .await;
    // Skipped, so nothing reached the SIEM bucket...
    assert_eq!(records(&direct, &siem.bucket).await.len(), 0);
    // ...but the audit trail lost nothing.
    let ca = h.internal_ca();
    let report = limen_verify::bucket::verify_bucket(&direct, &audit, "", &ca)
        .await
        .expect("verify");
    assert!(report.ok(), "{:?}", report.problems);
    assert!(report.events >= 20);
    remove_bucket(&direct, &audit).await;
    remove_bucket(&direct, &siem.bucket).await;
}

/// While the spool is not at risk, a down SIEM endpoint costs nothing: the
/// events wait, and arrive when it is back.
#[tokio::test(flavor = "multi_thread")]
async fn a_down_ocsf_sink_keeps_its_events_and_delivers_them_when_it_returns() {
    let Some(endpoint) = limen_testkit::s3_endpoint() else {
        return;
    };
    let direct = limen_verify::s3_client(Some(&endpoint), true).await;
    let audit = format!("limen-test-{}", uuid::Uuid::now_v7().simple());
    create_bucket(&direct, &audit).await;
    let siem = siem(&direct, &endpoint).await;
    siem.link.set_up(false);
    let Some(h) = Harness::start_with(&flags(&audit, &endpoint, &siem, &[])).await else {
        return;
    };
    ingest(&h, 20).await;
    let spool = h.state.pipeline.spool.clone();
    wait_for("the audit trail to drain", 60, async || {
        spool.pending("s3") == 0
    })
    .await;
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(
        spool.pending("ocsf") > 0,
        "the sink kept what it could not deliver"
    );
    assert_eq!(records(&direct, &siem.bucket).await.len(), 0);

    siem.link.set_up(true);
    let expected: BTreeSet<String> = h
        .audit_events()
        .await
        .iter()
        .map(|e| e.event_id.to_string())
        .collect();
    wait_for("everything to arrive after the outage", 90, async || {
        let got: BTreeSet<String> = records(&direct, &siem.bucket)
            .await
            .iter()
            .filter_map(|r| r["metadata"]["uid"].as_str().map(str::to_owned))
            .collect();
        got.is_superset(&expected)
    })
    .await;
    remove_bucket(&direct, &audit).await;
    remove_bucket(&direct, &siem.bucket).await;
}
