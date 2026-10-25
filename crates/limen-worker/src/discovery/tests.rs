use std::collections::BTreeMap;

use limen_policy::discovery::Source;
use limen_policy::{Document, Policy};
use limen_testkit::fake_aws;

use super::aws::Aws;
use super::sources;
use crate::db::sigv4::Credentials;

const DOC: &str = r"
kind: discovery
version: v1
metadata: { name: aws }
spec:
  provider: aws
  accounts: [{ role_arn: 'arn:aws:iam::111122223333:role/limen-discovery' }]
  regions: [eu-west-1]
  match:
    - type: ec2
      tags: { limen/managed: ['true'] }
      labels_from_tags: [env]
    - type: rds
    - type: redshift
    - type: elasticache
    - type: eks
";

fn doc() -> limen_policy::discovery::DiscoveryDoc {
    Policy::parse_yaml([("d.yaml", DOC)])
        .expect("doc")
        .documents()
        .into_iter()
        .find_map(|d| match d {
            Document::Discovery(d) => Some(d),
            _ => None,
        })
        .expect("discovery")
}

fn creds() -> Credentials {
    Credentials {
        access_key: "AKIAEXAMPLE".into(),
        secret_key: limen_core::secret::Secret::new("secret".into()),
        session_token: None,
    }
}

fn instance(id: &str, ip: &str, managed: bool) -> fake_aws::Instance {
    let mut tags = BTreeMap::from([
        ("Name".to_owned(), id.to_owned()),
        ("env".to_owned(), "prod".to_owned()),
        ("secret-tag".to_owned(), "do-not-send".to_owned()),
    ]);
    if managed {
        tags.insert("limen/managed".into(), "true".into());
    }
    fake_aws::Instance {
        id: id.into(),
        ip: ip.into(),
        state: "running".into(),
        tags,
        host_key: Some(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
                .into(),
        ),
    }
}

#[tokio::test]
async fn every_source_is_read_through_signed_describe_calls() {
    let (url, world) = fake_aws::start("111122223333").await;
    {
        let mut w = world.lock().expect("lock");
        w.instances = vec![
            instance("i-0aaa", "10.0.1.5", true),
            instance("i-0bbb", "10.0.1.6", false),
            fake_aws::Instance {
                state: "stopped".into(),
                ..instance("i-0ccc", "10.0.1.7", true)
            },
        ];
    }
    let aws = Aws::new(Some(url)).expect("client");
    let doc = doc();
    let c = creds();
    let scan = |i: usize| {
        let (aws, c, m) = (aws.clone(), c.clone(), doc.spec.matchers[i].clone());
        async move { sources::scan(&aws, &c, &m, "111122223333", "eu-west-1").await }
    };

    // EC2: running and tagged only; the host key comes from the console output;
    // only the tags the matcher uses are kept.
    let ec2 = scan(0).await.expect("ec2");
    assert_eq!(ec2.len(), 1);
    assert_eq!(ec2[0].provider_id, "i-0aaa");
    assert_eq!(ec2[0].target, "10.0.1.5:22");
    assert_eq!(
        ec2[0].facts["host_key"],
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
    );
    assert!(ec2[0].tags.contains_key("env") && ec2[0].tags.contains_key("limen/managed"));
    assert!(
        !ec2[0].tags.contains_key("secret-tag"),
        "tags nothing asked for never leave the worker"
    );

    // RDS: the Aurora cluster once (through its endpoint, not its members), and the instance.
    let rds = scan(1).await.expect("rds");
    let ids: Vec<&str> = rds.iter().map(|f| f.provider_id.as_str()).collect();
    assert_eq!(ids, ["aurora", "orders-db"]);
    assert_eq!(
        rds[0].target,
        "aurora.cluster-abc.eu-west-1.rds.amazonaws.com:5432"
    );
    assert_eq!(rds[1].facts["engine"], "postgres");
    assert_eq!(rds[1].facts["iam_auth"], "true");

    let redshift = scan(2).await.expect("redshift");
    assert_eq!(
        redshift[0].target,
        "warehouse.abc.eu-west-1.redshift.amazonaws.com:5439"
    );

    // ElastiCache: the cluster-mode group is skipped, the other one is found.
    let cache = scan(3).await.expect("elasticache");
    assert_eq!(cache.len(), 1);
    assert_eq!(cache[0].provider_id, "sessions");
    assert_eq!(cache[0].facts["tls"], "true");

    let eks = scan(4).await.expect("eks");
    assert_eq!(eks[0].target, "prod-eks");
    assert_eq!(eks[0].source, Source::Eks);

    // Read-only: every call was a Describe, a List, or a console read.
    let seen = world.lock().expect("lock").seen.clone();
    for action in &seen {
        assert!(
            action.starts_with("Describe")
                || action.starts_with("List")
                || action == "GetConsoleOutput"
                || action.starts_with("GET /clusters"),
            "discovery made a call that isn't a read: {action}"
        );
    }
}

#[tokio::test]
async fn roles_are_assumed_and_the_account_is_known() {
    let (url, _) = fake_aws::start("111122223333").await;
    let aws = Aws::new(Some(url)).expect("client");
    let (assumed, _) = aws
        .assume_role(
            &creds(),
            "arn:aws:iam::111122223333:role/limen-discovery",
            "eu-west-1",
        )
        .await
        .expect("assume");
    assert_eq!(assumed.access_key, "ASIAEXAMPLE");
    assert!(assumed.session_token.is_some());
    assert_eq!(
        aws.account_of(&creds(), "eu-west-1")
            .await
            .expect("account"),
        "111122223333"
    );
}

#[tokio::test]
async fn a_failing_service_is_an_error_not_an_empty_answer() {
    let (url, world) = fake_aws::start("111122223333").await;
    world.lock().expect("lock").fail_ec2 = true;
    let aws = Aws::new(Some(url)).expect("client");
    let doc = doc();
    let err = sources::scan(
        &aws,
        &creds(),
        &doc.spec.matchers[0],
        "111122223333",
        "eu-west-1",
    )
    .await
    .expect_err("an outage is not 'no instances'");
    assert!(err.contains("RequestLimitExceeded"), "{err}");
}

#[test]
fn console_output_gives_the_best_host_key() {
    use base64::Engine as _;
    let enc = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
    let out = enc(
        "x\n-----BEGIN SSH HOST KEY KEYS-----\nssh-rsa AAAArsa root@h\necdsa-sha2-nistp256 AAAAecdsa root@h\nssh-ed25519 AAAAed root@h\n-----END SSH HOST KEY KEYS-----\n",
    );
    assert_eq!(
        sources::host_key_from_console(&out).as_deref(),
        Some("ssh-ed25519 AAAAed")
    );
    let out = enc(
        "-----BEGIN SSH HOST KEY KEYS-----\nssh-rsa AAAArsa root@h\n-----END SSH HOST KEY KEYS-----",
    );
    assert_eq!(
        sources::host_key_from_console(&out).as_deref(),
        Some("ssh-rsa AAAArsa")
    );
    assert_eq!(sources::host_key_from_console(&enc("no keys here")), None);
    assert_eq!(sources::host_key_from_console("%%% not base64"), None);
}
