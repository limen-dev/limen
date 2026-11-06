//! Discovery against an AWS emulator (Moto), through the same signed calls the
//! worker makes. Set `LIMEN_TEST_AWS_ENDPOINT` and `LIMEN_TEST_AWS_OPEN_ENDPOINT`
//! to run (a missing variable prints SKIPPED, which CI treats as a failure).
//! CI starts both emulators as service containers; locally:
//!
//! ```sh
//! docker compose --project-directory deploy/compose \
//!   -f deploy/compose/stacks/aws-emulator.yml up -d --force-recreate
//! LIMEN_TEST_AWS_ENDPOINT=http://localhost:15000 \
//!   LIMEN_TEST_AWS_OPEN_ENDPOINT=http://localhost:15001 \
//!   cargo test -p limen-worker --lib discovery::emulator
//! ```
//!
//! **Emulator-tested, not verified against AWS** (#123). It shows that another
//! implementation of the APIs accepts the worker's signed requests (Moto's IAM
//! mode refuses a wrong secret), that the worker reads answers it didn't shape
//! itself, and that the describe-only role from the discovery guide is enough
//! for the EC2, RDS, Redshift and ElastiCache scans and can't launch an
//! instance. Moto is lenient about input, has no real engines, and its console
//! output has no SSH host keys.
//!
//! EKS is read from a second Moto without IAM mode: the first answers even
//! botocore's signed EKS `GET`s with `SignatureDoesNotMatch`. EKS signing and
//! the role's EKS permissions are therefore not covered.
//!
//! The IAM-mode Moto lets the first `INITIAL_NO_AUTH_ACTION_COUNT` calls
//! through unauthenticated (exactly the three that create the admin user) and
//! only a restart resets it, so it must be fresh for each run.

use limen_core::secret::Secret;
use limen_policy::discovery::Source;
use limen_policy::{Document, Policy};
use time::OffsetDateTime;

use super::aws::Aws;
use super::sources;
use super::xml::Node;
use crate::db::sigv4::{self, Credentials};

const ACCOUNT: &str = "123456789012"; // Moto's default account
const REGION: &str = "eu-west-1";
const ROLE: &str = "arn:aws:iam::123456789012:role/limen-discovery";

const DOC: &str = r"
kind: discovery
version: v1
metadata: { name: aws }
spec:
  provider: aws
  accounts: [{ role_arn: 'arn:aws:iam::123456789012:role/limen-discovery' }]
  regions: [eu-west-1]
  match:
    - type: ec2
      tags: { limen/managed: ['true'] }
      labels_from_tags: [env]
    - type: rds
      tags: { limen/managed: ['true'] }
    - type: redshift
      tags: { limen/managed: ['true'] }
    - type: elasticache
      tags: { limen/managed: ['true'] }
    - type: eks
      tags: { limen/managed: ['true'] }
";

/// The permissions docs/guides/discovery.md tells operators to grant.
const DISCOVERY_POLICY: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Resource":"*","Action":[
"ec2:DescribeInstances","ec2:GetConsoleOutput",
"rds:DescribeDBInstances","rds:DescribeDBClusters","rds:ListTagsForResource",
"redshift:DescribeClusters",
"elasticache:DescribeReplicationGroups","elasticache:ListTagsForResource",
"eks:ListClusters","eks:DescribeCluster"]}]}"#;

const ADMIN_POLICY: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;
const TRUST_POLICY: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}"#;

fn p(k: &str, v: &str) -> (String, String) {
    (k.to_owned(), v.to_owned())
}

fn tag_params(prefix: &str, key_name: &str, value_name: &str) -> Vec<(String, String)> {
    [
        ("limen/managed", "true"),
        ("env", "prod"),
        ("secret-tag", "x"),
    ]
    .iter()
    .enumerate()
    .flat_map(|(i, (k, v))| {
        [
            (format!("{prefix}.{}.{key_name}", i + 1), (*k).to_owned()),
            (format!("{prefix}.{}.{value_name}", i + 1), (*v).to_owned()),
        ]
    })
    .collect()
}

async fn call(
    aws: &Aws,
    creds: &Credentials,
    service: &str,
    version: &str,
    action: &str,
    params: &[(String, String)],
) -> Node {
    aws.query(creds, service, REGION, version, action, params)
        .await
        .unwrap_or_else(|e| panic!("seeding {service} {action}: {e}"))
}

fn text<'a>(n: &'a Node, path: &[&str]) -> &'a str {
    n.text_at(path)
        .unwrap_or_else(|| panic!("no {path:?} in {n:?}"))
}

/// `POST /clusters` on EKS: the one seeding call `Aws` has no method for.
async fn create_eks_cluster(endpoint: &str, creds: &Credentials, name: &str, role_arn: &str) {
    let body = serde_json::json!({
        "name": name,
        "roleArn": role_arn,
        "resourcesVpcConfig": { "subnetIds": ["subnet-1"] },
        "tags": { "limen/managed": "true", "env": "prod" },
    })
    .to_string();
    let url = reqwest::Url::parse(endpoint).expect("endpoint");
    let host = match url.port() {
        Some(port) => format!("{}:{port}", url.host_str().expect("host")),
        None => url.host_str().expect("host").to_owned(),
    };
    let ct = "application/json";
    let signed = sigv4::sign_headers(
        &sigv4::Target {
            method: "POST",
            host: &host,
            path: "/clusters",
            region: REGION,
            service: "eks",
        },
        "",
        &[("content-type", ct)],
        body.as_bytes(),
        creds,
        OffsetDateTime::now_utc(),
    );
    let mut req = reqwest::Client::new()
        .post(format!("{endpoint}/clusters"))
        .header("content-type", ct)
        .header("authorization", signed.authorization)
        .header("x-amz-date", signed.amz_date)
        .body(body);
    if let Some(t) = signed.session_token {
        req = req.header("x-amz-security-token", t);
    }
    let resp = req.send().await.expect("eks create");
    assert!(
        resp.status().is_success(),
        "eks create: {}",
        resp.text().await.unwrap_or_default()
    );
}

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

async fn iam(aws: &Aws, c: &Credentials, action: &str, params: Vec<(String, String)>) -> Node {
    aws.query(c, "iam", "us-east-1", "2010-05-08", action, &params)
        .await
        .unwrap_or_else(|e| panic!("iam {action}: {e}"))
}

/// The admin user, created in the emulator's unauthenticated window.
async fn bootstrap_admin(aws: &Aws) -> Credentials {
    let nobody = Credentials {
        access_key: "AKIAUNKNOWN".into(),
        secret_key: Secret::new("unknown".into()),
        session_token: None,
    };
    aws.query(
        &nobody,
        "iam",
        "us-east-1",
        "2010-05-08",
        "CreateUser",
        &[p("UserName", "limen-admin")],
    )
    .await
    .expect("the emulator must be fresh (restart it): its unauthenticated window is used up");
    let key = iam(
        aws,
        &nobody,
        "CreateAccessKey",
        vec![p("UserName", "limen-admin")],
    )
    .await;
    let admin = Credentials {
        access_key: text(&key, &["CreateAccessKeyResult", "AccessKey", "AccessKeyId"]).into(),
        secret_key: Secret::new(
            text(
                &key,
                &["CreateAccessKeyResult", "AccessKey", "SecretAccessKey"],
            )
            .into(),
        ),
        session_token: None,
    };
    iam(
        aws,
        &nobody,
        "PutUserPolicy",
        vec![
            p("UserName", "limen-admin"),
            p("PolicyName", "admin"),
            p("PolicyDocument", ADMIN_POLICY),
        ],
    )
    .await;

    let wrong = Credentials {
        secret_key: Secret::new("not-the-secret".into()),
        ..admin.clone()
    };
    let err = aws
        .account_of(&wrong, REGION)
        .await
        .expect_err("a request signed with the wrong secret must be refused");
    assert!(
        err.contains("AuthFailure") || err.contains("SignatureDoesNotMatch"),
        "{err}"
    );
    assert_eq!(
        aws.account_of(&admin, REGION).await.expect("admin"),
        ACCOUNT
    );
    admin
}

/// One managed resource of each kind; returns the managed instance's id and address.
async fn seed(aws: &Aws, admin: &Credentials) -> (String, String) {
    let mut run = vec![
        p("ImageId", "ami-12c6146b"),
        p("MinCount", "1"),
        p("MaxCount", "1"),
        p("TagSpecification.1.ResourceType", "instance"),
    ];
    run.extend(tag_params("TagSpecification.1.Tag", "Key", "Value"));
    let ec2 = call(aws, admin, "ec2", "2016-11-15", "RunInstances", &run).await;
    let id = text(&ec2, &["instancesSet", "item", "instanceId"]).to_owned();
    let ip = text(&ec2, &["instancesSet", "item", "privateIpAddress"]).to_owned();
    call(
        aws,
        admin,
        "ec2",
        "2016-11-15",
        "RunInstances",
        &[
            p("ImageId", "ami-12c6146b"),
            p("MinCount", "1"),
            p("MaxCount", "1"),
        ],
    )
    .await; // untagged: must not be found

    let db = |id: &str, extra: &[(&str, &str)]| {
        let mut v = vec![
            p("DBInstanceIdentifier", id),
            p("DBInstanceClass", "db.t3.micro"),
            p("AllocatedStorage", "20"),
            p("MasterUsername", "limen"),
            p("MasterUserPassword", "dev-only-password"),
        ];
        v.extend(extra.iter().map(|(k, x)| p(k, x)));
        v.extend(tag_params("Tags.Tag", "Key", "Value"));
        v
    };
    call(
        aws,
        admin,
        "rds",
        "2014-10-31",
        "CreateDBInstance",
        &db(
            "orders-db",
            &[
                ("Engine", "postgres"),
                ("EnableIAMDatabaseAuthentication", "true"),
            ],
        ),
    )
    .await;
    let mut cluster = vec![
        p("DBClusterIdentifier", "aurora"),
        p("Engine", "aurora-postgresql"),
        p("MasterUsername", "limen"),
        p("MasterUserPassword", "dev-only-password"),
    ];
    cluster.extend(tag_params("Tags.Tag", "Key", "Value"));
    call(aws, admin, "rds", "2014-10-31", "CreateDBCluster", &cluster).await;
    call(
        aws,
        admin,
        "rds",
        "2014-10-31",
        "CreateDBInstance",
        &db(
            "aurora-1",
            &[
                ("Engine", "aurora-postgresql"),
                ("DBClusterIdentifier", "aurora"),
            ],
        ),
    )
    .await; // a cluster member: reached through the cluster endpoint

    let mut redshift = vec![
        p("ClusterIdentifier", "warehouse"),
        p("NodeType", "dc2.large"),
        p("MasterUsername", "limen"),
        p("MasterUserPassword", "Dev0nlyPassword"),
    ];
    redshift.extend(tag_params("Tags.Tag", "Key", "Value"));
    call(
        aws,
        admin,
        "redshift",
        "2012-12-01",
        "CreateCluster",
        &redshift,
    )
    .await;

    let mut cache = vec![
        p("ReplicationGroupId", "sessions"),
        p("ReplicationGroupDescription", "sessions"),
        p("Engine", "redis"),
        p("CacheNodeType", "cache.t3.micro"),
        p("NumCacheClusters", "1"),
        p("TransitEncryptionEnabled", "true"),
    ];
    cache.extend(tag_params("Tags.Tag", "Key", "Value"));
    call(
        aws,
        admin,
        "elasticache",
        "2015-02-02",
        "CreateReplicationGroup",
        &cache,
    )
    .await;
    (id, ip)
}

#[tokio::test]
async fn discovery_reads_what_an_aws_emulator_serves() {
    let Ok(endpoint) = std::env::var("LIMEN_TEST_AWS_ENDPOINT") else {
        eprintln!("SKIPPED: LIMEN_TEST_AWS_ENDPOINT is not set");
        return;
    };
    let aws = Aws::new(Some(endpoint)).expect("client");
    let admin = bootstrap_admin(&aws).await;

    iam(
        &aws,
        &admin,
        "CreateRole",
        vec![
            p("RoleName", "limen-discovery"),
            p("AssumeRolePolicyDocument", TRUST_POLICY),
        ],
    )
    .await;
    iam(
        &aws,
        &admin,
        "PutRolePolicy",
        vec![
            p("RoleName", "limen-discovery"),
            p("PolicyName", "discovery"),
            p("PolicyDocument", DISCOVERY_POLICY),
        ],
    )
    .await;

    let (vm_id, address) = seed(&aws, &admin).await;

    let (role, _) = aws
        .assume_role(&admin, ROLE, REGION)
        .await
        .expect("the worker assumes the discovery role");
    assert_eq!(
        aws.account_of(&role, REGION).await.expect("account"),
        ACCOUNT
    );

    let doc = doc();
    let scan = |i: usize| {
        let (aws, role, m) = (aws.clone(), role.clone(), doc.spec.matchers[i].clone());
        async move { sources::scan(&aws, &role, &m, ACCOUNT, REGION).await }
    };

    let ec2 = scan(0).await.expect("ec2");
    assert_eq!(ec2.len(), 1, "{ec2:?}");
    assert_eq!(ec2[0].provider_id, vm_id);
    assert_eq!(ec2[0].target, format!("{address}:22"));
    assert_eq!(ec2[0].tags.get("env").map(String::as_str), Some("prod"));
    assert!(
        !ec2[0].tags.contains_key("secret-tag"),
        "unasked tags stay in the worker"
    );
    // Moto's console output has no host-key block, so no key is learned and
    // the scan still succeeds. Extraction itself is only fixture-tested.
    assert!(!ec2[0].facts.contains_key("host_key"));

    let rds = scan(1).await.expect("rds");
    let ids: Vec<&str> = rds.iter().map(|f| f.provider_id.as_str()).collect();
    assert_eq!(
        ids,
        ["aurora", "orders-db"],
        "the member is not listed: {rds:?}"
    );
    assert!(rds[0].target.ends_with(":5432"), "{}", rds[0].target);
    assert_eq!(rds[1].facts["engine"], "postgres");
    assert_eq!(rds[1].facts["iam_auth"], "true");

    let rs = scan(2).await.expect("redshift");
    assert_eq!(rs.len(), 1, "{rs:?}");
    assert_eq!(rs[0].provider_id, "warehouse");
    assert!(rs[0].target.ends_with(":5439"), "{}", rs[0].target);

    let ec = scan(3).await.expect("elasticache");
    assert_eq!(ec.len(), 1, "{ec:?}");
    assert_eq!(ec[0].provider_id, "sessions");

    let denied = aws
        .query(
            &role,
            "ec2",
            REGION,
            "2016-11-15",
            "RunInstances",
            &[
                p("ImageId", "ami-12c6146b"),
                p("MinCount", "1"),
                p("MaxCount", "1"),
            ],
        )
        .await
        .expect_err("the discovery role must not be able to launch instances");
    assert!(err_is_denied(&denied), "{denied}");
}

fn err_is_denied(e: &str) -> bool {
    e.contains("UnauthorizedOperation") || e.contains("AccessDenied") || e.contains("403")
}

#[tokio::test]
async fn eks_clusters_are_read_from_an_aws_emulator() {
    let Ok(endpoint) = std::env::var("LIMEN_TEST_AWS_OPEN_ENDPOINT") else {
        eprintln!("SKIPPED: LIMEN_TEST_AWS_OPEN_ENDPOINT is not set");
        return;
    };
    let aws = Aws::new(Some(endpoint.clone())).expect("client");
    let any = Credentials {
        access_key: "AKIAANY".into(),
        secret_key: Secret::new("any".into()),
        session_token: None,
    };
    create_eks_cluster(&endpoint, &any, "prod-eks", ROLE).await;
    let doc = doc();
    let eks = sources::scan(&aws, &any, &doc.spec.matchers[4], ACCOUNT, REGION)
        .await
        .expect("eks");
    assert_eq!(eks.len(), 1, "{eks:?}");
    assert_eq!(eks[0].provider_id, "prod-eks");
    assert_eq!(eks[0].source, Source::Eks);
    assert_eq!(
        eks[0].tags.get("limen/managed").map(String::as_str),
        Some("true")
    );
    assert!(
        !eks[0].tags.contains_key("env"),
        "unasked tags stay in the worker"
    );
}
