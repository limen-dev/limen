use std::net::IpAddr;

use serde_json::json;

use super::*;
use crate::{Document, Policy};

/// An edit to a YAML document, and what the refusal must say.
type Case<'a> = (&'a dyn Fn(&str) -> String, &'a str);

const BOTS: &str = include_str!("../../../../examples/policy/stacks/bots/policy.yaml");
const EXAMPLE: &str = include_str!("../../../../examples/policy/stacks/delegation/policy.yaml");

const PROFILE: &str = r#"
kind: resource_profile
version: v1
metadata: { name: payments-postgres }
spec:
  template:
    postgres:
      iam_auth: true
      region: eu-west-1
      tls_ca_file: /etc/limen/rds-ca.pem
    worker_selector: { network: payments-vpc }
  settable:
    postgres.endpoint:
      hosts: ["*.c9xk2p.eu-west-1.rds.amazonaws.com", "orders.payments.internal"]
      cidrs: ["10.20.0.0/16"]
      ports: [5432]
    postgres.default_database: {}
  labels:
    fixed: { team: payments }
    allowed: { env: [dev, staging] }
"#;

const WRITER: &str = r#"
kind: policy_writer
version: v1
metadata: { name: payments-terraform }
spec:
  bot: deploy-staging
  namespace: payments
  names: ["payments-*"]
  kinds: [resource]
  profiles: [payments-postgres]
"#;

fn profile() -> ResourceProfileDoc {
    Policy::parse_yaml([("p.yaml", PROFILE)])
        .expect("profile parses")
        .profile("payments-postgres")
        .expect("profile")
        .clone()
}

/// The error for the profile with `edit` applied to its YAML.
fn profile_error(edit: impl Fn(&str) -> String) -> String {
    match Policy::parse_yaml([("p.yaml", edit(PROFILE).as_str())]) {
        Ok(_) => panic!("profile should be refused"),
        Err(e) => e.to_string(),
    }
}

fn writer_input(spec: &serde_json::Value, labels: &[(&str, &str)]) -> WriterResource {
    WriterResource {
        name: "payments-orders-db".into(),
        description: None,
        labels: labels
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
        spec: spec.as_object().expect("object").clone(),
    }
}

fn materialize_error(spec: &serde_json::Value, labels: &[(&str, &str)]) -> String {
    match materialize(&profile(), &writer_input(spec, labels)) {
        Ok(doc) => panic!("should be refused, got {doc:?}"),
        Err(e) => e.to_string(),
    }
}

// ---- The ceiling ------------------------------------------------------------

/// The fields of a strict struct, read from serde's "unknown field" error.
fn fields_of(json: serde_json::Value) -> Vec<String> {
    let err = serde_json::from_value::<ResourceSpec>(json)
        .expect_err("the probe field is unknown")
        .to_string();
    let expected = err.split_once("expected").map_or("", |(_, rest)| rest);
    expected
        .split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

/// Fields reviewed as profile-only, per section. A field in neither this
/// list nor `SETTABLE` fails `every_resource_field_is_classified`: decide
/// which it is before shipping it. Settable means a bot writer controls it.
const PROFILE_ONLY: &[(&str, &[&str])] = &[
    ("ssh", &[]),
    (
        "postgres",
        &[
            "region",
            "iam_auth",
            "admin_secret_arn",
            "cluster_identifier",
            "workgroup",
            "password_dir",
            "tls_ca_file",
            "tls_server_name",
            "insecure_dev",
            "normalize_literals",
            "admin_user",
            "admin_password_file",
            "bootstrap",
        ],
    ),
    (
        "redis",
        &["region", "iam_auth", "cache_name", "tls", "audit"],
    ),
    ("kubernetes", &["cluster_name"]),
    (
        "mongodb",
        &[
            "flavor",
            "auth",
            "auth_source",
            "credentials_dir",
            "tls_ca_file",
            "tls_server_name",
            "insecure_dev",
            "full_commands",
            "max_commands_per_second",
        ],
    ),
    (
        "opensearch",
        &["region", "aws", "serverless", "tls", "audit"],
    ),
    ("rabbitmq", &["region", "aws", "tls", "sasl"]),
    (
        "web",
        &[
            "host",
            "tls_ca_file",
            "tls_server_name",
            "health_path",
            "insecure_dev",
            "identity_headers",
        ],
    ),
    ("tcp", &[]),
];

#[test]
fn every_resource_field_is_classified() {
    // Sections that share a struct: mysql and redshift are postgres's
    // DbTarget, elasticsearch is opensearch's, kafka is rabbitmq's.
    let shared = [
        ("mysql", "postgres"),
        ("redshift", "postgres"),
        ("elasticsearch", "opensearch"),
        ("kafka", "rabbitmq"),
    ];
    let sections = fields_of(json!({ "__probe__": 1 }));
    assert!(sections.len() > 10, "probe failed: {sections:?}");
    for section in &sections {
        if matches!(section.as_str(), "worker_selector" | "delegated") {
            continue; // Profile-only, and set by the control plane.
        }
        let reviewed = shared
            .iter()
            .find(|(s, _)| s == section)
            .map_or(section.as_str(), |(_, same)| *same);
        let profile_only = PROFILE_ONLY
            .iter()
            .find(|(s, _)| *s == reviewed)
            .map_or_else(
                || panic!("section {section:?} isn't reviewed in PROFILE_ONLY"),
                |(_, f)| *f,
            );
        let fields = fields_of(json!({ section.clone(): { "__probe__": 1 } }));
        assert!(!fields.is_empty(), "probe failed for {section}");
        for field in fields {
            let path = format!("{section}.{field}");
            let is_settable = settable(&path).is_some();
            let is_profile_only = profile_only.contains(&field.as_str());
            assert!(
                is_settable ^ is_profile_only,
                "{path}: classify it as settable (SETTABLE) or profile-only (PROFILE_ONLY), exactly once"
            );
        }
    }
    // And the ceiling only names fields that exist.
    for (path, _) in SETTABLE {
        let (section, field) = path.split_once('.').expect("section.field");
        assert!(
            fields_of(json!({ section: { "__probe__": 1 } })).contains(&field.to_owned()),
            "{path} is in SETTABLE but isn't a field"
        );
    }
}

// ---- Building a resource ----------------------------------------------------

#[test]
fn a_writer_completes_a_profile() {
    let doc = materialize(
        &profile(),
        &writer_input(
            &json!({ "postgres": {
                "endpoint": "orders.c9xk2p.eu-west-1.rds.amazonaws.com:5432",
                "default_database": "orders",
            }}),
            &[("env", "staging")],
        ),
    )
    .expect("valid");
    let pg = doc.spec.postgres.as_ref().expect("postgres");
    assert_eq!(
        pg.endpoint,
        "orders.c9xk2p.eu-west-1.rds.amazonaws.com:5432"
    );
    assert_eq!(pg.default_database.as_deref(), Some("orders"));
    // The profile's half is there, and the writer couldn't have changed it.
    assert!(pg.iam_auth);
    assert_eq!(pg.tls_ca_file.as_deref(), Some("/etc/limen/rds-ca.pem"));
    assert_eq!(
        doc.spec.worker_selector.get("network"),
        Some("payments-vpc")
    );
    assert_eq!(doc.metadata.labels.get("team"), Some("payments"));
    assert_eq!(doc.metadata.labels.get("env"), Some("staging"));
    let delegated = doc.spec.delegated.as_ref().expect("marked");
    assert_eq!(delegated.profile, "payments-postgres");
    assert_eq!(delegated.ports, [5432]);
    assert_eq!(delegated.cidrs, ["10.20.0.0/16"]);
    // An IP literal inside the cidrs works too.
    materialize(
        &profile(),
        &writer_input(&json!({ "postgres": { "endpoint": "10.20.3.4:5432" }}), &[]),
    )
    .expect("ip in cidrs");
}

#[test]
fn a_writer_cant_reach_past_the_profile() {
    let refused = [
        // Profile-only fields: credentials, files, IAM, the worker, audit.
        (
            json!({ "postgres": { "endpoint": "a.payments.internal:5432", "admin_secret_arn": "arn:aws:secretsmanager:eu-west-1:1:secret:other-team" }}),
            "isn't settable",
        ),
        (
            json!({ "postgres": { "endpoint": "x:5432", "admin_password_file": "/etc/limen/worker.key" }}),
            "isn't settable",
        ),
        (
            json!({ "postgres": { "endpoint": "x:5432", "iam_auth": false }}),
            "isn't settable",
        ),
        (
            json!({ "postgres": { "endpoint": "x:5432" }, "worker_selector": { "network": "other" }}),
            "isn't settable",
        ),
        (
            json!({ "postgres": { "endpoint": "x:5432", "normalize_literals": false }}),
            "isn't settable",
        ),
        (json!({ "delegated": { "profile": "x" }}), "isn't settable"),
        // Another protocol entirely.
        (json!({ "ssh": { "address": "host:22" }}), "isn't settable"),
        // Endpoints outside the bounds.
        (
            json!({ "postgres": { "endpoint": "orders.payments.internal:5433" }}),
            "port 5433",
        ),
        (
            json!({ "postgres": { "endpoint": "db.other-team.internal:5432" }}),
            "doesn't match",
        ),
        (
            json!({ "postgres": { "endpoint": "evil-c9xk2p.eu-west-1.rds.amazonaws.com:5432" }}),
            "doesn't match",
        ),
        (
            json!({ "postgres": { "endpoint": "c9xk2p.eu-west-1.rds.amazonaws.com:5432" }}),
            "doesn't match",
        ),
        (
            json!({ "postgres": { "endpoint": "10.30.0.1:5432" }}),
            "outside the allowed cidrs",
        ),
        (
            json!({ "postgres": { "endpoint": "169.254.169.254:5432" }}),
            "always refuses",
        ),
        (
            json!({ "postgres": { "endpoint": "127.0.0.1:5432" }}),
            "always refuses",
        ),
        (
            json!({ "postgres": { "endpoint": "[::ffff:127.0.0.1]:5432" }}),
            "always refuses",
        ),
        (
            json!({ "postgres": { "endpoint": "[fd00:ec2::254]:5432" }}),
            "always refuses",
        ),
        (
            json!({ "postgres": { "endpoint": "orders.payments.internal" }}),
            "not host:port",
        ),
        (
            json!({ "postgres": { "endpoint": 5432 }}),
            "must be a string",
        ),
        (
            json!({ "postgres": { "endpoint": "orders.payments.internal:5432", "default_database": "a\nb" }}),
            "control characters",
        ),
    ];
    for (spec, why) in refused {
        let err = materialize_error(&spec, &[]);
        assert!(err.contains(why), "{spec}: expected {why:?}, got {err}");
    }
    let endpoint = json!({ "postgres": { "endpoint": "orders.payments.internal:5432" }});
    for (labels, why) in [
        (&[("team", "other")][..], "fixed"),
        (&[("env", "prod")][..], "isn't allowed"),
        (&[("owner", "me")][..], "isn't allowed"),
    ] {
        let err = materialize_error(&endpoint, labels);
        assert!(err.contains(why), "{labels:?}: expected {why:?}, got {err}");
    }
}

// ---- Validating a profile ---------------------------------------------------

#[test]
fn a_profile_is_refused_when_it_would_hand_out_too_much() {
    let cases: [Case; 11] = [
        (
            &|p| {
                p.replace(
                    "    postgres.default_database: {}",
                    "    postgres.admin_secret_arn: {}",
                )
            },
            "can't be settable",
        ),
        (
            &|p| {
                p.replace(
                    "      hosts: [\"*.c9xk2p.eu-west-1.rds.amazonaws.com\", \"orders.payments.internal\"]\n      cidrs: [\"10.20.0.0/16\"]\n",
                    "",
                )
            },
            "needs hosts or cidrs",
        ),
        (&|p| p.replace("      ports: [5432]\n", ""), "needs ports"),
        (
            &|p| {
                p.replace(
                    "postgres.default_database: {}",
                    "postgres.default_database: { ports: [1] }",
                )
            },
            "takes no bounds",
        ),
        (
            &|p| p.replace("\"*.c9xk2p.eu-west-1.rds.amazonaws.com\"", "\"*.com\""),
            "too broad",
        ),
        (&|p| p.replace("10.20.0.0/16", "10.0.0.0/4"), "too broad"),
        (
            &|p| p.replace("10.20.0.0/16", "169.254.0.0/16"),
            "always refuses",
        ),
        (
            &|p| {
                p.replace(
                    "      region: eu-west-1\n",
                    "      region: eu-west-1\n      default_database: app\n",
                )
            },
            "both in the template and settable",
        ),
        (
            &|p| p.replace("    postgres.default_database: {}", "    ssh.host_key: {}"),
            "doesn't belong to the template's protocol",
        ),
        (
            &|p| {
                p.replace(
                    "    worker_selector:",
                    "    delegated: { profile: x }\n    worker_selector:",
                )
            },
            "delegated",
        ),
        (
            &|p| p.replace("allowed: { env: [dev, staging] }", "allowed: { team: [x] }"),
            "both fixed and allowed",
        ),
    ];
    for (edit, why) in cases {
        let err = profile_error(edit);
        assert!(err.contains(why), "expected {why:?}, got {err}");
    }
}

// ---- Writers ----------------------------------------------------------------

fn writer_error(edit: &dyn Fn(&str) -> String) -> String {
    let writer = edit(WRITER);
    match Policy::parse_yaml([
        ("b.yaml", BOTS),
        ("p.yaml", PROFILE),
        ("w.yaml", writer.as_str()),
    ]) {
        Ok(_) => panic!("writer should be refused: {writer}"),
        Err(e) => e.to_string(),
    }
}

#[test]
fn a_writer_grant_is_narrow_and_points_at_real_documents() {
    let policy = Policy::parse_yaml([("b.yaml", BOTS), ("p.yaml", PROFILE), ("w.yaml", WRITER)])
        .expect("valid");
    let grant = policy.writer_for_bot("deploy-staging").expect("grant");
    assert!(grant.spec.name_allowed("payments-orders-db"));
    assert!(!grant.spec.name_allowed("payments-"));
    assert!(!grant.spec.name_allowed("orders-prod"));
    assert_eq!(grant.spec.max_documents, DEFAULT_WRITER_DOCUMENTS);

    let cases: [Case; 8] = [
        (
            &|w| w.replace("namespace: payments", "namespace: default"),
            "namespace default",
        ),
        (
            &|w| w.replace("\"payments-*\"", "\"*\""),
            "prefix of at least two",
        ),
        (
            &|w| w.replace("\"payments-*\"", "\"pay*ments*\""),
            "prefix of at least two",
        ),
        (
            &|w| w.replace("bot: deploy-staging", "bot: nobody"),
            "unknown bot",
        ),
        (
            &|w| w.replace("profiles: [payments-postgres]", "profiles: [missing]"),
            "unknown resource_profile",
        ),
        (
            &|w| w.replace("  profiles: [payments-postgres]\n", ""),
            "needs profiles",
        ),
        (
            &|w| w.replace("kinds: [resource]", "kinds: [role]"),
            "unknown variant",
        ),
        (&|w| format!("{w}  max_documents: 0\n"), "max_documents"),
    ];
    for (edit, why) in cases {
        let err = writer_error(edit);
        assert!(err.contains(why), "expected {why:?}, got {err}");
    }
    // One grant per bot.
    let second = WRITER.replace("name: payments-terraform", "name: second");
    let err = Policy::parse_yaml([
        ("b.yaml", BOTS),
        ("p.yaml", PROFILE),
        ("w.yaml", WRITER),
        ("w2.yaml", second.as_str()),
    ])
    .expect_err("two grants");
    assert!(err.to_string().contains("one grant per bot"), "{err}");
}

#[test]
fn snapshots_leave_out_profiles_and_writers() {
    let policy = Policy::parse_yaml([("b.yaml", BOTS), ("p.yaml", PROFILE), ("w.yaml", WRITER)])
        .expect("valid");
    let kinds = |docs: &[Document]| docs.iter().map(Document::kind).collect::<Vec<_>>();
    let all = kinds(&policy.documents());
    assert!(all.contains(&"resource_profile") && all.contains(&"policy_writer"));
    let snapshot = policy.snapshot_documents();
    let names = kinds(&snapshot);
    assert!(!names.contains(&"resource_profile") && !names.contains(&"policy_writer"));
    // What a component gets still parses on its own: nothing in it refers to
    // the profiles it never sees.
    Policy::from_documents(snapshot).expect("snapshot parses");
}

#[test]
fn a_delegated_resource_survives_the_snapshot_round_trip() {
    let doc = materialize(
        &profile(),
        &writer_input(&json!({ "postgres": { "endpoint": "10.20.3.4:5432" }}), &[]),
    )
    .expect("valid");
    let json = serde_json::to_string(&vec![Document::Resource(doc.clone())]).expect("json");
    let back: Vec<Document> = serde_json::from_str(&json).expect("parse");
    assert_eq!(back, [Document::Resource(doc)]);
    // A resource without the marker serializes exactly as before Phase 14.
    let plain = Policy::parse_yaml([(
        "r.yaml",
        "kind: resource\nversion: v1\nmetadata: { name: r }\nspec:\n  tcp: { address: \"db:5432\" }\n",
    )])
    .expect("plain");
    let json = serde_json::to_string(&plain.snapshot_documents()).expect("json");
    assert!(!json.contains("delegated"), "{json}");
}

// ---- Addresses --------------------------------------------------------------

#[test]
fn host_patterns_match_whole_labels() {
    let patterns = [
        "*.payments.internal".to_owned(),
        "exact.example.com".to_owned(),
    ];
    for (host, ok) in [
        ("orders.payments.internal", true),
        ("a.b.payments.internal", true),
        ("ORDERS.payments.internal.", true),
        ("payments.internal", false),
        ("evilpayments.internal", false),
        ("orders.payments.internal.evil.com", false),
        ("exact.example.com", true),
        ("sub.exact.example.com", false),
        ("", false),
    ] {
        assert_eq!(host_allowed(host, &patterns), ok, "{host}");
    }
}

#[test]
fn cidrs_and_forbidden_addresses() {
    let ip = |s: &str| s.parse::<IpAddr>().expect("ip");
    let cidrs = ["10.20.0.0/16".to_owned(), "2001:db8::/32".to_owned()];
    assert!(in_cidrs(ip("10.20.255.1"), &cidrs));
    assert!(in_cidrs(ip("::ffff:10.20.0.9"), &cidrs));
    assert!(in_cidrs(ip("2001:db8::1"), &cidrs));
    assert!(!in_cidrs(ip("10.21.0.1"), &cidrs));
    assert!(!in_cidrs(ip("2001:db9::1"), &cidrs));
    for bad in [
        "127.0.0.1",
        "0.0.0.0",
        "0.1.2.3",
        "169.254.169.254",
        "169.254.0.1",
        "224.0.0.1",
        "255.255.255.255",
        "100.100.100.200",
        "168.63.129.16",
        "::1",
        "::",
        "fe80::1",
        "ff02::1",
        "fd00:ec2::254",
        "::ffff:169.254.169.254",
    ] {
        assert!(forbidden_address(ip(bad)), "{bad} must be refused");
    }
    for fine in [
        "10.0.0.1",
        "192.168.1.10",
        "172.16.0.5",
        "2001:db8::5",
        "8.8.8.8",
    ] {
        assert!(!forbidden_address(ip(fine)), "{fine} is a normal address");
    }
}

#[test]
fn the_example_stack_stands_alone() {
    let policy = Policy::parse_yaml([("delegation.yaml", EXAMPLE)]).expect("example parses");
    let grant = policy.writer_for_bot("payments-terraform").expect("grant");
    let profile = policy.profile(&grant.spec.profiles[0]).expect("profile");
    materialize(
        profile,
        &writer_input(
            &json!({ "postgres": { "endpoint": "orders.c9xk2p.eu-west-1.rds.amazonaws.com:5432" }}),
            &[("env", "staging")],
        ),
    )
    .expect("the example's own case works");
}
