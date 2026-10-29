use std::collections::BTreeMap;
use std::sync::Arc;

use limen_policy::{Document, Policy};
use serde_json::json;
use time::OffsetDateTime;

use super::*;

const PROFILE: &str = include_str!("../../../../examples/policy/stacks/delegation/policy.yaml");

fn api(namespace: &str, source: &str) -> Owner {
    Owner {
        channel: Channel::Api,
        source: source.into(),
        namespace: namespace.into(),
    }
}

fn tcp(name: &str) -> Input {
    let doc = Policy::parse_yaml_documents([(
        "r.yaml",
        format!("kind: resource\nversion: v1\nmetadata: {{ name: {name} }}\nspec:\n  tcp: {{ address: \"db.internal:5432\" }}\n").as_str(),
    )])
    .expect("parse")
    .remove(0);
    Input::document(&doc).expect("input")
}

/// Heads as `apply` leaves them, with etags as a save would set them.
fn run(heads: &mut BTreeMap<Key, Head>, change: &Change) -> Result<(), StoreError> {
    let (mut touched, mut deleted) = (Vec::new(), Vec::new());
    apply(heads, change, "alice", &mut touched, &mut deleted)?;
    for head in heads.values_mut() {
        if head.etag.is_empty() {
            head.etag = etag(head);
        }
    }
    Ok(())
}

fn replace(owner: &Owner, docs: Vec<Input>) -> Change {
    Change::ReplaceSource {
        owner: owner.clone(),
        documents: docs,
    }
}

#[test]
fn a_source_replaces_only_its_own_documents() {
    let git = Owner::default_git();
    let tf = api("payments", "terraform/prod");
    let mut heads = BTreeMap::new();
    run(&mut heads, &replace(&git, vec![tcp("a"), tcp("b")])).expect("git");
    run(
        &mut heads,
        &Change::Create {
            owner: tf.clone(),
            input: tcp("payments-db"),
        },
    )
    .expect("tf");
    // The next apply from files drops `b` and leaves Terraform's resource.
    run(&mut heads, &replace(&git, vec![tcp("a")])).expect("git again");
    let names: Vec<_> = heads.keys().map(|(_, n)| n.as_str()).collect();
    assert_eq!(names, ["a", "payments-db"]);
    // Files can't take over a document Terraform manages.
    let err = run(
        &mut heads,
        &replace(&git, vec![tcp("a"), tcp("payments-db")]),
    )
    .expect_err("owned");
    assert!(
        matches!(err, StoreError::OwnedElsewhere { ref owner, .. } if *owner == tf),
        "{err}"
    );
    assert!(err.to_string().contains("terraform/prod"), "{err}");
}

#[test]
fn writes_follow_existence_etags_and_owners() {
    let tf = api("payments", "terraform/prod");
    let other = api("payments", "terraform/staging");
    let mut heads = BTreeMap::new();
    run(
        &mut heads,
        &Change::Create {
            owner: tf.clone(),
            input: tcp("payments-db"),
        },
    )
    .expect("create");
    let key = ("resource".to_owned(), "payments-db".to_owned());
    let etag = heads[&key].etag.clone();
    assert!(matches!(
        run(
            &mut heads,
            &Change::Create {
                owner: tf.clone(),
                input: tcp("payments-db")
            }
        ),
        Err(StoreError::AlreadyExists(_))
    ));
    assert!(matches!(
        run(&mut heads, &Change::Update { owner: tf.clone(), input: tcp("payments-db"), etag: "stale".into() }),
        Err(StoreError::EtagMismatch { ref current, .. }) if *current == etag
    ));
    // The same namespace but another source is still another owner.
    assert!(matches!(
        run(
            &mut heads,
            &Change::Update {
                owner: other.clone(),
                input: tcp("payments-db"),
                etag: etag.clone()
            }
        ),
        Err(StoreError::OwnedElsewhere { .. })
    ));
    assert!(matches!(
        run(
            &mut heads,
            &Change::Delete {
                owner: other,
                key: key.clone(),
                etag: None,
                allow_missing: false
            }
        ),
        Err(StoreError::OwnedElsewhere { .. })
    ));
    run(
        &mut heads,
        &Change::Delete {
            owner: tf.clone(),
            key: key.clone(),
            etag: Some(etag),
            allow_missing: false,
        },
    )
    .expect("delete");
    assert!(matches!(
        run(
            &mut heads,
            &Change::Delete {
                owner: tf.clone(),
                key: key.clone(),
                etag: None,
                allow_missing: false
            }
        ),
        Err(StoreError::NotFound(_))
    ));
    run(
        &mut heads,
        &Change::Delete {
            owner: tf,
            key,
            etag: None,
            allow_missing: true,
        },
    )
    .expect("missing is fine");
}

fn delegated_heads() -> BTreeMap<Key, Head> {
    let git = Owner::default_git();
    let docs = Policy::parse_yaml_documents([("p.yaml", PROFILE)]).expect("parse");
    let mut heads = BTreeMap::new();
    run(
        &mut heads,
        &replace(
            &git,
            docs.iter()
                .map(|d| Input::document(d).expect("input"))
                .collect(),
        ),
    )
    .expect("git");
    run(
        &mut heads,
        &Change::Create {
            owner: api("payments", "terraform/prod"),
            input: Input {
                kind: "resource".into(),
                name: "payments-orders-db".into(),
                value: json!({
                    "kind": "resource",
                    "metadata": { "labels": { "env": "staging" } },
                    "spec": { "postgres": { "endpoint": "orders.c9xk2p.eu-west-1.rds.amazonaws.com:5432" } }
                }),
                profile: Some("payments-postgres".into()),
            },
        },
    )
    .expect("writer");
    heads
}

#[test]
fn a_writer_resource_is_built_from_its_profile_which_cant_go_while_used() {
    let heads = delegated_heads();
    let docs = effective(&heads).expect("effective");
    let resource = docs
        .iter()
        .find_map(|d| match d {
            Document::Resource(r) if r.metadata.name == "payments-orders-db" => Some(r),
            _ => None,
        })
        .expect("materialized");
    assert!(resource.spec.postgres.as_ref().expect("pg").iam_auth);
    assert_eq!(resource.metadata.labels.get("team"), Some("payments"));
    assert!(resource.spec.delegated.is_some());
    Policy::from_documents(docs).expect("valid policy");

    // Files that drop the profile (and the writer grant) are refused while
    // the resource still completes it.
    let mut heads = heads;
    let without: Vec<Input> = Policy::parse_yaml_documents([("p.yaml", PROFILE)])
        .expect("parse")
        .iter()
        .filter(|d| !matches!(d, Document::ResourceProfile(_) | Document::PolicyWriter(_)))
        .map(|d| Input::document(d).expect("input"))
        .collect();
    run(&mut heads, &replace(&Owner::default_git(), without)).expect("apply");
    let err = check_profiles_in_use(&heads).expect_err("in use");
    assert!(err.to_string().contains("payments-orders-db"), "{err}");
}

fn loaded(policy: Policy, version: i64) -> LoadedPolicy {
    LoadedPolicy {
        version,
        policy: Arc::new(policy),
        author: "old-replica".into(),
        created_at: Some(OffsetDateTime::now_utc()),
    }
}

#[test]
fn heads_catch_up_with_a_version_applied_without_them() {
    let heads = delegated_heads();
    // In agreement: nothing to do.
    let agreed = Policy::from_documents(effective(&heads).expect("eff")).expect("policy");
    assert_eq!(reconcile(heads.clone(), &loaded(agreed, 3)), heads);

    // A replica from before Phase 14 applied files that dropped `payments-ci`
    // and kept everything else, including the materialized resource.
    let mut docs = effective(&heads).expect("eff");
    docs.retain(|d| {
        d.name() != "payments-ci" && !matches!(d, Document::Bot(_) | Document::PolicyWriter(_))
    });
    let latest = Policy::from_documents(docs).expect("policy");
    let rebuilt = reconcile(heads.clone(), &loaded(latest.clone(), 4));
    assert!(!rebuilt.contains_key(&("role".into(), "payments-ci".into())));
    // The writer's resource keeps its owner and its profile: its result is
    // what the version has.
    let resource = &rebuilt[&("resource".to_owned(), "payments-orders-db".to_owned())];
    assert_eq!(resource.owner, api("payments", "terraform/prod"));
    assert_eq!(resource.profile.as_deref(), Some("payments-postgres"));
    let again = Policy::from_documents(effective(&rebuilt).expect("eff")).expect("policy");
    assert_eq!(again.digest(), latest.digest());
}

#[test]
fn etags_follow_content_and_owner() {
    let mut heads = BTreeMap::new();
    run(
        &mut heads,
        &Change::Create {
            owner: api("payments", "a"),
            input: tcp("payments-db"),
        },
    )
    .expect("create");
    let head = heads.values().next().expect("head").clone();
    let moved = Head {
        owner: api("payments", "b"),
        ..head.clone()
    };
    assert_ne!(etag(&head), etag(&moved));
    assert_eq!(etag(&head), etag(&head.clone()));
}

#[test]
fn sources_are_short_and_plain() {
    for ok in [
        "default",
        "github.com/acme/limen-policy",
        "terraform/payments-prod",
        "ci@main:1",
    ] {
        validate_source(ok).expect(ok);
    }
    for bad in ["", "has space", "new\nline", &"x".repeat(201)] {
        assert!(validate_source(bad).is_err(), "{bad:?}");
    }
}
