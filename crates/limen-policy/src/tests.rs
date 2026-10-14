use super::*;

const ROLES: &str = include_str!("../../../examples/policy/roles.yaml");
const MAPPINGS: &str = include_str!("../../../examples/policy/mappings.yaml");
const RESOURCES: &str = include_str!("../../../examples/policy/resources.yaml");

fn example() -> Policy {
    Policy::parse_yaml([
        ("roles.yaml", ROLES),
        ("mappings.yaml", MAPPINGS),
        ("resources.yaml", RESOURCES),
    ])
    .expect("example policy is valid")
}

fn roles(r: &[&str]) -> Vec<String> {
    r.iter().map(|s| (*s).to_owned()).collect()
}

fn ssh(login: &str) -> Principal {
    Principal::SshLogin(login.into())
}

fn db(role: &str) -> Principal {
    Principal::DbRole {
        role: role.into(),
        database: "orders".into(),
    }
}

#[test]
fn empty_policy_denies_everything() {
    let policy = Policy::default();
    let r = roles(&["sre"]);
    let d = policy.evaluate(&AccessRequest {
        roles: &r,
        resource: "anything",
        principal: ssh("root"),
    });
    assert!(!d.is_allowed());
    assert_eq!(policy.accessible(&r), []);
}

#[test]
fn allow_requires_matching_labels_kind_and_principal() {
    let p = example();
    let dev = roles(&["dev-readonly"]);
    let eval = |resource: &str, principal: Principal| {
        p.evaluate(&AccessRequest {
            roles: &dev,
            resource,
            principal,
        })
    };

    assert!(eval("orders-staging", db("limen_readonly")).is_allowed());
    assert_eq!(
        eval("orders-staging", db("limen_rw")),
        Decision::Deny {
            reason: DenyReason::NoMatchingRole
        }
    );
    assert_eq!(
        eval("orders-prod", db("limen_readonly")),
        Decision::Deny {
            reason: DenyReason::NoMatchingRole
        }
    );
    assert!(eval("web-staging-1", ssh("ubuntu")).is_allowed());
    assert!(!eval("web-staging-1", ssh("root")).is_allowed());
    assert_eq!(
        eval("orders-staging", ssh("ubuntu")),
        Decision::Deny {
            reason: DenyReason::InvalidRequest
        }
    );
    assert_eq!(
        eval("nope", ssh("ubuntu")),
        Decision::Deny {
            reason: DenyReason::UnknownResource
        }
    );
}

#[test]
fn deny_rule_wins() {
    let p = example();
    let dev = roles(&["dev-readonly"]);
    let d = p.evaluate(&AccessRequest {
        roles: &dev,
        resource: "bastion-staging",
        principal: ssh("ubuntu"),
    });
    assert_eq!(
        d,
        Decision::Deny {
            reason: DenyReason::ExplicitDeny
        }
    );
    // A deny in one role also overrides an allow from another role.
    let both = roles(&["dev-readonly", "sre"]);
    let d = p.evaluate(&AccessRequest {
        roles: &both,
        resource: "bastion-staging",
        principal: ssh("ubuntu"),
    });
    assert!(!d.is_allowed());
    // Alone, the wildcard sre role reaches the bastion.
    let sre = roles(&["sre"]);
    let d = p.evaluate(&AccessRequest {
        roles: &sre,
        resource: "bastion-staging",
        principal: ssh("ubuntu"),
    });
    assert_eq!(
        d,
        Decision::Allow {
            matched_roles: vec!["sre".into()]
        }
    );
}

#[test]
fn unknown_roles_grant_nothing() {
    let p = example();
    let r = roles(&["does-not-exist", "limen:admin"]);
    assert_eq!(p.accessible(&r), []);
}

#[test]
fn accessible_lists_resources_and_principals() {
    let p = example();
    let listed = p.accessible(&roles(&["dev-readonly"]));
    let summary: Vec<(&str, Vec<&str>)> = listed
        .iter()
        .map(|r| {
            (
                r.name.as_str(),
                r.principals.iter().map(String::as_str).collect(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            ("orders-staging", vec!["limen_readonly"]),
            ("web-staging-1", vec!["ubuntu"])
        ]
    );

    let sre = p.accessible(&roles(&["sre"]));
    let names: Vec<&str> = sre.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "bastion-staging",
            "cache-staging",
            "orders-prod",
            "orders-staging",
            "web-staging-1"
        ]
    );
}

#[test]
fn group_mapping_and_bootstrap_admins() {
    let p = example();
    let got = p.roles_for_groups(["developers", "unrelated"], &[]);
    assert_eq!(got.into_iter().collect::<Vec<_>>(), ["dev-readonly"]);
    let got = p.roles_for_groups(["ops"], &["ops".to_owned()]);
    assert_eq!(got.into_iter().collect::<Vec<_>>(), ["limen:admin"]);
    assert!(
        Policy::default()
            .roles_for_groups(["developers"], &[])
            .is_empty()
    );
}

#[test]
fn cert_ttl_takes_shortest_and_caps() {
    let p = example();
    let max = Duration::from_hours(1);
    assert_eq!(
        p.cert_ttl(&roles(&["dev-readonly", "sre"]), max),
        Duration::from_mins(10)
    );
    assert_eq!(p.cert_ttl(&roles(&["sre"]), max), Duration::from_mins(30));
    assert_eq!(
        p.cert_ttl(&roles(&["sre"]), Duration::from_mins(5)),
        Duration::from_mins(5)
    );
    assert_eq!(p.cert_ttl(&[], max), DEFAULT_CERT_TTL);
}

#[test]
fn digest_and_diff() {
    let a = example();
    let b = example();
    assert_eq!(a.digest(), b.digest());
    assert!(a.diff(&b).is_empty());

    let c =
        Policy::parse_yaml([("roles.yaml", ROLES), ("mappings.yaml", MAPPINGS)]).expect("valid");
    let diff = a.diff(&c);
    assert_eq!(diff.removed.len(), 5);
    assert!(diff.added.is_empty() && diff.changed.is_empty());
    assert_ne!(a.digest(), c.digest());
}

fn parse_err(yaml: &str) -> PolicyError {
    Policy::parse_yaml([("t.yaml", yaml)]).expect_err("should be rejected")
}

#[test]
fn rejects_invalid_documents() {
    // Unknown field.
    assert!(matches!(
        parse_err("kind: role\nversion: v1\nmetadata: {name: a}\nspec: {allow: [], bogus: 1}"),
        PolicyError::Parse { .. }
    ));
    // Unknown kind and version.
    assert!(matches!(
        parse_err("kind: user\nversion: v1\nmetadata: {name: a}\nspec: {}"),
        PolicyError::Parse { .. }
    ));
    assert!(matches!(
        parse_err("kind: role\nversion: v2\nmetadata: {name: a}\nspec: {}"),
        PolicyError::Parse { .. }
    ));
    // Empty role.
    assert!(matches!(
        parse_err("kind: role\nversion: v1\nmetadata: {name: a}\nspec: {}"),
        PolicyError::Invalid { .. }
    ));
    // Wildcard login.
    let wildcard = "kind: role\nversion: v1\nmetadata: {name: a}\nspec:\n  allow:\n    - resources: {kind: [ssh]}\n      ssh: {logins: ['*']}";
    assert!(matches!(parse_err(wildcard), PolicyError::Invalid { .. }));
    // Allow without a principal.
    let bare = "kind: role\nversion: v1\nmetadata: {name: a}\nspec:\n  allow:\n    - resources: {kind: [ssh]}";
    assert!(matches!(parse_err(bare), PolicyError::Invalid { .. }));
    // system: kube groups.
    let masters = "kind: role\nversion: v1\nmetadata: {name: a}\nspec:\n  allow:\n    - resources: {kind: [kubernetes]}\n      kube: {groups: ['system:masters']}";
    assert!(matches!(parse_err(masters), PolicyError::Invalid { .. }));
    // Mapping to an unknown role.
    let mapping = "kind: role_mapping\nversion: v1\nmetadata: {name: m}\nspec:\n  - {idp_group: g, roles: [ghost]}";
    assert!(matches!(parse_err(mapping), PolicyError::Invalid { .. }));
    // Resource with two protocols, and with a bad address.
    let two = "kind: resource\nversion: v1\nmetadata: {name: r}\nspec:\n  ssh: {address: 'h:22'}\n  redis: {endpoint: 'h:6379'}";
    assert!(matches!(parse_err(two), PolicyError::Invalid { .. }));
    let bad_addr =
        "kind: resource\nversion: v1\nmetadata: {name: r}\nspec:\n  ssh: {address: 'nohost'}";
    assert!(matches!(parse_err(bad_addr), PolicyError::Invalid { .. }));
    // Uppercase names and duplicates.
    let upper =
        "kind: resource\nversion: v1\nmetadata: {name: Prod}\nspec:\n  ssh: {address: 'h:22'}";
    assert!(matches!(parse_err(upper), PolicyError::Invalid { .. }));
    let dup = format!(
        "{RESOURCES}\n---\n{}",
        RESOURCES.split("---").next().expect("first doc")
    );
    assert!(matches!(parse_err(&dup), PolicyError::Duplicate { .. }));
}

#[test]
fn requires_approval_is_not_allowed() {
    assert!(
        !Decision::RequiresApproval {
            reason: "jit".into()
        }
        .is_allowed()
    );
}

#[test]
fn worker_selector_matching() {
    let p = example();
    let dev: BTreeMap<String, String> = [
        ("pool".to_owned(), "dev".to_owned()),
        ("az".to_owned(), "a".to_owned()),
    ]
    .into();
    let prod: BTreeMap<String, String> = [("pool".to_owned(), "prod".to_owned())].into();
    assert!(p.worker_may_serve("web-staging-1", &dev));
    assert!(!p.worker_may_serve("web-staging-1", &prod));
    assert!(!p.worker_may_serve("web-staging-1", &BTreeMap::new()));
    assert!(p.worker_may_serve("orders-prod", &prod));
    assert!(!p.worker_may_serve("no-such-resource", &dev));
}
