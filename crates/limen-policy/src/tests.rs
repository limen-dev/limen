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
            ("cache-staging", vec!["limen-ro"]),
            ("cache-valkey", vec!["limen-ro"]),
            ("catalog-staging", vec!["limen-read"]),
            ("catalog-x509", vec!["limen-read"]),
            ("orders-mysql-staging", vec!["limen_readonly"]),
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
            "cache-valkey",
            "catalog-atlas",
            "catalog-staging",
            "catalog-x509",
            "orders-mysql-staging",
            "orders-prod",
            "orders-staging",
            "reviews-docdb",
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
    assert_eq!(diff.removed.len(), 11);
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

mod planned_integrations {
    use super::*;

    const PLANNED: &str = include_str!("../../../examples/policy/planned.yaml");

    fn with_planned() -> Policy {
        Policy::parse_yaml([
            ("roles.yaml", ROLES),
            ("mappings.yaml", MAPPINGS),
            ("resources.yaml", RESOURCES),
            ("planned.yaml", PLANNED),
        ])
        .expect("example policy with the planned integrations is valid")
    }

    #[test]
    fn every_planned_kind_has_an_example_resource() {
        let policy = with_planned();
        let admin = roles(&["sre", "sre-planned"]);
        let kinds: std::collections::HashSet<_> =
            policy.accessible(&admin).iter().map(|r| r.kind).collect();
        for kind in ResourceKind::ALL {
            assert!(kinds.contains(&kind), "no example resource for {kind:?}");
        }
    }

    #[test]
    fn developers_get_staging_only_and_read_only_principals() {
        let policy = with_planned();
        let dev = roles(&["dev-readonly", "dev-planned"]);
        let seen = policy.accessible(&dev);
        let names: Vec<_> = seen.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"catalog-staging") && names.contains(&"grafana"));
        assert!(!names.contains(&"catalog-atlas"), "prod stays hidden");
        assert!(
            !names.contains(&"legacy-ftp"),
            "tcp is not granted to developers"
        );
        let mongo = seen
            .iter()
            .find(|r| r.name == "catalog-staging")
            .expect("seen");
        assert_eq!(mongo.principals, ["limen-read"]);
    }

    #[test]
    fn principals_must_fit_the_kind() {
        let policy = with_planned();
        let sre = roles(&["sre", "sre-planned"]);
        let eval = |resource: &str, principal: Principal| {
            policy.evaluate(&AccessRequest {
                roles: &sre,
                resource,
                principal,
            })
        };
        assert!(
            eval(
                "catalog-atlas",
                Principal::MongoRole {
                    role: "limen-rw".into(),
                    database: "shop".into()
                }
            )
            .is_allowed()
        );
        assert!(
            eval(
                "logs-opensearch",
                Principal::SearchRole("limen-read".into())
            )
            .is_allowed()
        );
        assert!(eval("orders-mq", Principal::MqUser("limen-admin".into())).is_allowed());
        assert!(
            eval(
                "payments-msk",
                Principal::KafkaUser("limen-consumer".into())
            )
            .is_allowed()
        );
        assert!(eval("grafana", Principal::WebAccess).is_allowed());
        assert!(eval("legacy-ftp", Principal::TcpAccess).is_allowed());
        assert!(
            eval("warehouse-prod", db("limen_rw")).is_allowed(),
            "redshift uses the db grant"
        );
        // The wrong kind of principal for a resource is an invalid request, not a quiet allow.
        assert_eq!(
            eval("grafana", Principal::TcpAccess),
            Decision::Deny {
                reason: DenyReason::InvalidRequest
            }
        );
        assert_eq!(
            eval("catalog-atlas", Principal::SearchRole("limen-read".into())),
            Decision::Deny {
                reason: DenyReason::InvalidRequest
            }
        );
    }

    #[test]
    fn a_resource_has_exactly_one_kind_and_valid_addresses() {
        let two = "kind: resource\nversion: v1\nmetadata: { name: x }\nspec:\n  kafka: { endpoint: \"k:9092\" }\n  tcp: { address: \"t:1\" }\n";
        assert!(Policy::parse_yaml([("x.yaml", two)]).is_err());
        let bad = "kind: resource\nversion: v1\nmetadata: { name: x }\nspec:\n  web: { address: \"no-port\", host: \"a.example.com\" }\n";
        assert!(Policy::parse_yaml([("x.yaml", bad)]).is_err());
        let unknown = "kind: resource\nversion: v1\nmetadata: { name: x }\nspec:\n  mongodb: { endpoint: \"m:1\", flavour: atlas }\n";
        assert!(
            Policy::parse_yaml([("x.yaml", unknown)]).is_err(),
            "typos are rejected"
        );
    }

    #[test]
    fn web_grants_take_no_fields() {
        let role = "kind: role\nversion: v1\nmetadata: { name: r }\nspec:\n  allow:\n    - resources: { kind: [web], labels: { \"*\": [\"*\"] } }\n      web: { paths: [\"/\"] }\n";
        assert!(Policy::parse_yaml([("r.yaml", role)]).is_err());
    }
}

#[test]
fn every_example_resource_has_a_target_to_show() {
    let policy = Policy::parse_yaml([
        ("roles.yaml", ROLES),
        ("mappings.yaml", MAPPINGS),
        ("resources.yaml", RESOURCES),
        (
            "planned.yaml",
            include_str!("../../../examples/policy/planned.yaml"),
        ),
    ])
    .expect("valid");
    for (name, resource) in &policy.resources {
        assert!(
            resource.spec.target().is_some_and(|t| !t.is_empty()),
            "{name} has no target text"
        );
    }
}

mod bots {
    use super::*;
    use crate::bot::JoinMethod;

    const BOTS: &str = include_str!("../../../examples/policy/bots.yaml");

    fn with_bots() -> Policy {
        Policy::parse_yaml([
            ("roles.yaml", ROLES),
            ("mappings.yaml", MAPPINGS),
            ("resources.yaml", RESOURCES),
            ("bots.yaml", BOTS),
        ])
        .expect("example policy with bots is valid")
    }

    fn bot_doc(body: &str) -> String {
        format!(
            "kind: role\nversion: v1\nmetadata: {{ name: r }}\nspec:\n  allow:\n    - resources: {{ kind: [ssh], labels: {{ \"*\": [\"*\"] }} }}\n      ssh: {{ logins: [ubuntu] }}\n---\nkind: bot\nversion: v1\nmetadata: {{ name: b }}\nspec:\n  roles: [r]\n{body}"
        )
    }

    fn rejected(body: &str) -> String {
        match Policy::parse_yaml([("b.yaml", bot_doc(body).as_str())]) {
            Ok(_) => panic!("accepted:\n{body}"),
            Err(e) => e.to_string(),
        }
    }

    fn claims(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect()
    }

    #[test]
    fn the_example_bots_are_valid_and_have_usernames() {
        let p = with_bots();
        let names: Vec<_> = p.bots().map(BotDocExt::username_for_test).collect();
        assert_eq!(
            names,
            ["bot:argo-sync", "bot:deploy-staging", "bot:nightly-report"]
        );
        assert_eq!(p.bot("deploy-staging").expect("bot").ttl().as_secs(), 900);
        assert_eq!(
            p.bot("argo-sync").expect("bot").ttl().as_secs(),
            900,
            "default is 15 minutes"
        );
    }

    trait BotDocExt {
        fn username_for_test(&self) -> String;
    }
    impl BotDocExt for crate::bot::BotDoc {
        fn username_for_test(&self) -> String {
            self.username()
        }
    }

    #[test]
    fn a_repository_alone_is_refused() {
        let e = rejected(
            "  join:\n    method: github_actions\n    match: { repository: acme/infra }\n",
        );
        assert!(e.contains("repository alone"), "{e}");
    }

    #[test]
    fn wildcards_pull_requests_and_builtin_roles_are_refused() {
        assert!(rejected("  join:\n    method: github_actions\n    match: { repository: \"acme/*\", ref: refs/heads/main }\n").contains("wildcard"));
        assert!(rejected("  join:\n    method: github_actions\n    match: { repository: acme/infra, ref: refs/pull/7/merge }\n").contains("pull request"));
        assert!(rejected("  join:\n    method: github_actions\n    match: { repository: acme/infra, ref: refs/heads/main, event_name: pull_request_target }\n").contains("pull request"));
        let admin = bot_doc("  join:\n    method: github_actions\n    match: { repository: acme/infra, ref: refs/heads/main }\n").replace("roles: [r]", "roles: [\"limen:admin\"]");
        assert!(
            Policy::parse_yaml([("b.yaml", admin.as_str())])
                .expect_err("rejected")
                .to_string()
                .contains("built-in role")
        );
    }

    #[test]
    fn method_specific_rules() {
        assert!(
            rejected(
                "  join:\n    method: gitlab\n    match: { project_path: acme/x, ref: main }\n"
            )
            .contains("ref_protected")
        );
        assert!(
            rejected("  join:\n    method: gitlab\n    match: { project_path: acme/x }\n")
                .contains("`ref` or `environment`")
        );
        assert!(
            rejected("  join:\n    method: oidc\n    match: { sub: x }\n")
                .contains("needs join.issuer")
        );
        assert!(rejected("  join:\n    method: oidc\n    issuer: https://i.example.com\n    match: { aud: x }\n").contains("`sub`"));
        assert!(rejected("  join:\n    method: oidc\n    issuer: \"https://u:p@i.example.com\"\n    match: { sub: x }\n").contains("credentials"));
        assert!(
            rejected("  join:\n    method: github_actions\n    match: {}\n")
                .contains("at least one claim")
        );
    }

    #[test]
    fn lifetimes_and_unknown_roles() {
        assert!(rejected("  max_ttl: 2h\n  join:\n    method: github_actions\n    match: { repository: a/b, ref: refs/heads/main }\n").contains("at most 1h"));
        let unknown = bot_doc("  join:\n    method: github_actions\n    match: { repository: a/b, ref: refs/heads/main }\n").replace("roles: [r]", "roles: [nope]");
        assert!(
            Policy::parse_yaml([("b.yaml", unknown.as_str())])
                .expect_err("rejected")
                .to_string()
                .contains("unknown role")
        );
        let typo = bot_doc("  join:\n    metod: github_actions\n    match: {}\n");
        assert!(
            Policy::parse_yaml([("b.yaml", typo.as_str())]).is_err(),
            "typos are rejected"
        );
    }

    #[test]
    fn matching_is_exact_and_needs_every_claim() {
        let p = with_bots();
        let issuer = "https://token.actions.githubusercontent.com";
        let good = claims(&[
            ("repository", "acme/infra"),
            ("ref", "refs/heads/main"),
            ("environment", "staging"),
            ("actor", "someone"),
        ]);
        let found = p.match_bots(JoinMethod::GithubActions, issuer, &good, None);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].metadata.name, "deploy-staging");
        // A trailing slash on the issuer makes no difference.
        assert_eq!(
            p.match_bots(
                JoinMethod::GithubActions,
                &format!("{issuer}/"),
                &good,
                None
            )
            .len(),
            1
        );
        for wrong in [
            claims(&[
                ("repository", "acme/infra"),
                ("ref", "refs/heads/feature"),
                ("environment", "staging"),
            ]),
            claims(&[
                ("repository", "acme/infra-evil"),
                ("ref", "refs/heads/main"),
                ("environment", "staging"),
            ]),
            claims(&[("repository", "acme/infra"), ("ref", "refs/heads/main")]),
            claims(&[]),
        ] {
            assert!(
                p.match_bots(JoinMethod::GithubActions, issuer, &wrong, None)
                    .is_empty(),
                "{wrong:?}"
            );
        }
        assert!(
            p.match_bots(
                JoinMethod::GithubActions,
                "https://evil.example.com",
                &good,
                None
            )
            .is_empty(),
            "wrong issuer"
        );
        assert!(
            p.match_bots(JoinMethod::Gitlab, issuer, &good, None)
                .is_empty(),
            "wrong method"
        );
        assert!(
            p.match_bots(JoinMethod::GithubActions, issuer, &good, Some("argo-sync"))
                .is_empty(),
            "named bot must match"
        );
    }

    #[test]
    fn a_pull_request_run_never_matches_a_github_rule_whatever_it_names() {
        // Valid: a repository and an environment. Nothing in it mentions pull
        // requests, so only the matcher can keep them out.
        let policy = Policy::parse_yaml([(
            "b.yaml",
            bot_doc("  join:\n    method: github_actions\n    match: { repository: acme/infra, environment: staging }\n")
                .as_str(),
        )])
        .expect("valid rule");
        let issuer = "https://token.actions.githubusercontent.com";
        let run = |event: &str, git_ref: &str| {
            claims(&[
                ("repository", "acme/infra"),
                ("environment", "staging"),
                ("event_name", event),
                ("ref", git_ref),
            ])
        };
        let found = |c: &BTreeMap<String, String>| {
            policy
                .match_bots(JoinMethod::GithubActions, issuer, c, None)
                .len()
        };
        assert_eq!(found(&run("push", "refs/heads/main")), 1);
        assert_eq!(found(&run("workflow_dispatch", "refs/heads/main")), 1);
        assert_eq!(
            found(&run("pull_request", "refs/pull/7/merge")),
            0,
            "pull_request"
        );
        assert_eq!(
            found(&run("pull_request_target", "refs/heads/main")),
            0,
            "pull_request_target"
        );
        assert_eq!(
            found(&run("push", "refs/pull/7/merge")),
            0,
            "a pull request ref on its own"
        );
    }

    #[test]
    fn issuers_are_listed_per_method() {
        let p = with_bots();
        assert_eq!(
            p.bot_issuers(JoinMethod::Gitlab)
                .into_iter()
                .collect::<Vec<_>>(),
            ["https://gitlab.com"]
        );
        assert_eq!(
            p.bot_issuers(JoinMethod::Oidc)
                .into_iter()
                .collect::<Vec<_>>(),
            ["https://oidc.argo.example.com"]
        );
    }

    #[test]
    fn bots_show_up_in_digests_and_diffs() {
        let without = example();
        let with = with_bots();
        assert_ne!(without.digest(), with.digest());
        let diff = without.diff(&with);
        assert!(diff.added.contains(&"bot/deploy-staging".to_owned()));
        assert!(diff.added.contains(&"role/deployer".to_owned()));
    }
}

#[test]
fn kube_groups_are_what_the_roles_grant_minus_denies() {
    let docs = "\
kind: resource
version: v1
metadata: {name: eks-dev, labels: {env: dev}}
spec:
  kubernetes: {cluster_name: dev}
---
kind: resource
version: v1
metadata: {name: web-dev, labels: {env: dev}}
spec:
  ssh: {address: 'h:22', host_key: 'ssh-ed25519 AAAA'}
---
kind: role
version: v1
metadata: {name: dev}
spec:
  allow:
    - resources: {kind: [kubernetes], labels: {env: [dev]}}
      kube: {groups: ['limen:view', 'limen:edit']}
  deny:
    - resources: {kind: [kubernetes]}
      kube: {groups: ['limen:edit']}
---
kind: role
version: v1
metadata: {name: viewer}
spec:
  allow:
    - resources: {kind: [kubernetes]}
      kube: {groups: ['limen:view']}
";
    let p = Policy::parse_yaml([("p.yaml", docs)]).expect("valid");
    assert_eq!(p.kube_groups(&roles(&["dev"]), "eks-dev"), ["limen:view"]);
    assert_eq!(
        p.kube_groups(&roles(&["dev", "viewer"]), "eks-dev"),
        ["limen:view"]
    );
    assert_eq!(
        p.kube_groups(&roles(&["nobody"]), "eks-dev"),
        Vec::<String>::new()
    );
    assert!(
        p.kube_groups(&roles(&["dev"]), "web-dev").is_empty(),
        "not a cluster"
    );
    assert_eq!(
        p.kube_groups(&roles(&["dev"]), "ghost"),
        Vec::<String>::new()
    );
}

#[test]
fn redis_grants_come_from_matching_allow_rules() {
    let docs = "kind: role\nversion: v1\nmetadata: {name: cachers}\nspec:\n  allow:\n    - resources: {kind: [redis], labels: {env: [staging]}}\n      redis: {users: [limen-ro], keys: ['session:*'], deny_commands: [KEYS]}\n    - resources: {kind: [redis], labels: {env: [prod]}}\n      redis: {users: [limen-ro]}";
    let policy =
        Policy::parse_yaml([("roles.yaml", docs), ("resources.yaml", RESOURCES)]).expect("valid");
    let r = roles(&["cachers"]);
    let grants = policy.redis_grants(&r, "cache-staging", "limen-ro");
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].keys, ["session:*"]);
    assert_eq!(grants[0].deny_commands, ["KEYS"]);
    let none = |roles: &[String], resource: &str, user: &str| {
        policy.redis_grants(roles, resource, user).len()
    };
    assert_eq!(none(&r, "cache-staging", "limen-rw"), 0);
    assert_eq!(none(&r, "nope", "limen-ro"), 0);
    assert_eq!(none(&roles(&["ghost"]), "cache-staging", "limen-ro"), 0);
}

#[test]
fn rejects_blank_redis_restrictions() {
    let bad = "kind: role\nversion: v1\nmetadata: {name: a}\nspec:\n  allow:\n    - resources: {kind: [redis]}\n      redis: {users: [u], deny_commands: ['']}";
    assert!(matches!(parse_err(bad), PolicyError::Invalid { .. }));
}

#[test]
fn a_component_name_can_not_be_a_worker_selector() {
    let err = Policy::parse_yaml([(
        "p.yaml",
        r#"
kind: resource
version: v1
metadata: { name: by-name }
spec:
  ssh: { address: "10.0.0.1:22" }
  worker_selector: { limen.io/name: prod-a-worker-1 }
"#,
    )])
    .expect_err("names are display only");
    assert!(err.to_string().contains("limen.io/name"), "{err}");
}

#[test]
fn the_matcher_ignores_a_name_selector_even_if_one_gets_through() {
    // Validation refuses such a selector; this is the second lock, for a
    // policy stored before the rule existed.
    let mut p = example();
    let resource = p.resources.get_mut("web-staging-1").expect("resource");
    resource.spec.worker_selector = limen_core::labels::Labels::default();
    resource
        .spec
        .worker_selector
        .insert("limen.io/name", "prod-a-worker-1")
        .expect("a valid label");
    let named: BTreeMap<String, String> =
        [("limen.io/name".to_owned(), "prod-a-worker-1".to_owned())].into();
    assert!(!p.worker_may_serve("web-staging-1", &named));
}

mod mongodb {
    use super::*;

    fn resource(spec: &str) -> Result<Policy, PolicyError> {
        let doc = format!(
            "kind: resource\nversion: v1\nmetadata: {{ name: m }}\nspec:\n  mongodb: {{ {spec} }}\n"
        );
        Policy::parse_yaml([("m.yaml", doc.as_str())])
    }

    fn role(grant: &str) -> Result<Policy, PolicyError> {
        let doc = format!(
            "kind: role\nversion: v1\nmetadata: {{ name: r }}\nspec:\n  allow:\n    - resources: {{ kind: [mongodb], labels: {{ \"*\": [\"*\"] }} }}\n      mongo: {{ {grant} }}\n"
        );
        Policy::parse_yaml([("r.yaml", doc.as_str())])
    }

    #[test]
    fn a_scram_resource_needs_credentials_and_an_x509_one_cannot_be_documentdb() {
        assert!(
            resource("endpoint: \"m:27017\", credentials_dir: /c, tls_ca_file: /ca.pem").is_ok()
        );
        assert!(resource("endpoint: \"m:27017\", tls_ca_file: /ca.pem").is_err());
        assert!(
            resource("endpoint: \"m:27017\", flavor: documentdb, auth: x509, credentials_dir: /c")
                .is_err()
        );
        assert!(
            resource("endpoint: \"m:27017\", flavor: atlas, auth: x509, credentials_dir: /c")
                .is_ok()
        );
    }

    #[test]
    fn iam_login_is_for_atlas_and_documentdb_and_uses_the_external_source() {
        assert!(resource("endpoint: \"m:27017\", flavor: atlas, auth: aws").is_ok());
        assert!(resource("endpoint: \"m:27017\", auth: aws").is_err());
        assert!(
            resource("endpoint: \"m:27017\", flavor: documentdb, auth: aws, auth_source: admin")
                .is_err()
        );
    }

    #[test]
    fn insecure_dev_is_only_for_standard_servers() {
        assert!(resource("endpoint: \"m:27017\", credentials_dir: /c, insecure_dev: true").is_ok());
        assert!(
            resource(
                "endpoint: \"m:27017\", flavor: atlas, credentials_dir: /c, insecure_dev: true"
            )
            .is_err()
        );
    }

    #[test]
    fn names_that_reach_the_filesystem_or_the_server_are_checked() {
        assert!(valid_mongo_role("limen-read") && valid_mongo_role("limen_rw.1"));
        assert!(
            !valid_mongo_role("../etc") && !valid_mongo_role(".hidden") && !valid_mongo_role("")
        );
        assert!(!valid_mongo_role("a/b") && !valid_mongo_role(&"x".repeat(65)));
        assert!(valid_mongo_database("orders") && valid_mongo_database("shop-2"));
        assert!(
            !valid_mongo_database("a.b")
                && !valid_mongo_database("a b")
                && !valid_mongo_database("$x")
        );
        assert!(role("roles: [\"../x\"]").is_err());
        assert!(role("roles: [limen-read], databases: [\"a.b\"]").is_err());
        assert!(role("roles: [limen-read], databases: [orders, \"*\"]").is_ok());
        assert!(role("roles: [limen-read], deny_commands: [\"drop;\"]").is_err());
        assert!(role("roles: [limen-read], deny_commands: [drop, dropDatabase]").is_ok());
    }

    #[test]
    fn a_session_may_do_what_any_covering_grant_permits() {
        let roles_doc = r#"
kind: role
version: v1
metadata: { name: dev }
spec:
  allow:
    - resources: { kind: [mongodb], labels: { "*": ["*"] } }
      mongo: { roles: [limen-read], databases: [orders], deny_commands: [drop] }
    - resources: { kind: [mongodb], labels: { "*": ["*"] } }
      mongo: { roles: [limen-rw], databases: ["*"] }
"#;
        let res = "kind: resource\nversion: v1\nmetadata: { name: m }\nspec:\n  mongodb: { endpoint: \"m:1\", credentials_dir: /c }\n";
        let p = Policy::parse_yaml([("r.yaml", roles_doc), ("m.yaml", res)]).expect("policy");
        let dev = roles(&["dev"]);
        let grants = p.mongo_grants(&dev, "m", "limen-read");
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].deny_commands, ["drop"]);
        assert!(matches!(
            p.mongo_grants(&dev, "m", "limen-other").as_slice(),
            []
        ));
        assert!(matches!(
            p.mongo_grants(&dev, "nope", "limen-read").as_slice(),
            []
        ));
        let eval = |role: &str, database: &str| {
            p.evaluate(&AccessRequest {
                roles: &dev,
                resource: "m",
                principal: Principal::MongoRole {
                    role: role.into(),
                    database: database.into(),
                },
            })
            .is_allowed()
        };
        assert!(eval("limen-read", "orders"));
        assert!(!eval("limen-read", "billing"), "only the granted databases");
        assert!(eval("limen-rw", "billing"));
    }
}
