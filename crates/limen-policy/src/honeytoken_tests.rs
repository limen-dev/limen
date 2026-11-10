//! Honeytoken resources (ADR-0050): a decoy is listed for the roles it is
//! exposed to and reachable by nothing, whatever a role's selectors say.

#![allow(clippy::assert_is_empty)]

use super::*;

const ROLES: &str = r"
kind: role
version: v1
metadata: { name: everything }
spec:
  allow:
    - resources: { kind: [ssh, postgres, kubernetes, redis, tcp], labels: { '*': ['*'] } }
      ssh: { logins: [root] }
      db: { roles: [limen_read], databases: [x] }
      kube: { groups: [devs] }
      redis: { users: [default], keys: ['*'] }
      tcp: {}
---
kind: role
version: v1
metadata: { name: named }
spec:
  allow:
    - resources: { kind: [ssh], names: [prod-backup-db] }
      ssh: { logins: [root] }
---
kind: role
version: v1
metadata: { name: bait }
spec:
  allow:
    - resources: { kind: [ssh], names: [web-1] }
      ssh: { logins: [ubuntu] }
";

const REAL: &str = r"
kind: resource
version: v1
metadata: { name: web-1, labels: { env: prod } }
spec:
  ssh: { address: 'web-1:22' }
";

const DECOY: &str = r"
kind: resource
version: v1
metadata: { name: prod-backup-db, labels: { env: prod } }
spec:
  honeytoken:
    kind: postgres
    principals: [backup_admin, readonly]
    exposed_to: [bait]
";

fn policy(docs: &[&str]) -> Result<Policy, PolicyError> {
    let named: Vec<(String, &str)> = docs
        .iter()
        .enumerate()
        .map(|(i, d)| (format!("doc{i}.yaml"), *d))
        .collect();
    Policy::parse_yaml(named.iter().map(|(n, d)| (n.as_str(), *d)))
}

fn roles(r: &[&str]) -> Vec<String> {
    r.iter().map(|s| (*s).to_owned()).collect()
}

fn with_decoy() -> Policy {
    policy(&[ROLES, REAL, DECOY]).expect("valid")
}

fn invalid_text(docs: &[&str]) -> String {
    policy(docs).expect_err("must be refused").to_string()
}

#[test]
fn a_decoy_is_in_its_own_map_and_nowhere_a_grant_looks() {
    let p = with_decoy();
    assert!(p.honeytoken("prod-backup-db").is_some());
    assert!(p.resource("prod-backup-db").is_none());
    assert!(p.resources().all(|r| r.metadata.name != "prod-backup-db"));
    assert_eq!(p.resource_count(), 1);
    assert!(p.honeytoken("web-1").is_none());
    assert_eq!(p.honeytokens().count(), 1);
}

#[test]
fn no_role_reaches_a_decoy_not_even_one_that_matches_everything() {
    let p = with_decoy();
    // `everything` matches every label and kind; `named` names the decoy.
    for held in [roles(&["everything"]), roles(&["named"]), roles(&["bait"])] {
        assert!(
            p.accessible(&held)
                .iter()
                .all(|r| r.name != "prod-backup-db"),
            "{held:?}"
        );
        for principal in [
            Principal::SshLogin("root".into()),
            Principal::DbRole {
                role: "limen_read".into(),
                database: "x".into(),
            },
            Principal::KubeGroup("devs".into()),
            Principal::RedisUser("default".into()),
            Principal::TcpAccess,
        ] {
            let d = p.evaluate(&AccessRequest {
                roles: &held,
                resource: "prod-backup-db",
                principal,
            });
            assert!(!d.is_allowed(), "{held:?} {d:?}");
        }
        assert!(p.kube_groups(&held, "prod-backup-db").is_empty());
        assert!(
            p.redis_grants(&held, "prod-backup-db", "default")
                .is_empty()
        );
        assert!(
            p.requestable_resources(&[], &held)
                .iter()
                .all(|r| r.name != "prod-backup-db")
        );
    }
    assert!(p.who_can("prod-backup-db").is_empty());
}

#[test]
fn a_decoy_is_denied_like_an_unknown_resource() {
    let p = with_decoy();
    let ask = |resource: &str| {
        p.evaluate(&AccessRequest {
            roles: &roles(&["everything"]),
            resource,
            principal: Principal::SshLogin("root".into()),
        })
    };
    assert_eq!(ask("prod-backup-db"), ask("no-such-resource"));
}

#[test]
fn no_worker_may_serve_a_decoy() {
    let p = with_decoy();
    assert!(!p.worker_may_serve("prod-backup-db", &BTreeMap::new()));
}

#[test]
fn a_decoy_is_exposed_only_to_the_roles_it_names_and_looks_like_a_resource() {
    let p = with_decoy();
    assert!(p.exposed_honeytokens(&roles(&["everything"])).is_empty());
    assert!(p.exposed_honeytokens(&[]).is_empty());
    let shown = p.exposed_honeytokens(&roles(&["everything", "bait"]));
    assert_eq!(
        shown,
        vec![AccessibleResource {
            name: "prod-backup-db".into(),
            kind: ResourceKind::Postgres,
            labels: BTreeMap::from([("env".into(), "prod".into())]),
            principals: vec!["backup_admin".into(), "readonly".into()],
        }]
    );
}

#[test]
fn a_decoy_survives_a_round_trip_through_documents_and_changes_the_digest() {
    let with = with_decoy();
    let without = policy(&[ROLES, REAL]).expect("valid");
    assert_ne!(with.digest(), without.digest());
    let again = Policy::from_documents(with.documents()).expect("valid");
    assert_eq!(again, with);
    assert!(
        with.diff(&without)
            .removed
            .iter()
            .any(|r| r.contains("prod-backup-db"))
    );
}

#[test]
fn a_decoy_with_an_address_or_worker_is_refused() {
    let with_section = DECOY.replace("spec:\n", "spec:\n  postgres: { endpoint: 'db:5432' }\n");
    assert!(invalid_text(&[ROLES, &with_section]).contains("no protocol section"));
    let with_selector = DECOY.replace("spec:\n", "spec:\n  worker_selector: { pool: dev }\n");
    assert!(invalid_text(&[ROLES, &with_selector]).contains("worker_selector"));
}

#[test]
fn a_decoy_must_be_visible_to_someone_and_plausible() {
    let web = DECOY.replace("kind: postgres", "kind: web");
    assert!(invalid_text(&[ROLES, &web]).contains("kind web"));
    let nobody = DECOY.replace("exposed_to: [bait]", "exposed_to: []");
    assert!(invalid_text(&[ROLES, &nobody]).contains("exposed_to"));
    // A role that doesn't exist is no error and no warning: either would
    // tell whoever deletes a role which decoys it was exposed to.
    let unknown_role = DECOY.replace("exposed_to: [bait]", "exposed_to: [ghost]");
    let p = policy(&[ROLES, &unknown_role]).expect("valid");
    assert_eq!(p.honeytoken_missing_roles("prod-backup-db"), ["ghost"]);
    assert!(
        with_decoy()
            .honeytoken_missing_roles("prod-backup-db")
            .is_empty()
    );
    // Not a policy warning: those reach every writer's write results.
    assert!(p.warnings().iter().all(|w| !w.contains("prod-backup-db")));
    let db_name = DECOY.replace("principals:", "default_database: orders\n    principals:");
    assert!(policy(&[ROLES, &db_name]).is_ok());
    let ssh_db = db_name.replace("kind: postgres", "kind: ssh");
    assert!(invalid_text(&[ROLES, &ssh_db]).contains("default_database"));
    let none = DECOY.replace("principals: [backup_admin, readonly]", "principals: []");
    assert!(invalid_text(&[ROLES, &none]).contains("principals"));
    let spaced = DECOY.replace("backup_admin", "'back up'");
    assert!(invalid_text(&[ROLES, &spaced]).contains("principal"));
    let many = DECOY.replace("[backup_admin, readonly]", "[a, b, c, d, e, f, g, h, i]");
    assert!(invalid_text(&[ROLES, &many]).contains("principals"));
}

#[test]
fn a_decoys_principals_are_listed_as_a_real_resource_lists_them() {
    let messy = DECOY.replace(
        "[backup_admin, readonly]",
        "[readonly, backup_admin, readonly]",
    );
    let p = policy(&[ROLES, &messy]).expect("valid");
    let shown = p.exposed_honeytokens(&roles(&["bait"]));
    assert_eq!(shown[0].principals, ["backup_admin", "readonly"]);
    let tcp = DECOY.replace("kind: postgres", "kind: tcp");
    let p = policy(&[ROLES, &tcp]).expect("valid");
    assert_eq!(
        p.exposed_honeytokens(&roles(&["bait"]))[0].principals,
        ["access"]
    );
}

#[test]
fn a_decoy_can_be_exposed_to_a_builtin_role_and_unknown_fields_are_errors() {
    let builtin = DECOY.replace("exposed_to: [bait]", "exposed_to: [limen:admin]");
    assert!(policy(&[ROLES, &builtin]).is_ok());
    let typo = DECOY.replace("principals:", "principles:");
    assert!(policy(&[ROLES, &typo]).is_err());
}

#[test]
fn a_decoy_can_not_share_a_name_with_a_resource_or_another_decoy() {
    let same = REAL.replace("web-1", "prod-backup-db");
    assert!(invalid_text(&[ROLES, &same, DECOY]).contains("duplicate resource"));
    assert!(invalid_text(&[ROLES, DECOY, &same]).contains("duplicate resource"));
    assert!(invalid_text(&[ROLES, DECOY, DECOY]).contains("duplicate resource"));
}

#[test]
fn a_discovered_resource_can_not_take_a_decoys_name() {
    let p = with_decoy();
    let other = policy(&[&REAL.replace("web-1", "prod-backup-db")]).expect("valid");
    let doc = other.resource("prod-backup-db").expect("resource").clone();
    let (out, skipped) = p.with_discovered([doc]);
    assert_eq!(skipped.len(), 1, "{skipped:?}");
    assert!(out.resource("prod-backup-db").is_none());
}
