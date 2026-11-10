//! Policy suggest (ADR-0050): removals only, from real use.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use crate::suggest::{
    Action, KEEP_LABEL, KEEP_VALUE, SuggestError, SuggestInput, Suggestions, UsageRow, suggest,
};
use crate::{Document, Policy};

const NOW: i64 = 1_800_000_000;
const DAY: i64 = 86_400;

const RESOURCES: &str = r"
kind: resource
version: v1
metadata: { name: web-prod, labels: { env: prod } }
spec: { ssh: { address: 'h:22' } }
---
kind: resource
version: v1
metadata: { name: web-staging, labels: { env: staging } }
spec: { ssh: { address: 'h:22' } }
---
kind: resource
version: v1
metadata: { name: orders, labels: { env: prod } }
spec: { postgres: { endpoint: 'db.internal:5432' } }
---
kind: resource
version: v1
metadata: { name: cache, labels: { env: prod } }
spec: { redis: { endpoint: 'h:6379' } }
---
kind: resource
version: v1
metadata: { name: tunnel, labels: { env: prod } }
spec: { tcp: { address: 't:1' } }
---
kind: resource
version: v1
metadata: { name: wiki, labels: { env: prod } }
spec: { web: { address: 'h:80', host: 'wiki.example.com', insecure_dev: true } }
";

const ROLES: &str = r"
kind: role
version: v1
metadata: { name: dev }
spec:
  allow:
    - resources: { kind: [ssh], labels: { env: [prod, staging] } }
      ssh: { logins: [ubuntu, root] }
    - resources: { kind: [postgres], labels: { env: [prod] } }
      db: { roles: [limen_read, limen_write], databases: ['*'] }
  deny:
    - resources: { kind: [ssh], labels: { env: [prod] } }
      ssh: { logins: [admin] }
---
kind: role
version: v1
metadata: { name: cachers }
spec:
  allow:
    - resources: { kind: [redis], labels: { env: [prod] } }
      redis: { users: [reader, writer], keys: ['s:*'] }
    - resources: { kind: [tcp], labels: { env: [prod] } }
      tcp: {}
---
kind: role
version: v1
metadata: { name: ghost }
spec:
  allow:
    - resources: { kind: [ssh], labels: { env: [staging] } }
      ssh: { logins: [legacy] }
---
kind: role
version: v1
metadata: { name: emergency }
spec:
  break_glass: true
  allow:
    - resources: { kind: [ssh], labels: { env: [prod] } }
      ssh: { logins: [ubuntu] }
  request: { who: [dev] }
---
kind: role
version: v1
metadata: { name: asker }
spec:
  allow:
    - resources: { kind: [postgres], labels: { env: [prod] } }
      db: { roles: [limen_read], databases: ['*'] }
  request: { who: [dev], approvers: [sre] }
---
kind: role
version: v1
metadata: { name: quarterly, labels: { suggest: keep } }
spec:
  allow:
    - resources: { kind: [ssh], labels: { env: [prod] } }
      ssh: { logins: [batch] }
---
kind: role
version: v1
metadata: { name: webby }
spec:
  allow:
    - resources: { kind: [web], labels: { env: [prod] } }
      web: { methods: [GET] }
    - resources: { kind: [ssh], labels: { env: [prod] } }
      ssh: { logins: [wiki] }
";

fn policy() -> Policy {
    Policy::parse_yaml([("r.yaml", RESOURCES), ("roles.yaml", ROLES)]).expect("fixture")
}

fn row(user: &str, resource: &str, principal: &str, days_ago: i64) -> UsageRow {
    UsageRow {
        user: user.into(),
        resource: resource.into(),
        principal: principal.into(),
        sessions: 1,
        last_used_unix: NOW - days_ago * DAY,
    }
}

struct World {
    usage: Vec<UsageRow>,
    people: BTreeMap<String, Vec<String>>,
    role_changed: BTreeMap<String, i64>,
    resource_created: BTreeMap<String, i64>,
    watching: Option<i64>,
    window: u32,
}

impl World {
    fn new(usage: Vec<UsageRow>) -> Self {
        World {
            usage,
            people: BTreeMap::new(),
            role_changed: BTreeMap::new(),
            resource_created: BTreeMap::new(),
            watching: Some(NOW - 400 * DAY),
            window: 90,
        }
    }

    fn run(&self, policy: &Policy) -> Result<Suggestions, SuggestError> {
        suggest(
            policy,
            &SuggestInput {
                usage: &self.usage,
                people: &self.people,
                role_changed_unix: &self.role_changed,
                resource_created_unix: &self.resource_created,
                watching_since_unix: self.watching,
                now_unix: NOW,
                window_days: self.window,
            },
        )
    }
}

fn role<'a>(s: &'a Suggestions, name: &str) -> Option<&'a crate::suggest::RoleSuggestion> {
    s.roles.iter().find(|r| r.role == name)
}

#[test]
fn an_unused_login_is_dropped_and_the_rest_stays() {
    let w = World::new(vec![
        row("ana", "web-prod", "ubuntu", 3),
        row("ana", "orders", "limen_read", 3),
        row("ana", "orders", "limen_write", 3),
    ]);
    let s = w.run(&policy()).expect("suggest");
    let dev = role(&s, "dev").expect("dev is tightened");
    assert_eq!(dev.changes.len(), 1, "{:?}", dev.changes);
    assert_eq!(dev.changes[0].action, Action::RemovePrincipals);
    assert_eq!(dev.changes[0].principals, vec!["root".to_owned()]);
    let ssh = dev.document.spec.allow[0].ssh.as_ref().expect("ssh");
    assert_eq!(ssh.logins, vec!["ubuntu".to_owned()]);
    // The database rule and the deny rule are untouched.
    assert_eq!(dev.document.spec.allow.len(), 2);
    assert_eq!(
        dev.document.spec.deny,
        policy().role("dev").unwrap().spec.deny
    );
}

#[test]
fn an_unused_rule_goes_and_a_role_with_nothing_left_is_reported_not_written() {
    let w = World::new(vec![row("ana", "web-prod", "ubuntu", 3)]);
    let s = w.run(&policy()).expect("suggest");
    // `dev` keeps its ssh rule and loses the database rule, which nobody used.
    let dev = role(&s, "dev").expect("dev");
    assert!(
        dev.changes
            .iter()
            .any(|c| c.action == Action::RemoveGrant && c.grant == "db")
    );
    assert_eq!(dev.document.spec.allow.len(), 1);
    // `ghost` has only one unused rule: it cannot be written back empty.
    assert!(role(&s, "ghost").is_none());
    assert!(
        s.unused_roles.contains(&"ghost".to_owned()),
        "{:?}",
        s.unused_roles
    );
}

#[test]
fn use_by_anyone_counts_and_other_resources_do_not() {
    // Someone else used `root` on staging: it is use of the ssh rule that reaches staging.
    let w = World::new(vec![row("bo", "web-staging", "root", 10)]);
    let s = w.run(&policy()).expect("suggest");
    let dev = role(&s, "dev").expect("dev");
    let c = &dev.changes[0];
    assert_eq!(c.principals, vec!["ubuntu".to_owned()], "{c:?}");
    // A login on a resource the rule does not reach counts for nothing.
    let w = World::new(vec![row("bo", "orders", "root", 10)]);
    let s = w.run(&policy()).expect("suggest");
    assert!(
        role(&s, "dev")
            .expect("dev")
            .changes
            .iter()
            .any(|c| c.grant == "ssh" && c.action == Action::RemoveGrant)
    );
}

#[test]
fn overlapping_roles_both_count_the_same_session() {
    // `dev` and `webby` both allow ssh to web-prod, `wiki` only through webby.
    // A session as `wiki` is use of webby's rule, and it must not hide dev's `ubuntu`.
    let w = World::new(vec![row("ana", "web-prod", "wiki", 1)]);
    let s = w.run(&policy()).expect("suggest");
    assert!(role(&s, "webby").is_none_or(|r| r.changes.iter().all(|c| c.grant != "ssh")));
    let dev = role(&s, "dev").expect("dev");
    assert!(
        dev.changes
            .iter()
            .any(|c| c.grant == "ssh" && c.action == Action::RemoveGrant)
    );
}

#[test]
fn rules_whose_use_is_not_recorded_are_left_alone() {
    let w = World::new(vec![]);
    let s = w.run(&policy()).expect("suggest");
    assert!(
        s.not_assessed
            .iter()
            .any(|n| n.role == "webby" && n.rule == Some(1)),
        "{:?}",
        s.not_assessed
    );
    let webby = role(&s, "webby").expect("its ssh rule is judged");
    assert_eq!(webby.document.spec.allow.len(), 1);
    assert!(webby.document.spec.allow[0].web.is_some());
}

#[test]
fn some_roles_are_never_judged() {
    let w = World::new(vec![]);
    let s = w.run(&policy()).expect("suggest");
    for name in ["emergency", "asker", "quarterly"] {
        assert!(role(&s, name).is_none(), "{name}");
        assert!(
            s.kept.iter().any(|k| k.role == name),
            "{name}: {:?}",
            s.kept
        );
        assert!(!s.unused_roles.contains(&name.to_owned()));
    }
    assert_eq!(
        policy()
            .role("quarterly")
            .unwrap()
            .metadata
            .labels
            .get(KEEP_LABEL),
        Some(KEEP_VALUE)
    );
}

#[test]
fn a_role_changed_inside_the_window_is_left_alone() {
    let mut w = World::new(vec![]);
    w.role_changed.insert("dev".into(), NOW - 10 * DAY);
    let s = w.run(&policy()).expect("suggest");
    assert!(role(&s, "dev").is_none());
    assert!(s.kept.iter().any(|k| k.role == "dev"));
    // Changed before the window, it is judged.
    w.role_changed.insert("dev".into(), NOW - 200 * DAY);
    assert!(role(&w.run(&policy()).unwrap(), "dev").is_some());
}

#[test]
fn a_resource_created_inside_the_window_blocks_its_rule() {
    let mut w = World::new(vec![row("ana", "web-prod", "ubuntu", 3)]);
    w.resource_created
        .insert("web-staging".into(), NOW - 5 * DAY);
    let s = w.run(&policy()).expect("suggest");
    assert!(
        role(&s, "dev").is_none_or(|r| r.changes.iter().all(|c| c.grant != "ssh")),
        "the ssh rule reaches a resource that is five days old"
    );
    assert!(
        s.not_assessed
            .iter()
            .any(|n| n.role == "dev" && n.rule == Some(1))
    );
}

#[test]
fn use_outside_the_window_does_not_count() {
    let w = World::new(vec![row("ana", "web-prod", "root", 120)]);
    let s = w.run(&policy()).expect("suggest");
    let dev = role(&s, "dev").expect("dev");
    assert!(
        dev.changes
            .iter()
            .any(|c| c.grant == "ssh" && c.action == Action::RemoveGrant)
    );
    // A longer window sees it.
    let mut w = World::new(vec![row("ana", "web-prod", "root", 120)]);
    w.window = 180;
    let s = w.run(&policy()).expect("suggest");
    let dev = role(&s, "dev").expect("dev");
    assert!(
        dev.changes
            .iter()
            .any(|c| c.principals == ["ubuntu".to_owned()])
    );
}

#[test]
fn short_history_is_refused() {
    let mut w = World::new(vec![]);
    w.watching = Some(NOW - 30 * DAY);
    match w.run(&policy()) {
        Err(SuggestError::ShortHistory {
            window_days: 90,
            available_days: 30,
        }) => {}
        other => panic!("{other:?}"),
    }
    w.window = 30;
    w.run(&policy()).expect("a window it can honour");
    w.watching = None;
    assert_eq!(w.run(&policy()), Err(SuggestError::NoHistory));
    for bad in [0, 6, 366, 10_000] {
        let mut w = World::new(vec![]);
        w.window = bad;
        assert_eq!(w.run(&policy()), Err(SuggestError::Window(bad)));
    }
}

#[test]
fn tcp_counts_as_used_by_any_session_on_it() {
    let w = World::new(vec![row("ana", "tunnel", "10.0.0.1:5432", 2)]);
    let s = w.run(&policy()).expect("suggest");
    let cachers = role(&s, "cachers").expect("cachers");
    assert!(
        cachers.changes.iter().all(|c| c.grant != "tcp"),
        "{:?}",
        cachers.changes
    );
}

#[test]
fn people_who_did_not_use_a_role_are_listed() {
    let mut w = World::new(vec![
        row("ana", "web-prod", "ubuntu", 3),
        row("bo", "orders", "limen_read", 3),
    ]);
    w.people
        .insert("ana".into(), vec!["dev".into(), "cachers".into()]);
    w.people.insert("bo".into(), vec!["dev".into()]);
    w.people.insert("cy".into(), vec!["emergency".into()]);
    let s = w.run(&policy()).expect("suggest");
    let ana = s.people.iter().find(|p| p.user == "ana").expect("ana");
    assert_eq!(ana.roles, vec!["cachers".to_owned()]);
    // Both of bo's sessions are on `dev`'s rules.
    assert!(s.people.iter().all(|p| p.user != "bo"));
    // An exempt role is never called unused.
    assert!(s.people.iter().all(|p| p.user != "cy"));
}

#[test]
fn the_yaml_is_the_changed_roles_and_loads_back() {
    let w = World::new(vec![row("ana", "web-prod", "ubuntu", 3)]);
    let p = policy();
    let s = w.run(&p).expect("suggest");
    let yaml = s.to_yaml(7).expect("yaml");
    assert!(yaml.contains("version 7"), "{yaml}");
    let docs = Policy::parse_yaml_documents([("s.yaml", yaml.as_str())]).expect("parses");
    assert_eq!(docs.len(), s.roles.len());
    assert!(docs.iter().all(|d| matches!(d, Document::Role(_))));
    let applied = s.apply_to(&p).expect("applies");
    assert!(!p.access_diff(&applied).widens());
    assert!(
        !p.access_diff(&applied).changes.is_empty(),
        "something was lost"
    );
}

#[test]
fn nothing_to_suggest_is_an_empty_result() {
    let w = World::new(vec![
        row("a", "web-prod", "ubuntu", 1),
        row("a", "web-prod", "root", 1),
        row("a", "web-prod", "wiki", 1),
        row("a", "web-staging", "legacy", 1),
        row("a", "orders", "limen_read", 1),
        row("a", "orders", "limen_write", 1),
        row("a", "cache", "reader", 1),
        row("a", "cache", "writer", 1),
        row("a", "tunnel", "", 1),
    ]);
    let s = w.run(&policy()).expect("suggest");
    assert!(s.roles.is_empty() && s.unused_roles.is_empty(), "{s:?}");
}

struct Lcg(u64);
impl Lcg {
    fn next(&mut self, n: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        usize::try_from(self.0 >> 33).expect("fits") % n
    }
}

/// The fixture with the lists in `dev` and `cachers` drawn at random.
fn random_policy(rng: &mut Lcg) -> Policy {
    let pick = |rng: &mut Lcg, from: &[&str]| -> String {
        let mut chosen: Vec<&str> = from.iter().copied().filter(|_| rng.next(2) == 0).collect();
        if chosen.is_empty() {
            chosen.push(from[rng.next(from.len())]);
        }
        chosen.join(", ")
    };
    let logins = pick(rng, &["ubuntu", "root", "batch", "wiki"]);
    let db_roles = pick(rng, &["limen_read", "limen_write", "limen_admin"]);
    let users = pick(rng, &["reader", "writer"]);
    let roles = ROLES
        .replace(
            "logins: [ubuntu, root] }",
            &format!("logins: [{logins}] }}"),
        )
        .replace(
            "roles: [limen_read, limen_write], databases: ['*'] }",
            &format!("roles: [{db_roles}], databases: ['*'] }}"),
        )
        .replace("users: [reader, writer]", &format!("users: [{users}]"));
    Policy::parse_yaml([("r.yaml", RESOURCES), ("roles.yaml", roles.as_str())])
        .expect("random policy")
}

#[test]
fn suggestions_only_ever_lose_access_and_settle() {
    let resources = [
        "web-prod",
        "web-staging",
        "orders",
        "cache",
        "tunnel",
        "wiki",
        "nope",
    ];
    let principals = [
        "ubuntu",
        "root",
        "batch",
        "wiki",
        "legacy",
        "limen_read",
        "limen_write",
        "reader",
        "writer",
        "",
        "admin",
    ];
    let mut rng = Lcg(0xfeed);
    let mut with_changes = 0;
    for round in 0..1_500 {
        let p = random_policy(&mut rng);
        let mut usage = Vec::new();
        for _ in 0..rng.next(14) {
            usage.push(row(
                "u",
                resources[rng.next(resources.len())],
                principals[rng.next(principals.len())],
                i64::try_from(rng.next(200)).unwrap(),
            ));
        }
        let mut w = World::new(usage);
        w.window = [7, 30, 90, 180, 365][rng.next(5)];
        if rng.next(4) == 0 {
            w.role_changed.insert(
                "dev".into(),
                NOW - i64::try_from(rng.next(300)).unwrap() * DAY,
            );
        }
        if rng.next(4) == 0 {
            w.resource_created.insert(
                "web-staging".into(),
                NOW - i64::try_from(rng.next(300)).unwrap() * DAY,
            );
        }
        let s = w.run(&p).unwrap_or_else(|e| panic!("round {round}: {e}"));
        let next = s
            .apply_to(&p)
            .unwrap_or_else(|e| panic!("round {round}: {e}"));
        let diff = p.access_diff(&next);
        assert!(!diff.widens(), "round {round}: {}", diff.render_text());
        if !s.roles.is_empty() {
            with_changes += 1;
            assert!(
                !diff.changes.is_empty(),
                "round {round}: a suggestion that changes nothing"
            );
        }
        // Settled: with the same use, the result suggests nothing more.
        let again = w.run(&next).unwrap();
        assert!(again.roles.is_empty(), "round {round}: {:?}", again.roles);
    }
    // The property is not vacuous.
    assert!(
        with_changes > 500,
        "only {with_changes} of 1500 rounds suggested anything"
    );
}
