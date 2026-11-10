//! Replay of recorded sessions (ADR-0049).

use std::collections::BTreeSet;

use super::*;
use crate::replay::{
    Holder, Outcome, ReplayRecord, ReplayReport, Unreplayable, principal_from_session,
};

const ACTIVE: &str = r"
kind: resource
version: v1
metadata: { name: web-prod, labels: { env: prod } }
spec: { ssh: { address: '10.0.0.2:22' } }
---
kind: resource
version: v1
metadata: { name: web-staging, labels: { env: staging } }
spec: { ssh: { address: '10.0.0.1:22' } }
---
kind: resource
version: v1
metadata: { name: orders-prod, labels: { env: prod } }
spec: { postgres: { endpoint: 'db.internal:5432' } }
---
kind: role
version: v1
metadata: { name: dev }
spec:
  allow:
    - resources: { kind: [ssh], labels: { env: [prod, staging] } }
      ssh: { logins: [ubuntu] }
    - resources: { kind: [postgres], labels: { env: [prod] } }
      db: { roles: [limen_read], databases: [orders] }
---
kind: role
version: v1
metadata: { name: sre }
spec:
  allow:
    - resources: { kind: [ssh], labels: { env: [prod, staging] } }
      ssh: { logins: [ubuntu, root] }
---
kind: role
version: v1
metadata: { name: prod-ssh-emergency }
spec:
  allow:
    - resources: { kind: [ssh], labels: { env: [prod] } }
      ssh: { logins: [ubuntu] }
  request:
    who: [developers]
    approvers: [sre-team]
---
kind: role_mapping
version: v1
metadata: { name: m }
spec:
  - { idp_group: developers, roles: [dev] }
  - { idp_group: sre-team, roles: [sre] }
---
kind: bot
version: v1
metadata: { name: nightly }
spec:
  roles: [dev]
  join:
    method: github_actions
    match: { repository: acme/infra, ref: refs/heads/main }
";

/// Developers lose production SSH, but may ask for it.
fn tightened() -> String {
    ACTIVE.replace(
        "    - resources: { kind: [ssh], labels: { env: [prod, staging] } }\n      ssh: { logins: [ubuntu] }\n    - resources: { kind: [postgres]",
        "    - resources: { kind: [ssh], labels: { env: [staging] } }\n      ssh: { logins: [ubuntu] }\n    - resources: { kind: [postgres]",
    )
}

fn parse(yaml: &str) -> Policy {
    Policy::parse_yaml([("p.yaml", yaml)]).expect("valid policy")
}

fn person(user: &str, groups: &[&str], resource: &str, login: &str, n: u64) -> ReplayRecord {
    ReplayRecord {
        user: user.into(),
        holder: Holder::Person {
            groups: groups.iter().map(|g| (*g).into()).collect(),
        },
        resource: resource.into(),
        principal: Principal::SshLogin(login.into()),
        granted_roles: Vec::new(),
        sessions: n,
        first_unix: 1_000,
        last_unix: 2_000,
    }
}

fn bot(name: &str, resource: &str, login: &str, n: u64) -> ReplayRecord {
    ReplayRecord {
        user: format!("bot:{name}"),
        holder: Holder::Bot { name: name.into() },
        ..person("x", &[], resource, login, n)
    }
}

fn run(old: &Policy, new: &Policy, records: &[ReplayRecord]) -> ReplayReport {
    old.replay(new, records, &[], &BTreeSet::new())
}

#[test]
fn replaying_the_active_policy_against_itself_changes_nothing() {
    let p = parse(ACTIVE);
    let records = [
        person("alice", &["developers"], "web-prod", "ubuntu", 10),
        person("bob", &["sre-team"], "web-prod", "root", 3),
        bot("nightly", "web-prod", "ubuntu", 30),
    ];
    let report = run(&p, &p, &records);
    assert_eq!(report.affected_sessions, 0);
    assert_eq!(report.affected.len(), 0);
    assert_eq!(report.unchanged, 43);
    assert_eq!(report.examined, 43);
    assert!(report.headline().starts_with("No replayed session"));
}

#[test]
fn a_tightening_names_the_people_and_the_bot_it_would_have_refused() {
    let old = parse(ACTIVE);
    let new = parse(&tightened());
    let records = [
        person("alice", &["developers"], "web-prod", "ubuntu", 10),
        person("alice", &["developers"], "web-staging", "ubuntu", 5),
        person("carol", &["developers"], "web-prod", "ubuntu", 4),
        person("bob", &["sre-team"], "web-prod", "root", 3),
        bot("nightly", "web-prod", "ubuntu", 30),
    ];
    let report = run(&old, &new, &records);
    // Developers (and the bot, which holds `dev`) lose prod; sre and staging stay.
    assert_eq!(report.affected_sessions, 44);
    assert_eq!(report.unchanged, 8);
    assert_eq!(report.affected_users(), (2, 1));
    // Largest first.
    assert_eq!(report.affected[0].user, "bot:nightly");
    // The bot cannot ask for anything; people in `developers` can.
    assert_eq!(report.affected[0].now, Outcome::Deny);
    let alice = report
        .affected
        .iter()
        .find(|a| a.user == "alice")
        .expect("alice");
    assert_eq!(alice.now, Outcome::NeedsRequest);
    assert_eq!(alice.principal, "login ubuntu");
    assert_eq!(alice.sessions, 10);
    assert_eq!(
        report.headline(),
        "Would have refused 44 sessions by 2 people and 1 bot (52 sessions replayed over 0 days, 0 not replayable)."
    );
}

#[test]
fn what_the_active_policy_already_refuses_is_not_blamed_on_the_change() {
    let old = parse(ACTIVE);
    let new = parse(&tightened());
    // Left every group since: the reconstruction cannot allow it today.
    let records = [person("dave", &[], "web-prod", "ubuntu", 7)];
    let report = run(&old, &new, &records);
    assert_eq!(report.already_refused, 7);
    assert_eq!(report.affected_sessions, 0);
    assert_eq!(report.unchanged, 0);
    assert_eq!(report.examined, 7);
}

#[test]
fn a_bot_missing_from_the_proposed_policy_holds_nothing() {
    let old = parse(ACTIVE);
    let new = parse(&ACTIVE.replace("kind: bot", "kind: bot_removed").replace(
        "---\nkind: bot_removed\nversion: v1\nmetadata: { name: nightly }\nspec:\n  roles: [dev]\n  join:\n    method: github_actions\n    match: { repository: acme/infra, ref: refs/heads/main }\n",
        "",
    ));
    let report = run(&old, &new, &[bot("nightly", "web-staging", "ubuntu", 2)]);
    assert_eq!(report.affected_sessions, 2);
    assert!(report.affected[0].bot);
}

#[test]
fn a_removed_resource_and_a_relabel_are_reported() {
    let old = parse(ACTIVE);
    let without = ACTIVE.replace(
        "kind: resource\nversion: v1\nmetadata: { name: web-staging, labels: { env: staging } }\nspec: { ssh: { address: '10.0.0.1:22' } }\n---\n",
        "",
    );
    let new = parse(&without);
    let relabeled: BTreeSet<String> = ["web-staging".to_owned()].into();
    let report = old.replay(
        &new,
        &[person("alice", &["developers"], "web-staging", "ubuntu", 1)],
        &[],
        &relabeled,
    );
    assert_eq!(report.affected_sessions, 1);
    assert!(report.affected[0].labels_changed);
    assert!(
        report
            .render_text()
            .contains("labels changed in the window")
    );
}

#[test]
fn granted_roles_count_for_the_resource_they_were_granted_on() {
    let old = parse(ACTIVE);
    let new = parse(&tightened());
    // Someone outside `developers` got `prod-ssh-emergency` on web-prod.
    let mut record = person("erin", &["interns"], "web-prod", "ubuntu", 2);
    record.granted_roles = vec!["prod-ssh-emergency".into()];
    let report = run(&old, &new, &[record]);
    // The grant is unaffected by the dev change: allowed before and after.
    assert_eq!(report.unchanged, 2);
    assert_eq!(report.affected_sessions, 0);
}

#[test]
fn shadow_rules_that_would_have_fired_are_counted_without_changing_the_outcome() {
    let old = parse(ACTIVE);
    let with_shadow = ACTIVE.replace(
        "    - resources: { kind: [postgres], labels: { env: [prod] } }\n      db: { roles: [limen_read], databases: [orders] }\n",
        "    - resources: { kind: [postgres], labels: { env: [prod] } }\n      db: { roles: [limen_read], databases: [orders] }\n  deny:\n    - name: no-ubuntu-in-prod\n      mode: shadow\n      shadow_until: 2027-01-31\n      resources: { kind: [ssh], labels: { env: [prod] } }\n      ssh: { logins: [ubuntu] }\n",
    );
    let new = parse(&with_shadow);
    let report = run(
        &old,
        &new,
        &[person("alice", &["developers"], "web-prod", "ubuntu", 6)],
    );
    assert_eq!(report.affected_sessions, 0);
    assert_eq!(report.unchanged, 6);
    assert_eq!(report.shadow.len(), 1);
    assert_eq!(report.shadow[0].rule, "dev/no-ubuntu-in-prod");
    assert_eq!(report.shadow[0].sessions, 6);
}

#[test]
fn recorded_sessions_become_the_principal_the_proxy_asked_for() {
    let ok = |kind, up, db| principal_from_session(kind, up, db);
    assert_eq!(
        ok("ssh", Some("ubuntu"), None),
        Ok(Principal::SshLogin("ubuntu".into()))
    );
    assert_eq!(
        ok("postgres", Some("limen_read"), Some("orders")),
        Ok(Principal::DbRole {
            role: "limen_read".into(),
            database: "orders".into()
        })
    );
    assert_eq!(
        ok("mongodb", Some("reader"), Some("app")),
        Ok(Principal::MongoRole {
            role: "reader".into(),
            database: "app".into()
        })
    );
    assert_eq!(
        ok("postgres", Some("limen_read"), None),
        Err(Unreplayable::NoDatabase)
    );
    assert_eq!(
        ok("postgres", Some("limen_read"), Some("")),
        Err(Unreplayable::NoDatabase)
    );
    assert_eq!(ok("ssh", None, None), Err(Unreplayable::NoPrincipal));
    assert_eq!(ok("ssh", Some(""), None), Err(Unreplayable::NoPrincipal));
    assert_eq!(ok("web", None, None), Ok(Principal::WebAccess));
    assert_eq!(ok("tcp", None, None), Ok(Principal::TcpAccess));
    assert_eq!(
        ok("kubernetes", Some("x"), None),
        Err(Unreplayable::Kubernetes)
    );
    assert_eq!(
        ok("gopher", Some("x"), None),
        Err(Unreplayable::UnknownKind)
    );
    assert_eq!(
        ok("opensearch", Some("ro"), None),
        Ok(Principal::SearchRole("ro".into()))
    );
}

#[test]
fn markdown_escapes_names_that_come_from_recorded_sessions() {
    let old = parse(ACTIVE);
    let new = parse(&tightened());
    let report = run(
        &old,
        &new,
        &[person(
            "evil|<img src=x>`",
            &["developers"],
            "web-prod",
            "ubuntu",
            1,
        )],
    );
    let md = report.render_markdown();
    assert_eq!(md.matches('<').count(), md.matches("\\<").count(), "{md}");
    assert!(md.contains("evil\\|\\<img"), "{md}");
    assert!(md.contains("Approximate"));
}

#[test]
fn skips_and_truncation_are_always_reported() {
    let mut report = ReplayReport {
        window_days: 30,
        truncated: true,
        ..ReplayReport::default()
    };
    report.skip(Unreplayable::Kubernetes.reason(), 4);
    report.skip("nothing", 0);
    assert_eq!(report.skipped_total(), 4);
    let text = report.render_text();
    assert!(text.contains("partial"), "{text}");
    assert!(text.contains("Kubernetes"), "{text}");
    assert!(text.contains("4 not replayable"), "{text}");
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

/// The replay must give the answer enforcement gives (ADR-0028's rule): the
/// outcome of a record is `evaluate_eligible` on the roles its holder has.
#[test]
fn replay_agrees_with_enforcement_on_random_records() {
    let old = parse(ACTIVE);
    let new = parse(&tightened());
    let groups = ["developers", "sre-team", "interns"];
    let resources = ["web-prod", "web-staging", "orders-prod", "nope"];
    let principals = [
        Principal::SshLogin("ubuntu".into()),
        Principal::SshLogin("root".into()),
        Principal::DbRole {
            role: "limen_read".into(),
            database: "orders".into(),
        },
        Principal::WebAccess,
    ];
    let grants = [vec![], vec!["prod-ssh-emergency".to_owned()]];
    let mut rng = Lcg(0x5eed);
    for _ in 0..5_000 {
        let holder = if rng.next(4) == 0 {
            Holder::Bot {
                name: "nightly".into(),
            }
        } else {
            Holder::Person {
                groups: groups
                    .iter()
                    .filter(|_| rng.next(2) == 0)
                    .map(|g| (*g).to_owned())
                    .collect(),
            }
        };
        let record = ReplayRecord {
            user: "u".into(),
            holder: holder.clone(),
            resource: resources[rng.next(resources.len())].into(),
            principal: principals[rng.next(principals.len())].clone(),
            granted_roles: grants[rng.next(2)].clone(),
            sessions: 1,
            first_unix: 0,
            last_unix: 0,
        };
        for policy in [&old, &new] {
            let (roles, eligible): (BTreeSet<String>, BTreeSet<String>) = match &holder {
                Holder::Person { groups } => (
                    policy.roles_for_groups(groups.iter().map(String::as_str), &[]),
                    policy.requestable_roles_for_groups(groups.iter().map(String::as_str)),
                ),
                Holder::Bot { name } => (
                    policy
                        .bot(name)
                        .map(|b| b.spec.roles.iter().cloned().collect())
                        .unwrap_or_default(),
                    BTreeSet::new(),
                ),
            };
            let roles: BTreeSet<String> = roles
                .into_iter()
                .chain(record.granted_roles.iter().cloned())
                .collect();
            let roles: Vec<String> = roles.into_iter().collect();
            let eligible: Vec<String> = eligible.into_iter().collect();
            let expected = policy.evaluate_eligible(
                &AccessRequest {
                    roles: &roles,
                    resource: &record.resource,
                    principal: record.principal.clone(),
                },
                &eligible,
            );
            assert_eq!(policy.replay_decision(&record, &[]), expected, "{record:?}");
        }
        // Self-replay never reports anything.
        let same = old.replay(&old, std::slice::from_ref(&record), &[], &BTreeSet::new());
        assert_eq!(same.affected_sessions, 0, "{record:?}");
        // And an affected record is exactly: allowed before, not after.
        let report = old.replay(&new, std::slice::from_ref(&record), &[], &BTreeSet::new());
        let before = old.replay_decision(&record, &[]).is_allowed();
        let after = new.replay_decision(&record, &[]).is_allowed();
        assert_eq!(
            report.affected_sessions == 1,
            before && !after,
            "{record:?}"
        );
    }
}

#[test]
fn terminal_output_carries_no_control_characters_from_names() {
    let old = parse(ACTIVE);
    let new = parse(&tightened());
    let report = run(
        &old,
        &new,
        &[person(
            "evil\x1b[31m@x",
            &["developers"],
            "web-prod",
            "ubuntu",
            1,
        )],
    );
    let text = report.render_text();
    assert!(!text.contains('\x1b'), "{text:?}");
    assert!(text.contains("evil [31m@x"), "{text:?}");
}

#[test]
fn a_huge_answer_is_cut_to_the_largest_groups_with_the_totals_intact() {
    let old = parse(ACTIVE);
    let new = parse(&tightened());
    let records: Vec<ReplayRecord> = (0..600)
        .map(|i| {
            person(
                &format!("u{i}"),
                &["developers"],
                "web-prod",
                "ubuntu",
                1 + i,
            )
        })
        .collect();
    let report = run(&old, &new, &records);
    assert_eq!(report.affected.len(), crate::replay::MAX_AFFECTED_ROWS);
    assert_eq!(report.affected_omitted, 100);
    assert_eq!(report.affected_sessions, (1..=600).sum::<u64>());
    assert_eq!(report.affected[0].sessions, 600, "largest first");
    assert!(report.render_text().contains("100 more groups"));
}

#[test]
fn a_partial_replay_says_so_in_the_headline() {
    let report = ReplayReport {
        truncated: true,
        ..ReplayReport::default()
    };
    assert!(report.headline().contains("partial"));
}
