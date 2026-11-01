//! Access requests, policy tooling, and discovery documents (ADR-0025,
//! ADR-0027, ADR-0028).

use std::collections::BTreeSet;

use super::*;
use crate::tooling::{ChangeKind, Subject, Via};

const BASE: &str = r"
kind: resource
version: v1
metadata: { name: web-staging, labels: { env: staging } }
spec: { ssh: { address: '10.0.0.1:22' } }
---
kind: resource
version: v1
metadata: { name: web-prod, labels: { env: prod } }
spec: { ssh: { address: '10.0.0.2:22' } }
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
    - resources: { kind: [ssh], labels: { env: [staging] } }
      ssh: { logins: [ubuntu] }
---
kind: role
version: v1
metadata: { name: prod-db-readonly }
spec:
  allow:
    - resources: { kind: [postgres], labels: { env: [prod] } }
      db: { roles: [limen_read], databases: ['*'] }
  request:
    who: [developers]
    approvers: [sre-leads]
    max_duration: 2h
    ticket_pattern: '^(INC|OPS)-[0-9]+$'
---
kind: role
version: v1
metadata: { name: prod-ssh-emergency }
spec:
  break_glass: true
  allow:
    - resources: { kind: [ssh], labels: { env: [prod] } }
      ssh: { logins: [ubuntu] }
  request:
    who: [developers]
---
kind: role
version: v1
metadata: { name: sre }
spec:
  allow:
    - resources: { kind: [ssh, postgres], labels: { env: [prod, staging] } }
      ssh: { logins: [ubuntu, deploy] }
      db: { roles: [limen_read], databases: ['*'] }
  deny:
    - resources: { kind: [ssh], labels: { env: [prod] } }
      ssh: { logins: [root] }
---
kind: role_mapping
version: v1
metadata: { name: m }
spec:
  - { idp_group: developers, roles: [dev] }
  - { idp_group: sre, roles: [sre] }
";

fn base() -> Policy {
    Policy::parse_yaml([("base.yaml", BASE)]).expect("base policy")
}

fn with(extra: &str) -> Policy {
    Policy::parse_yaml([("base.yaml", BASE), ("extra.yaml", extra)]).expect("policy")
}

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_owned()).collect()
}

fn invalid_role(yaml: &str) -> String {
    match Policy::parse_yaml([("r.yaml", yaml)]).expect_err("must be refused") {
        PolicyError::Invalid { message, .. } => message,
        other => panic!("unexpected error {other:?}"),
    }
}

fn role_yaml(spec: &str) -> String {
    format!(
        "kind: role\nversion: v1\nmetadata: {{ name: r }}\nspec:\n  allow:\n    - resources: {{ kind: [ssh], labels: {{ \"*\": [\"*\"] }} }}\n      ssh: {{ logins: [ubuntu] }}\n{spec}"
    )
}

#[test]
fn request_specs_are_validated() {
    for (spec, expect) in [
        ("  request: { who: [] , approvers: [a] }", "request.who"),
        ("  request: { who: [a] }", "needs request.approvers"),
        (
            "  request: { who: [a], approvers: [b], approvals_required: 0 }",
            "1 to 5",
        ),
        (
            "  request: { who: [a], approvers: [b], max_duration: 8d }",
            "at most 7d",
        ),
        (
            "  request: { who: [a], approvers: [b], ticket_pattern: '(' }",
            "not a valid expression",
        ),
        (
            "  request: { who: [a], approvers: [b], require_reason: false, ticket_pattern: 'X' }",
            "needs request.require_reason",
        ),
        ("  break_glass: true", "needs request.who"),
        (
            "  break_glass: true\n  request: { who: [a], approvers: [b] }",
            "remove request.approvers",
        ),
        (
            "  break_glass: true\n  request: { who: [a], max_duration: 2h }",
            "at most 1h",
        ),
        (
            "  break_glass: true\n  request: { who: [a], require_reason: false }",
            "always needs a reason",
        ),
        (
            "  request: { who: [a], approvers: [b], surprise: 1 }",
            "surprise",
        ),
    ] {
        let message = match Policy::parse_yaml([("r.yaml", role_yaml(spec).as_str())]) {
            Err(PolicyError::Invalid { message, .. } | PolicyError::Parse { message, .. }) => {
                message
            }
            other => panic!("{spec}: expected a refusal, got {other:?}"),
        };
        assert!(message.contains(expect), "{spec}: {message}");
    }
    // A well-formed one is accepted, with the defaults filled in.
    let ok = Policy::parse_yaml([(
        "r.yaml",
        role_yaml("  request: { who: [a], approvers: [b] }").as_str(),
    )])
    .expect("valid");
    let request = ok
        .role("r")
        .expect("r")
        .spec
        .request
        .clone()
        .expect("request");
    assert_eq!(request.approvals_required, 1);
    assert!(request.require_reason);
    assert_eq!(
        request.duration_limit(false),
        model::DEFAULT_REQUEST_DURATION
    );
    assert_eq!(
        request.duration_limit(true),
        model::MAX_BREAK_GLASS_DURATION
    );
    assert!(invalid_role(&role_yaml("  break_glass: true")).contains("break_glass"));
}

#[test]
fn ticket_patterns_cannot_make_the_matcher_spin() {
    let re = compile_ticket_pattern("^(a+)+$").expect("compiles");
    let hostile = "a".repeat(50_000) + "!";
    // Linear time: this returns at once instead of backtracking forever.
    assert!(!re.is_match(&hostile));
    assert!(compile_ticket_pattern(&"(".repeat(300)).is_err());
}

#[test]
fn a_requestable_role_yields_requires_approval_and_never_access() {
    let policy = base();
    let held = strings(&["dev"]);
    let eligible = strings(&["prod-db-readonly", "prod-ssh-emergency"]);
    let ask = |resource, principal| AccessRequest {
        roles: &held,
        resource,
        principal,
    };
    let db = Principal::DbRole {
        role: "limen_read".into(),
        database: "orders".into(),
    };
    // Enforcement sees a plain denial.
    let enforced = policy.evaluate(&ask("orders-prod", db.clone()));
    assert!(!enforced.is_allowed());
    // The asking path says what to do.
    match policy.evaluate_eligible(&ask("orders-prod", db), &eligible) {
        Decision::RequiresApproval { roles, .. } => assert_eq!(roles, ["prod-db-readonly"]),
        other => panic!("expected RequiresApproval, got {other:?}"),
    }
    // Nothing requestable reaches a login that no role offers.
    let root = Principal::SshLogin("root".into());
    assert!(matches!(
        policy.evaluate_eligible(&ask("web-prod", root), &eligible),
        Decision::Deny { .. }
    ));
    // What you already hold wins over asking.
    let staging = Principal::SshLogin("ubuntu".into());
    assert!(
        policy
            .evaluate_eligible(&ask("web-staging", staging), &eligible)
            .is_allowed()
    );
    // An unknown role in the eligible list grants nothing.
    assert!(matches!(
        policy.evaluate_eligible(
            &ask(
                "orders-prod",
                Principal::DbRole {
                    role: "limen_read".into(),
                    database: "x".into()
                }
            ),
            &strings(&["no-such-role"])
        ),
        Decision::Deny { .. }
    ));
}

#[test]
fn deny_rules_in_a_requestable_role_stop_it_being_offered() {
    let policy = with(
        r"
kind: role
version: v1
metadata: { name: careful }
spec:
  allow:
    - resources: { kind: [ssh], labels: { env: [prod] } }
      ssh: { logins: [ubuntu] }
  deny:
    - resources: { kind: [ssh], labels: { env: [prod] } }
      ssh: { logins: [ubuntu] }
  request: { who: [developers], approvers: [sre-leads] }
",
    );
    let held = strings(&["dev"]);
    let req = AccessRequest {
        roles: &held,
        resource: "web-prod",
        principal: Principal::SshLogin("ubuntu".into()),
    };
    assert!(matches!(
        policy.evaluate_eligible(&req, &strings(&["careful"])),
        Decision::Deny { .. }
    ));
}

#[test]
fn requestable_roles_follow_groups_and_approvers_are_checked_by_group_or_name() {
    let policy = base();
    let devs: BTreeSet<String> = policy.requestable_roles_for_groups(["developers"]);
    assert_eq!(
        devs.into_iter().collect::<Vec<_>>(),
        ["prod-db-readonly", "prod-ssh-emergency"]
    );
    assert!(policy.requestable_roles_for_groups(["sre"]).is_empty());
    assert!(policy.may_approve("prod-db-readonly", "lead", ["sre-leads"]));
    assert!(!policy.may_approve("prod-db-readonly", "lead", ["developers"]));
    // A break-glass role has no approvers: nobody approves it.
    assert!(!policy.may_approve("prod-ssh-emergency", "lead", ["sre-leads"]));
    assert!(!policy.may_approve("dev", "lead", ["sre-leads"]));
    let named = with(
        r"
kind: role
version: v1
metadata: { name: named }
spec:
  allow:
    - resources: { kind: [ssh], labels: { env: [prod] } }
      ssh: { logins: [ubuntu] }
  request: { who: [developers], approver_users: [alice] }
",
    );
    assert!(named.may_approve("named", "alice", []));
    assert!(!named.may_approve("named", "bob", ["sre-leads"]));
}

#[test]
fn requestable_resources_hint_names_and_kinds_only() {
    let policy = base();
    let held = strings(&["dev"]);
    let eligible = strings(&["prod-db-readonly", "prod-ssh-emergency"]);
    let hints = policy.requestable_resources(&held, &eligible);
    let names: Vec<&str> = hints.iter().map(|h| h.name.as_str()).collect();
    assert_eq!(names, ["orders-prod", "web-prod"]);
    assert_eq!(hints[0].roles, ["prod-db-readonly"]);
    // Resources already reachable are not offered again.
    assert!(!names.contains(&"web-staging"));
}

#[test]
fn warnings_flag_overlap_and_tag_steering() {
    let policy = with(
        r"
kind: role
version: v1
metadata: { name: loose }
spec:
  allow:
    - resources: { kind: [ssh], labels: { team: [payments] } }
      ssh: { logins: [ubuntu] }
  request: { who: [g], approvers: [g] }
---
kind: discovery
version: v1
metadata: { name: aws }
spec:
  provider: aws
  regions: [eu-west-1]
  match:
    - { type: ec2, labels_from_tags: [team] }
",
    );
    let warnings = policy.warnings().join("\n");
    assert!(
        warnings.contains("may both request and approve"),
        "{warnings}"
    );
    assert!(warnings.contains("selects on label \"team\""), "{warnings}");
    assert!(base().warnings().is_empty(), "{:?}", base().warnings());
}

// ---------------------------------------------------------------------------
// The tracing decision and enforcement must agree.

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

#[test]
fn trace_agrees_with_enforcement_on_random_requests() {
    let policy = base();
    let all_roles = [
        "dev",
        "sre",
        "prod-db-readonly",
        "prod-ssh-emergency",
        "ghost",
    ];
    let resources = ["web-staging", "web-prod", "orders-prod", "nope"];
    let principals = [
        Principal::SshLogin("ubuntu".into()),
        Principal::SshLogin("root".into()),
        Principal::SshLogin("deploy".into()),
        Principal::DbRole {
            role: "limen_read".into(),
            database: "orders".into(),
        },
        Principal::DbRole {
            role: "limen_write".into(),
            database: "orders".into(),
        },
        Principal::KubeGroup("x".into()),
        Principal::WebAccess,
    ];
    let mut rng = Lcg(0x5eed);
    for _ in 0..5_000 {
        let held: Vec<String> = all_roles
            .iter()
            .filter(|_| rng.next(2) == 0)
            .map(|r| (*r).to_owned())
            .collect();
        let eligible: Vec<String> = all_roles
            .iter()
            .filter(|_| rng.next(3) == 0)
            .map(|r| (*r).to_owned())
            .collect();
        let req = AccessRequest {
            roles: &held,
            resource: resources[rng.next(resources.len())],
            principal: principals[rng.next(principals.len())].clone(),
        };
        assert_eq!(
            policy.trace(&req, &[]).decision,
            policy.evaluate(&req),
            "held {held:?} {req:?}"
        );
        assert_eq!(
            policy.trace(&req, &eligible).decision,
            policy.evaluate_eligible(&req, &eligible),
            "held {held:?} eligible {eligible:?} {req:?}"
        );
        // The asking path never turns a refusal into access.
        if policy.evaluate_eligible(&req, &eligible).is_allowed() {
            assert!(policy.evaluate(&req).is_allowed());
        }
    }
}

#[test]
fn trace_says_why() {
    let policy = base();
    let held = strings(&["dev"]);
    let trace = policy.trace(
        &AccessRequest {
            roles: &held,
            resource: "web-prod",
            principal: Principal::SshLogin("ubuntu".into()),
        },
        &[],
    );
    let text = trace.render().join("\n");
    assert!(
        text.contains("needs env in [staging], the resource has env=prod"),
        "{text}"
    );
    let trace = policy.trace(
        &AccessRequest {
            roles: &held,
            resource: "web-staging",
            principal: Principal::SshLogin("root".into()),
        },
        &[],
    );
    assert!(
        trace
            .render()
            .join("\n")
            .contains("grants ubuntu, not login root")
    );
    let sre = strings(&["sre"]);
    let denied = policy.trace(
        &AccessRequest {
            roles: &sre,
            resource: "web-prod",
            principal: Principal::SshLogin("root".into()),
        },
        &[],
    );
    assert_eq!(
        denied.decision,
        Decision::Deny {
            reason: DenyReason::ExplicitDeny
        }
    );
    assert!(denied.render().join("\n").contains("deny rule 1"));
}

#[test]
fn explaining_to_a_user_does_not_reveal_hidden_resources() {
    let policy = base();
    let held = strings(&["dev"]);
    let eligible = Vec::new();
    // `web-prod` exists and is hidden from `dev`; `ghost-host` does not exist.
    let hidden = policy.explain_for_user(&held, &eligible, "web-prod", None);
    let missing = policy.explain_for_user(&held, &eligible, "ghost-host", None);
    assert_eq!(
        hidden
            .iter()
            .map(|l| l.replace("web-prod", "X"))
            .collect::<Vec<_>>(),
        missing
            .iter()
            .map(|l| l.replace("ghost-host", "X"))
            .collect::<Vec<_>>(),
        "a hidden resource must read exactly like a missing one"
    );
    let text = hidden.join("\n");
    assert!(text.contains("Your role `dev` allows"));
    assert!(
        !text.contains("env=prod") && !text.contains("postgres"),
        "no facts about the resource leak: {text}"
    );
    // What they can reach is explained plainly.
    let ok = policy.explain_for_user(
        &held,
        &eligible,
        "web-staging",
        Some(&Principal::SshLogin("root".into())),
    );
    assert!(ok.join("\n").contains("But not as login root"));
    // And what they could ask for.
    let ask = policy.explain_for_user(&held, &strings(&["prod-db-readonly"]), "orders-prod", None);
    let ask = ask.join("\n");
    assert!(ask.contains("limen request orders-prod --for 30m"), "{ask}");
    // ... and who approves (#120).
    assert!(
        ask.contains("`prod-db-readonly`: approved by members of sre-leads"),
        "{ask}"
    );
    // Break-glass alone: the break-glass command, and no approver to wait for.
    let glass = policy
        .explain_for_user(&held, &strings(&["prod-ssh-emergency"]), "web-prod", None)
        .join("\n");
    assert!(glass.contains("break-glass: granted at once"), "{glass}");
    assert!(
        glass.contains("limen request web-prod --break-glass"),
        "{glass}"
    );
}

/// The suggested request command works as printed: its duration never exceeds
/// the role's own limit, and several break-glass roles name the one to ask for.
#[test]
fn the_suggested_request_command_respects_the_role() {
    let held = strings(&["dev"]);
    // A role that allows only 15 minutes: `--for 30m` would be refused.
    let short = with(
        r"
kind: role
version: v1
metadata: { name: quick }
spec:
  allow:
    - resources: { kind: [postgres], labels: { env: [prod] } }
      db: { roles: [limen_read], databases: ['*'] }
  request:
    who: [developers]
    approvers: [sre-leads]
    max_duration: 15m
",
    );
    let ask = short
        .explain_for_user(&held, &strings(&["quick"]), "orders-prod", None)
        .join("\n");
    assert!(ask.contains("limen request orders-prod --for 15m"), "{ask}");

    // Two break-glass roles and nothing else: the command says which.
    let two = with(
        r"
kind: role
version: v1
metadata: { name: prod-ssh-emergency-2 }
spec:
  break_glass: true
  allow:
    - resources: { kind: [ssh], labels: { env: [prod] } }
      ssh: { logins: [ubuntu] }
  request:
    who: [developers]
",
    );
    let glass = two
        .explain_for_user(
            &held,
            &strings(&["prod-ssh-emergency", "prod-ssh-emergency-2"]),
            "web-prod",
            None,
        )
        .join("\n");
    assert!(
        glass.contains("limen request web-prod --break-glass --role prod-ssh-emergency "),
        "{glass}"
    );
}

// ---------------------------------------------------------------------------
// Effective-access tooling.

#[test]
fn who_can_lists_standing_requestable_and_break_glass() {
    let policy = base();
    let entries = policy.who_can("web-prod");
    let by_role = |role: &str| entries.iter().find(|e| e.role == role).expect(role);
    assert_eq!(by_role("sre").via, Via::Standing);
    assert_eq!(by_role("sre").groups, ["sre"]);
    assert_eq!(by_role("prod-ssh-emergency").via, Via::BreakGlass);
    assert_eq!(by_role("prod-ssh-emergency").groups, ["developers"]);
    assert!(
        !entries.iter().any(|e| e.role == "dev"),
        "dev only reaches staging"
    );
    let db = policy.who_can("orders-prod");
    let ask = db
        .iter()
        .find(|e| e.role == "prod-db-readonly")
        .expect("requestable");
    assert_eq!(ask.via, Via::Request);
    assert_eq!(ask.approvers, ["sre-leads"]);
}

#[test]
fn what_can_separates_standing_from_requestable() {
    let policy = base();
    let can = policy
        .what_can(&strings(&["developers"]), None)
        .expect("what_can");
    assert_eq!(
        can.standing
            .iter()
            .map(|r| r.name.as_str())
            .collect::<Vec<_>>(),
        ["web-staging"]
    );
    assert_eq!(
        can.requestable
            .iter()
            .map(|r| r.name.as_str())
            .collect::<Vec<_>>(),
        ["orders-prod", "web-prod"]
    );
    assert!(policy.what_can(&[], Some("nobody")).is_err());
}

#[test]
fn access_diff_reads_as_who_gained_what() {
    let old = base();
    let wider = BASE.replace(
        "{ idp_group: developers, roles: [dev] }",
        "{ idp_group: developers, roles: [dev, sre] }",
    );
    let new = Policy::parse_yaml([("b.yaml", wider.as_str())]).expect("wider");
    let diff = old.access_diff(&new);
    assert!(diff.widens());
    let text = diff.render_text();
    assert!(
        text.contains("+ group `developers` gains ssh access to `web-prod` as deploy, ubuntu"),
        "{text}"
    );
    assert!(diff.changes.iter().all(|c| c.change == ChangeKind::Gain));
    // Moving a role from standing to by-request is a loss of standing access.
    let back = new.access_diff(&old);
    assert!(
        back.changes
            .iter()
            .all(|c| c.change == ChangeKind::Loss || c.via != Via::Standing),
        "going back opens no standing access: {:?}",
        back.changes
    );
    assert!(back.render_text().contains("- group `developers` loses"));
    // A change that opens nothing says so.
    assert!(old.access_diff(&old).is_empty());
    assert!(
        old.access_diff(&old)
            .render_text()
            .contains("No change in effective access")
    );
    let md = diff.render_markdown();
    assert!(md.contains("Access gained"), "{md}");
    // Requestable access shows up as its own kind of gain.
    let none = Policy::parse_yaml([(
        "b.yaml",
        BASE.replace(
            "who: [developers]\n    approvers",
            "who: [nobody]\n    approvers",
        )
        .as_str(),
    )])
    .expect("p");
    let asked = none.access_diff(&old);
    assert!(
        asked.changes.iter().any(|c| c.via == Via::Request
            && c.subject == Subject::Group("developers".into())
            && c.resource == "orders-prod"),
        "{:?}",
        asked.changes
    );
}

// ---------------------------------------------------------------------------
// policy_test

const TESTS: &str = r"
kind: policy_test
version: v1
metadata: { name: prod-is-locked-down }
spec:
  cases:
    - name: developers cannot ssh to prod
      who: { groups: [developers] }
      resource: web-prod
      principal: { login: root }
      expect: deny
    - name: developers can ask for the prod database
      who: { groups: [developers] }
      resource: orders-prod
      principal: { db_role: limen_read, database: orders }
      expect: request
    - name: sre read prod
      who: { groups: [sre] }
      resource: orders-prod
      principal: { db_role: limen_read, database: orders }
      expect: allow
      via_role: sre
";

#[test]
fn policy_tests_run_through_the_real_engine() {
    let policy = with(TESTS);
    let report = policy.run_tests();
    assert!(report.ok(), "{:#?}", report.results);
    assert_eq!(report.results.len(), 3);
    assert_eq!(report.coverage.deny_cases, 1);
    // Coverage names what no case touched.
    assert_eq!(report.coverage.untested_resources, ["web-staging"]);
    assert_eq!(report.coverage.untested_roles, Vec::<String>::new());
}

#[test]
fn a_failing_case_says_what_it_got() {
    let bad = TESTS.replace("expect: deny", "expect: allow");
    let report = with(&bad).run_tests();
    assert_eq!(report.failed(), 1);
    let failed = report.results.iter().find(|r| !r.passed).expect("failure");
    assert_eq!(
        (failed.expected.as_str(), failed.got.as_str()),
        ("allow", "deny")
    );
    // `via_role` must be the role that granted it.
    let wrong_via = TESTS.replace("via_role: sre", "via_role: dev");
    let report = with(&wrong_via).run_tests();
    let failed = report.results.iter().find(|r| !r.passed).expect("failure");
    assert!(
        failed.detail.contains("allowed through sre, not dev"),
        "{failed:?}"
    );
}

#[test]
fn a_deny_case_on_a_typo_does_not_pass() {
    let typo = TESTS.replace("resource: web-prod", "resource: web-prd");
    let report = with(&typo).run_tests();
    let failed = report.results.iter().find(|r| !r.passed).expect("failure");
    assert_eq!(failed.got, "error");
    assert!(failed.detail.contains("no resource named web-prd"));
    // A bot that doesn't exist is a failure too.
    let bot = TESTS.replace(
        "who: { groups: [developers] }\n      resource: web-prod",
        "who: { bot: ghost }\n      resource: web-prod",
    );
    assert!(!with(&bot).run_tests().ok());
}

#[test]
fn policy_test_documents_are_validated_and_ignored_at_runtime() {
    for (yaml, expect) in [
        (
            TESTS.replace(
                "principal: { login: root }",
                "principal: { login: root, web: true }",
            ),
            "exactly one",
        ),
        (
            TESTS.replace(
                "who: { groups: [developers] }\n      resource: web-prod",
                "who: {}\n      resource: web-prod",
            ),
            "who needs",
        ),
        (
            TESTS.replace(
                "db_role: limen_read, database: orders }\n      expect: request",
                "db_role: limen_read }\n      expect: request",
            ),
            "needs a database",
        ),
        (
            TESTS.replace("expect: deny", "expect: deny\n      via_role: sre"),
            "via_role goes with",
        ),
    ] {
        let err =
            Policy::parse_yaml([("base.yaml", BASE), ("t.yaml", yaml.as_str())]).expect_err(expect);
        assert!(err.to_string().contains(expect), "{expect}: {err}");
    }
    // Same decisions with or without the tests in the policy.
    let (a, b) = (base(), with(TESTS));
    let held = strings(&["dev"]);
    let req = AccessRequest {
        roles: &held,
        resource: "web-staging",
        principal: Principal::SshLogin("ubuntu".into()),
    };
    assert_eq!(a.evaluate(&req), b.evaluate(&req));
    assert_ne!(a.digest(), b.digest(), "tests are part of the document set");
}

// ---------------------------------------------------------------------------
// discovery documents

const DISCOVERY: &str = r"
kind: discovery
version: v1
metadata: { name: aws-prod }
spec:
  provider: aws
  accounts: [{ role_arn: 'arn:aws:iam::111122223333:role/limen-discovery' }]
  regions: [eu-west-1]
  auto_accept: [team]
  match:
    - type: ec2
      tags: { limen/managed: ['true'] }
      name_template: '{{ tag.Name }}'
      ssh: { port: 22 }
      labels_from_tags: [env, team]
    - type: rds
      labels: { source: aws }
";

#[test]
fn discovery_documents_parse_and_default() {
    let policy = with(DISCOVERY);
    let doc = policy.discovery().next().expect("discovery");
    assert_eq!(doc.spec.interval(), discovery::DEFAULT_INTERVAL);
    assert_eq!(doc.spec.stale_after_cycles(), 3);
    assert_eq!(doc.spec.matchers.len(), 2);
    // Round-trips through the signed snapshot's JSON form.
    let json = serde_json::to_string(&policy.documents()).expect("json");
    let back: Vec<Document> = serde_json::from_str(&json).expect("back");
    assert_eq!(
        Policy::from_documents(back).expect("policy").digest(),
        policy.digest()
    );
}

#[test]
fn discovery_documents_refuse_what_a_tag_could_abuse() {
    for (from, to, expect) in [
        (
            "regions: [eu-west-1]",
            "regions: []",
            "regions must not be empty",
        ),
        ("regions: [eu-west-1]", "regions: [mars]", "invalid region"),
        (
            "role_arn: 'arn:aws:iam::111122223333:role/limen-discovery'",
            "role_arn: 'arn:aws:iam::1:role/x'",
            "role_arn",
        ),
        (
            "labels_from_tags: [env, team]",
            "labels_from_tags: [env, limen.io/name]",
            "reserved",
        ),
        (
            "labels_from_tags: [env, team]",
            "labels_from_tags: ['Bad Key!']",
            "not a valid label key",
        ),
        (
            "auto_accept: [team]",
            "auto_accept: [owner]",
            "not in any labels_from_tags",
        ),
        (
            "name_template: '{{ tag.Name }}'",
            "name_template: '{{ secret }}'",
            "unknown placeholder",
        ),
        ("  match:\n", "  interval: 5s\n  match:\n", "at least 1m"),
        (
            "    - type: rds\n      labels: { source: aws }",
            "    - type: rds\n      ssh: {}",
            "ec2 matchers only",
        ),
    ] {
        let yaml = DISCOVERY.replace(from, to);
        let err = Policy::parse_yaml([("d.yaml", yaml.as_str())]).expect_err(expect);
        assert!(err.to_string().contains(expect), "{expect}: {err}");
    }
}

// ---------------------------------------------------------------------------
// Discovery: from what a worker saw to a proposed resource

mod proposals {
    use std::collections::BTreeMap;

    use super::*;
    use crate::discovery::{Found, Source, propose, resource_doc};

    const DOC: &str = r"
kind: discovery
version: v1
metadata: { name: aws-prod }
spec:
  provider: aws
  accounts: [{ role_arn: 'arn:aws:iam::111122223333:role/limen-discovery' }]
  regions: [eu-west-1]
  worker_selector: { pool: prod }
  match:
    - type: ec2
      tags: { limen/managed: ['true'] }
      labels_from_tags: [env, team]
      labels: { owner: platform }
    - type: rds
      name_template: 'rds-{{ id }}'
    - type: eks
";

    fn doc() -> crate::discovery::DiscoveryDoc {
        Policy::parse_yaml([("d.yaml", DOC)])
            .expect("doc")
            .discovery()
            .next()
            .expect("discovery")
            .clone()
    }

    fn tags(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn ec2(extra_tags: &[(&str, &str)]) -> Found {
        let mut t = vec![("limen/managed", "true"), ("Name", "Web Prod 1")];
        t.extend_from_slice(extra_tags);
        Found {
            source: Source::Ec2,
            account: "111122223333".into(),
            region: "eu-west-1".into(),
            provider_id: "i-0abc123".into(),
            target: "10.0.1.5:22".into(),
            tags: tags(&t),
            facts: tags(&[(
                "host_key",
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
            )]),
        }
    }

    #[test]
    fn an_instance_gets_its_name_from_the_template_and_only_allowed_tags_become_labels() {
        let p = propose(
            &doc(),
            0,
            &ec2(&[("env", "prod"), ("team", "payments"), ("secret", "x")]),
        )
        .expect("proposal");
        assert_eq!(p.name, "web-prod-1");
        assert_eq!(p.labels["env"], "prod");
        assert_eq!(p.labels["team"], "payments");
        assert_eq!(
            p.labels["owner"], "platform",
            "static labels from the document"
        );
        assert!(
            !p.labels.contains_key("secret"),
            "tags not listed never become labels"
        );
        assert!(!p.labels.contains_key("name"));
        assert_eq!(p.labels["limen.io/region"], "eu-west-1");
        assert_eq!(p.labels["limen.io/discovered"], "true");
        assert_eq!(p.blockers, Vec::<String>::new());
        assert_eq!(p.kind, limen_core::resource::ResourceKind::Ssh);
        // And the result is a valid resource that only the document's workers serve.
        let selector: limen_core::labels::Labels =
            serde_json::from_value(serde_json::json!({ "pool": "prod" })).expect("labels");
        let res = resource_doc(&p.name, &p.labels, &p.spec, &selector).expect("resource");
        let policy = Policy::from_documents([Document::Resource(res)]).expect("valid");
        let r = policy.resource("web-prod-1").expect("resource");
        assert_eq!(r.spec.worker_selector.get("pool"), Some("prod"));
    }

    #[test]
    fn a_tag_cannot_set_the_labels_limen_sets() {
        // A hostile `limen.io/account` tag isn't in labels_from_tags, and the
        // control plane's own values win anyway.
        let mut found = ec2(&[("env", "prod")]);
        found
            .tags
            .insert("limen.io/account".into(), "999999999999".into());
        let p = propose(&doc(), 0, &found).expect("proposal");
        assert_eq!(p.labels["limen.io/account"], "111122223333");
    }

    #[test]
    fn an_invalid_label_value_is_skipped_not_trusted() {
        let p =
            propose(&doc(), 0, &ec2(&[("env", "pr\u{0}od"), ("team", "ok")])).expect("proposal");
        assert!(!p.labels.contains_key("env"));
        assert_eq!(p.labels["team"], "ok");
    }

    #[test]
    fn reports_outside_the_document_are_dropped() {
        let mut other_region = ec2(&[]);
        other_region.region = "us-east-1".into();
        assert!(
            propose(&doc(), 0, &other_region)
                .expect_err("refused")
                .contains("region")
        );
        let mut other_account = ec2(&[]);
        other_account.account = "999999999999".into();
        assert!(
            propose(&doc(), 0, &other_account)
                .expect_err("refused")
                .contains("account")
        );
        let mut untagged = ec2(&[]);
        untagged.tags.remove("limen/managed");
        assert!(
            propose(&doc(), 0, &untagged)
                .expect_err("refused")
                .contains("filter")
        );
        assert!(
            propose(&doc(), 1, &ec2(&[]))
                .expect_err("refused")
                .contains("looks for rds")
        );
        assert!(propose(&doc(), 9, &ec2(&[])).is_err());
    }

    #[test]
    fn a_name_that_cannot_be_built_falls_back_to_the_id() {
        let mut found = ec2(&[]);
        found.tags.remove("Name");
        assert_eq!(
            propose(&doc(), 0, &found).expect("proposal").name,
            "i-0abc123"
        );
        found.tags.insert("Name".into(), "***".into());
        assert_eq!(
            propose(&doc(), 0, &found).expect("proposal").name,
            "i-0abc123"
        );
    }

    #[test]
    fn an_instance_without_a_known_host_key_cannot_be_accepted() {
        let mut found = ec2(&[]);
        found.facts.clear();
        let p = propose(&doc(), 0, &found).expect("proposal");
        assert_eq!(p.blockers.len(), 1);
        assert!(p.blockers[0].contains("host key"));
    }

    fn rds(engine: &str, iam: &str) -> Found {
        Found {
            source: Source::Rds,
            account: "111122223333".into(),
            region: "eu-west-1".into(),
            provider_id: "orders".into(),
            target: "orders.abc.eu-west-1.rds.amazonaws.com:5432".into(),
            tags: BTreeMap::new(),
            facts: tags(&[("engine", engine), ("iam_auth", iam)]),
        }
    }

    #[test]
    fn databases_become_postgres_or_mysql_resources() {
        let p = propose(&doc(), 1, &rds("aurora-postgresql", "true")).expect("postgres");
        assert_eq!(p.name, "rds-orders");
        assert_eq!(p.kind, limen_core::resource::ResourceKind::Postgres);
        assert_eq!(p.spec["postgres"]["iam_auth"], true);
        assert_eq!(
            p.spec["postgres"]["endpoint"],
            "orders.abc.eu-west-1.rds.amazonaws.com:5432"
        );
        let p = propose(&doc(), 1, &rds("mysql", "false")).expect("mysql");
        assert_eq!(p.kind, limen_core::resource::ResourceKind::Mysql);
        assert_eq!(p.spec["mysql"]["iam_auth"], false);
        let p = propose(&doc(), 1, &rds("oracle-ee", "false")).expect("proposal");
        assert!(p.blockers[0].contains("oracle-ee"));
    }

    #[test]
    fn a_cluster_becomes_a_kubernetes_resource() {
        let found = Found {
            source: Source::Eks,
            account: "111122223333".into(),
            region: "eu-west-1".into(),
            provider_id: "prod-eks".into(),
            target: "prod-eks".into(),
            tags: BTreeMap::new(),
            facts: BTreeMap::new(),
        };
        let p = propose(&doc(), 2, &found).expect("proposal");
        assert_eq!(p.spec["kubernetes"]["cluster_name"], "prod-eks");
        assert_eq!(found.key(), "aws:111122223333:eu-west-1:eks:prod-eks");
    }

    #[test]
    fn discovered_resources_never_replace_a_static_one() {
        let base = base();
        let p = propose(&doc(), 0, &ec2(&[])).expect("proposal");
        let selector = limen_core::labels::Labels::default();
        let fresh = resource_doc(&p.name, &p.labels, &p.spec, &selector).expect("resource");
        let clash = resource_doc("web-prod", &p.labels, &p.spec, &selector).expect("resource");
        let (merged, skipped) = base.with_discovered([fresh, clash]);
        assert!(merged.resource("web-prod-1").is_some());
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].0, "web-prod");
        // The static web-prod is untouched.
        assert_eq!(
            merged
                .resource("web-prod")
                .expect("static")
                .spec
                .ssh
                .as_ref()
                .expect("ssh")
                .address,
            "10.0.0.2:22"
        );
        // Roles select the discovered one by label, like any other.
        let can = merged
            .what_can(&["sre".to_owned()], None)
            .expect("what_can");
        assert!(can.standing.iter().any(|r| r.name == "web-prod"));
    }
}
