//! Shadow mode (ADR-0046): reported, never enforced.

use super::*;
use crate::shadow::ShadowMatch;

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
metadata: { name: wiki, labels: { env: prod } }
spec: { web: { address: 'h:80', host: 'wiki.example.com', insecure_dev: true } }
";

const BASE_ROLE: &str = r"
kind: role
version: v1
metadata: { name: dev }
spec:
  allow:
    - resources: { kind: [ssh], labels: { env: [prod, staging] } }
      ssh: { logins: [ubuntu, root] }
    - resources: { kind: [web], labels: { env: [prod] } }
      web: { methods: [GET, DELETE] }
  deny:
    - name: no-root-in-prod
      mode: shadow
      shadow_until: 2027-01-31
      resources: { kind: [ssh], labels: { env: [prod] } }
      ssh: { logins: [root] }
    - name: no-delete
      mode: shadow
      shadow_until: 2027-01-31
      resources: { kind: [web] }
      web: { methods: [DELETE], path_prefixes: [/admin] }
";

fn policy(role: &str) -> Result<Policy, PolicyError> {
    Policy::parse_yaml([("resources.yaml", RESOURCES), ("roles.yaml", role)])
}

fn none() -> Vec<ShadowMatch> {
    Vec::new()
}

fn held() -> Vec<String> {
    vec!["dev".to_owned()]
}

fn request<'a>(roles: &'a [String], resource: &'a str, login: &str) -> AccessRequest<'a> {
    AccessRequest {
        roles,
        resource,
        principal: Principal::SshLogin(login.into()),
    }
}

#[test]
fn a_shadow_deny_never_changes_the_decision_but_is_reported() {
    let p = policy(BASE_ROLE).expect("valid");
    let roles = held();
    let req = request(&roles, "web-prod", "root");
    assert!(p.evaluate(&req).is_allowed(), "shadow does not deny");
    let hits = p.shadow_denies(&req);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].role, "dev");
    assert_eq!(hits[0].rule, "no-root-in-prod");
    assert_eq!(hits[0].index, 0);
    // Not matching: other login, other environment.
    assert_eq!(
        p.shadow_denies(&request(&roles, "web-prod", "ubuntu")),
        none()
    );
    assert_eq!(
        p.shadow_denies(&request(&roles, "web-staging", "root")),
        none()
    );
}

#[test]
fn nothing_is_reported_when_enforcement_already_refuses() {
    let role = format!(
        "{BASE_ROLE}---\nkind: role\nversion: v1\nmetadata: {{ name: lock }}\nspec:\n  deny:\n    - resources: {{ kind: [ssh], labels: {{ env: [prod] }} }}\n"
    );
    let p = policy(&role).expect("valid");
    let roles = vec!["dev".to_owned(), "lock".to_owned()];
    let req = request(&roles, "web-prod", "root");
    assert!(!p.evaluate(&req).is_allowed());
    assert_eq!(p.shadow_denies(&req), none());
}

#[test]
fn a_shadow_role_grants_nothing_and_reports_its_denies() {
    let role = r"
kind: role
version: v1
metadata: { name: ghost }
spec:
  mode: shadow
  shadow_until: 2027-01-31
  allow:
    - resources: { kind: [ssh] }
      ssh: { logins: [ubuntu] }
  deny:
    - name: no-prod
      resources: { kind: [ssh], labels: { env: [prod] } }
";
    let both = format!("{BASE_ROLE}---{role}");
    let p = policy(&both).expect("valid");
    // Alone it grants nothing.
    let only = vec!["ghost".to_owned()];
    assert!(
        !p.evaluate(&request(&only, "web-staging", "ubuntu"))
            .is_allowed()
    );
    // Beside dev it denies nothing and adds no grant, but it reports.
    let roles = vec!["dev".to_owned(), "ghost".to_owned()];
    let req = request(&roles, "web-prod", "ubuntu");
    assert!(p.evaluate(&req).is_allowed());
    let hits = p.shadow_denies(&req);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].rule, "no-prod");
    assert!(
        p.warnings()
            .iter()
            .any(|w| w.contains("shadow mode until 2027-01-31"))
    );
}

#[test]
fn shadow_rules_do_not_widen_what_tools_say_a_role_reaches() {
    let enforced = BASE_ROLE
        .replace("      mode: shadow\n", "")
        .replace("      shadow_until: 2027-01-31\n", "");
    let (shadow, enforced) = (
        policy(BASE_ROLE).expect("valid"),
        policy(&enforced).expect("valid"),
    );
    let diff = enforced.access_diff(&shadow);
    assert!(
        diff.widens_standing(),
        "moving a deny to shadow widens effective access: {diff:?}"
    );
    assert!(!shadow.access_diff(&enforced).widens());
    assert!(shadow.access_diff(&shadow).is_empty());
}

#[test]
fn web_requests_are_reported_by_method_and_path() {
    let p = policy(BASE_ROLE).expect("valid");
    let roles = held();
    assert!(p.web_request_allowed(&roles, "wiki", "DELETE", "/admin/users"));
    let hits = p.shadow_denies_web(&roles, "wiki", "DELETE", "/admin/users");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].rule, "no-delete");
    assert_eq!(
        p.shadow_denies_web(&roles, "wiki", "GET", "/admin/users"),
        none()
    );
    assert_eq!(
        p.shadow_denies_web(&roles, "wiki", "DELETE", "/public"),
        none()
    );
}

#[test]
fn an_unnamed_or_unlimited_shadow_is_rejected() {
    let cases = [
        // No name.
        BASE_ROLE.replacen(
            "    - name: no-root-in-prod\n",
            "    - name_removed: x\n",
            1,
        ),
        // No shadow_until.
        BASE_ROLE.replacen("      shadow_until: 2027-01-31\n", "", 1),
        // Duplicate names.
        BASE_ROLE.replace("no-delete", "no-root-in-prod"),
        // Shadow on an allow rule.
        BASE_ROLE.replacen(
            "    - resources: { kind: [web], labels: { env: [prod] } }\n",
            "    - mode: shadow\n      resources: { kind: [web], labels: { env: [prod] } }\n",
            1,
        ),
        // shadow_until without a mode.
        BASE_ROLE.replacen("      mode: shadow\n", "", 1),
        // A bad date.
        BASE_ROLE.replacen("2027-01-31", "2027-13-31", 1),
    ];
    for (i, case) in cases.iter().enumerate() {
        assert!(
            policy(case).is_err(),
            "case {i} should be rejected:\n{case}"
        );
    }
}

#[test]
fn shadow_roles_have_their_own_rules() {
    let role = |spec: &str| {
        format!(
            "kind: role\nversion: v1\nmetadata: {{ name: ghost }}\nspec:\n  mode: shadow\n{spec}"
        )
    };
    let deny = "  deny:\n    - name: a\n      resources: { kind: [ssh] }\n";
    assert!(policy(&role(&format!("  shadow_until: 2027-01-31\n{deny}"))).is_ok());
    // No date.
    assert!(policy(&role(deny)).is_err());
    // Nothing to report.
    let allow_only = "  shadow_until: 2027-01-31\n  allow:\n    - resources: { kind: [ssh] }\n      ssh: { logins: [x] }\n";
    assert!(policy(&role(allow_only)).is_err());
    // An unnamed deny rule.
    let unnamed = "  shadow_until: 2027-01-31\n  deny:\n    - resources: { kind: [ssh] }\n";
    assert!(policy(&role(unnamed)).is_err());
    // A rule-level date inside a shadow role.
    let both = "  shadow_until: 2027-01-31\n  deny:\n    - name: a\n      shadow_until: 2027-01-31\n      resources: { kind: [ssh] }\n";
    assert!(policy(&role(both)).is_err());
    // Requestable.
    let requestable = format!("  shadow_until: 2027-01-31\n  request: {{ who: [g] }}\n{deny}");
    assert!(policy(&role(&requestable)).is_err());
}

#[test]
fn shadow_fields_round_trip_and_enforce_is_the_default() {
    let p = policy(BASE_ROLE).expect("valid");
    let again = Policy::from_documents(p.documents()).expect("round trips");
    assert_eq!(p.digest(), again.digest());
    let plain = policy(
        "kind: role\nversion: v1\nmetadata: { name: dev }\nspec:\n  allow:\n    - resources: { kind: [ssh] }\n      ssh: { logins: [x] }\n",
    )
    .expect("valid");
    let yaml = serde_json::to_string(&plain.documents()).expect("serializes");
    assert!(
        !yaml.contains("shadow") && !yaml.contains("\"mode\""),
        "{yaml}"
    );
}

/// With the shadow rules switched to enforce, the old policy denies exactly
/// the requests the shadow policy allows and reports (ADR-0028: one engine).
#[test]
fn shadow_reports_exactly_what_enforcing_would_deny() {
    let shadow = policy(BASE_ROLE).expect("valid");
    let enforced_yaml = BASE_ROLE
        .replace("      mode: shadow\n", "")
        .replace("      shadow_until: 2027-01-31\n", "");
    let enforced = policy(&enforced_yaml).expect("valid");
    let resources = ["web-prod", "web-staging", "wiki", "nope"];
    let logins = ["ubuntu", "root", "deploy"];
    let principals: Vec<Principal> = logins
        .iter()
        .map(|l| Principal::SshLogin((*l).into()))
        .chain([Principal::WebAccess])
        .collect();
    let mut seed = 0x5eed_u64;
    let mut next = |n: usize| {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        usize::try_from(seed >> 33).expect("fits") % n
    };
    for _ in 0..5_000 {
        let roles = if next(4) == 0 { Vec::new() } else { held() };
        let req = AccessRequest {
            roles: &roles,
            resource: resources[next(resources.len())],
            principal: principals[next(principals.len())].clone(),
        };
        let reported = !shadow.shadow_denies(&req).is_empty();
        let now = shadow.evaluate(&req);
        let then = enforced.evaluate(&req);
        if now.is_allowed() {
            assert_eq!(
                reported,
                matches!(
                    then,
                    Decision::Deny {
                        reason: DenyReason::ExplicitDeny
                    }
                ),
                "{req:?}"
            );
        } else {
            assert!(!reported, "{req:?}");
            assert!(!then.is_allowed(), "enforcing never opens access: {req:?}");
        }
    }
}

#[test]
fn a_policy_test_can_require_that_a_shadow_rule_fires() {
    let case = |expect: &str, shadow: &str| {
        format!(
            "{BASE_ROLE}---\nkind: policy_test\nversion: v1\nmetadata: {{ name: t }}\nspec:\n  cases:\n    - who: {{ roles: [dev] }}\n      resource: web-prod\n      principal: {{ login: root }}\n      expect: {expect}\n      shadow_deny: [{shadow}]\n"
        )
    };
    let ok = policy(&case("allow", "dev/no-root-in-prod")).expect("valid");
    assert!(ok.run_tests().ok(), "{:?}", ok.run_tests().results);
    let wrong = policy(&case("allow", "dev/no-delete")).expect("valid");
    let report = wrong.run_tests();
    assert!(!report.ok());
    assert!(
        report.results[0].detail.contains("did not match"),
        "{:?}",
        report.results
    );
    assert!(policy(&case("deny", "dev/no-root-in-prod")).is_err());
    assert!(policy(&case("allow", "no-slash")).is_err());
}

fn day(y: i32, m: u8, d: u8) -> time::Date {
    time::Date::from_calendar_date(y, time::Month::try_from(m).expect("month"), d).expect("date")
}

#[test]
fn dates_are_checked_against_a_day_you_name() {
    let p = policy(BASE_ROLE).expect("valid: a past date still loads");
    // Within range.
    assert_eq!(
        p.shadow_date_problems(day(2026, 11, 8)),
        Vec::<String>::new()
    );
    // The last day still counts.
    assert_eq!(
        p.shadow_date_problems(day(2027, 1, 31)),
        Vec::<String>::new()
    );
    // Passed: both rules are named.
    let passed = p.shadow_date_problems(day(2027, 2, 1));
    assert_eq!(passed.len(), 2, "{passed:?}");
    assert!(passed[0].contains("has passed"), "{passed:?}");
    // More than 90 days ahead.
    let far = p.shadow_date_problems(day(2026, 10, 1));
    assert_eq!(far.len(), 2, "{far:?}");
    assert!(far[0].contains("days away"), "{far:?}");
    assert_eq!(p.shadow_rules().len(), 2);
}

#[test]
fn loosening_is_enforce_to_shadow_or_a_later_date() {
    let enforced = BASE_ROLE
        .replace("      mode: shadow\n", "")
        .replace("      shadow_until: 2027-01-31\n", "");
    let (enforced, shadow) = (
        policy(&enforced).expect("valid"),
        policy(BASE_ROLE).expect("valid"),
    );
    // Enforce to shadow, even though the rules were unnamed-in-effect before.
    let lines = enforced.shadow_loosening(&shadow);
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(lines[0].contains("now reported only"), "{lines:?}");
    // The other way, and no change, are not loosening.
    assert_eq!(shadow.shadow_loosening(&enforced), Vec::<String>::new());
    assert_eq!(shadow.shadow_loosening(&shadow), Vec::<String>::new());
    // A later date is.
    let later = policy(&BASE_ROLE.replace("2027-01-31", "2027-02-28")).expect("valid");
    let lines = shadow.shadow_loosening(&later);
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(
        lines[0].contains("moves from 2027-01-31 to 2027-02-28"),
        "{lines:?}"
    );
    // An earlier date is not.
    assert_eq!(later.shadow_loosening(&shadow), Vec::<String>::new());
    // A brand-new shadow rule, and a brand-new role, are not.
    let none = policy("kind: role\nversion: v1\nmetadata: { name: dev }\nspec:\n  allow:\n    - resources: { kind: [ssh] }\n      ssh: { logins: [x] }\n").expect("valid");
    assert_eq!(none.shadow_loosening(&shadow), Vec::<String>::new());
    let empty = policy("kind: role\nversion: v1\nmetadata: { name: other }\nspec:\n  allow:\n    - resources: { kind: [ssh] }\n      ssh: { logins: [x] }\n").expect("valid");
    assert_eq!(empty.shadow_loosening(&shadow), Vec::<String>::new());
}

#[test]
fn moving_a_whole_role_to_shadow_is_loosening_too() {
    let enforced = "kind: role\nversion: v1\nmetadata: { name: lock }\nspec:\n  deny:\n    - name: no-prod\n      resources: { kind: [ssh], labels: { env: [prod] } }\n";
    let shadow = "kind: role\nversion: v1\nmetadata: { name: lock }\nspec:\n  mode: shadow\n  shadow_until: 2027-01-31\n  deny:\n    - name: no-prod\n      resources: { kind: [ssh], labels: { env: [prod] } }\n";
    let (a, b) = (
        policy(enforced).expect("valid"),
        policy(shadow).expect("valid"),
    );
    assert_eq!(a.shadow_loosening(&b).len(), 1);
    assert_eq!(b.shadow_loosening(&a), Vec::<String>::new());
}

#[test]
fn explain_says_a_shadow_rule_matched_but_did_not_apply() {
    let p = policy(BASE_ROLE).expect("valid");
    let roles = held();
    let trace = p.trace(&request(&roles, "web-prod", "root"), &[]);
    assert!(trace.decision.is_allowed(), "{:?}", trace.decision);
    let text = trace.render().join("\n");
    assert!(
        text.contains("deny rule 1 denies") && text.contains("shadow: reported, not enforced"),
        "{text}"
    );
    let admin_view = p.explain_resource(&roles, &[], "web-prod").join("\n");
    assert!(
        admin_view.contains("shadow: reported, not enforced"),
        "{admin_view}"
    );
}

const GHOST: &str = r"
kind: role
version: v1
metadata: { name: ghost }
spec:
  mode: shadow
  shadow_until: 2027-01-31
  allow:
    - resources: { kind: [ssh] }
      ssh: { logins: [ubuntu, root] }
  deny:
    - name: no-prod
      resources: { kind: [ssh], labels: { env: [prod] } }
";

/// A person asking why they can't reach something is never told about shadow
/// rules, and a shadow role they hold is not listed as granting anything.
#[test]
fn a_users_explain_never_mentions_shadow_rules() {
    let both = format!("{BASE_ROLE}---{GHOST}");
    let p = policy(&both).expect("valid");
    for roles in [vec!["dev"], vec!["ghost"], vec!["dev", "ghost"], vec![]] {
        let roles: Vec<String> = roles.into_iter().map(str::to_owned).collect();
        for resource in ["web-prod", "web-staging", "wiki", "nope"] {
            for principal in [Some(Principal::SshLogin("root".into())), None] {
                let text = p
                    .explain_for_user(&roles, &[], resource, principal.as_ref())
                    .join("\n");
                for word in ["shadow", "no-root-in-prod", "no-prod", "no-delete"] {
                    assert!(!text.contains(word), "{roles:?} {resource}: {text}");
                }
                assert!(
                    !text.contains("Your role `ghost` allows"),
                    "a shadow role grants nothing: {text}"
                );
            }
        }
    }
    // An admin's trace does show them.
    let held = vec!["dev".to_owned(), "ghost".to_owned()];
    let text = p
        .trace(&request(&held, "web-prod", "root"), &[])
        .render()
        .join("\n");
    assert!(text.contains("shadow"), "{text}");
}

/// ADR-0028's one-engine rule with shadow rules and a shadow role present:
/// the trace and enforcement agree on every request.
#[test]
fn trace_agrees_with_enforcement_with_shadow_rules_present() {
    let p = policy(&format!("{BASE_ROLE}---{GHOST}")).expect("valid");
    let all = ["dev", "ghost", "unknown"];
    let resources = ["web-prod", "web-staging", "wiki", "nope"];
    let principals = [
        Principal::SshLogin("ubuntu".into()),
        Principal::SshLogin("root".into()),
        Principal::WebAccess,
    ];
    let mut seed = 0xfeed_u64;
    let mut next = |n: usize| {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        usize::try_from(seed >> 33).expect("fits") % n
    };
    for _ in 0..5_000 {
        let held: Vec<String> = all
            .iter()
            .filter(|_| next(2) == 0)
            .map(|r| (*r).to_owned())
            .collect();
        let eligible: Vec<String> = all
            .iter()
            .filter(|_| next(3) == 0)
            .map(|r| (*r).to_owned())
            .collect();
        let req = AccessRequest {
            roles: &held,
            resource: resources[next(resources.len())],
            principal: principals[next(principals.len())].clone(),
        };
        assert_eq!(
            p.trace(&req, &[]).decision,
            p.evaluate(&req),
            "{held:?} {req:?}"
        );
        assert_eq!(
            p.trace(&req, &eligible).decision,
            p.evaluate_eligible(&req, &eligible),
            "{held:?} {eligible:?} {req:?}"
        );
        // A shadow role never opens anything by itself.
        if held.iter().all(|r| r != "dev") {
            assert!(!p.evaluate(&req).is_allowed(), "{held:?} {req:?}");
        }
    }
}
