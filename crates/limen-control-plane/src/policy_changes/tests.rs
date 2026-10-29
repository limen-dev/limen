use serde_json::json;

use super::*;
use crate::policy_store::{Input, Owner};

fn input(kind: &str, profile: Option<&str>) -> Input {
    Input {
        kind: kind.into(),
        name: "x".into(),
        value: json!({}),
        profile: profile.map(str::to_owned),
    }
}

fn create(kind: &str, profile: Option<&str>) -> Change {
    Change::Create {
        owner: Owner::default_git(),
        input: input(kind, profile),
    }
}

#[test]
fn only_resources_from_profiles_are_approved_by_the_grant() {
    assert!(!beyond_profiles(&[create("resource", Some("pg"))]));
    assert!(beyond_profiles(&[create("resource", None)]));
    assert!(beyond_profiles(&[create("role_mapping", None)]));
    assert!(beyond_profiles(&[
        create("resource", Some("pg")),
        create("role", None)
    ]));
    let delete = |kind: &str| Change::Delete {
        owner: Owner::default_git(),
        key: (kind.into(), "x".into()),
        etag: None,
        allow_missing: true,
    };
    assert!(!beyond_profiles(&[delete("resource")]));
    assert!(beyond_profiles(&[delete("role")]));
}

#[test]
fn people_are_held_only_when_everything_is() {
    let changes = [create("role", None)];
    assert!(hold_for(false, WideningApproval::Writers, &changes).is_none());
    assert!(hold_for(false, WideningApproval::All, &changes).is_some());
    assert!(hold_for(true, WideningApproval::Writers, &changes).is_some());
    assert!(
        hold_for(
            true,
            WideningApproval::Writers,
            &[create("resource", Some("pg"))]
        )
        .is_none()
    );
}

#[test]
fn whoever_started_the_run_cant_approve_it() {
    let github = BTreeMap::from([("actor".to_owned(), "OctoCat".to_owned())]);
    assert!(started_the_run("octocat", &github));
    assert!(started_the_run("octocat@example.com", &github));
    assert!(!started_the_run("alice", &github));
    let gitlab = BTreeMap::from([("user_login".to_owned(), "alice".to_owned())]);
    assert!(started_the_run("Alice@corp.example", &gitlab));
    assert!(!started_the_run("bob", &gitlab));
    assert!(!started_the_run("alice", &BTreeMap::new()));
}

#[test]
fn plans_round_trip_through_json() {
    let plan = Plan {
        changes: vec![create("resource", Some("pg"))],
        require_tests: true,
        gains: vec!["group:sre gains ssh on web".into()],
        basis: vec![(("resource".into(), "x".into()), None)],
    };
    let back: Plan =
        serde_json::from_value(serde_json::to_value(&plan).expect("to json")).expect("from json");
    assert_eq!(back.gains, plan.gains);
    assert!(back.require_tests);
    assert!(
        matches!(&back.changes[0], Change::Create { input, .. } if input.profile.as_deref() == Some("pg"))
    );
}

#[test]
fn applying_reads_as_pending() {
    assert_eq!(State::parse("applying"), Some(State::Pending));
    assert_eq!(State::parse("superseded"), Some(State::Superseded));
    assert_eq!(State::parse("nope"), None);
}
