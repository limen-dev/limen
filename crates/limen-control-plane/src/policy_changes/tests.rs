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
fn people_are_held_only_when_everything_is() {
    assert!(hold_for(None, WideningApproval::Writers).is_none());
    assert!(hold_for(None, WideningApproval::All).is_some());
    assert!(hold_for(Some("payments"), WideningApproval::Writers).is_some());
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

#[test]
fn only_people_and_bots_gain_standing_access() {
    use limen_core::resource::ResourceKind;
    use limen_policy::tooling::{AccessChange, ChangeKind, Subject, Via};
    let change = |subject: Subject, change: ChangeKind, via: Via| AccessChange {
        change,
        subject,
        resource: "web".into(),
        kind: ResourceKind::Ssh,
        via,
        principals: vec!["ubuntu".into()],
    };
    assert!(gives_standing(&change(
        Subject::Group("sre".into()),
        ChangeKind::Gain,
        Via::Standing
    )));
    assert!(gives_standing(&change(
        Subject::Bot("ci".into()),
        ChangeKind::Gain,
        Via::Standing
    )));
    // A role reaching more is nobody's access until someone holds it.
    assert!(!gives_standing(&change(
        Subject::Role("ops".into()),
        ChangeKind::Gain,
        Via::Standing
    )));
    assert!(!gives_standing(&change(
        Subject::Group("sre".into()),
        ChangeKind::Gain,
        Via::Request
    )));
    assert!(!gives_standing(&change(
        Subject::Group("sre".into()),
        ChangeKind::Loss,
        Via::Standing
    )));
}
