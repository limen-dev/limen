//! Policy writes with several control plane replicas on one database (#182).
//! Set `LIMEN_TEST_DATABASE_URL` to run them.
//!
//! A replica reloads another replica's applies only on its next refresh (every
//! few seconds), so its in-memory policy can be behind. A write must still be
//! computed against the latest version in the database.

mod common;

use common::{Harness, forwarded};
use limen_audit::EventKind;
use limen_proto::v1::admin_client::AdminClient;
use limen_proto::v1::{ApplyPolicyRequest, ApplyPolicyResponse, PolicySource};
use limen_testkit::users::ADMIN;
use rustls_pki_types::CertificateDer;

const ROLES: &str = include_str!("../../../examples/policy/shared/roles.yaml");
const MAPPINGS: &str = include_str!("../../../examples/policy/shared/mappings.yaml");
const SSH: &str = include_str!("../../../examples/policy/stacks/ssh/resources.yaml");
const DATABASE: &str = include_str!("../../../examples/policy/stacks/database/resources.yaml");

/// Roles, mappings, and the SSH resources.
fn small() -> Vec<PolicySource> {
    sources(&[("resources.yaml", SSH)])
}

/// `small` plus the database resources.
fn large() -> Vec<PolicySource> {
    sources(&[("resources.yaml", SSH), ("databases.yaml", DATABASE)])
}

fn sources(resources: &[(&str, &str)]) -> Vec<PolicySource> {
    [("roles.yaml", ROLES), ("mappings.yaml", MAPPINGS)]
        .iter()
        .chain(resources)
        .map(|(name, content)| PolicySource {
            name: (*name).into(),
            content: (*content).into(),
        })
        .collect()
}

/// Two replicas on one database, and an admin certificate both accept.
async fn pair() -> Option<(Harness, Harness, CertificateDer<'static>)> {
    let a = Harness::start_with(&["--id=cp-a".into()]).await?;
    let b = a.start_peer(&["--id=cp-b".into()]).await;
    let (_, admin) = a.login(ADMIN, &["admins"]).await.expect("admin login");
    Some((a, b, admin))
}

async fn apply(
    h: &Harness,
    admin: &CertificateDer<'static>,
    sources: Vec<PolicySource>,
) -> ApplyPolicyResponse {
    let (_, proxy) = h.enroll_proxy().await;
    AdminClient::new(h.channel(Some(proxy)))
        .apply_policy(forwarded(
            ApplyPolicyRequest {
                sources,
                dry_run: false,
                source_ref: String::new(),
                require_tests: false,
            },
            Some(admin),
        ))
        .await
        .expect("apply")
        .into_inner()
}

/// `(version, previous_version)` of every `policy.change` either replica audited.
async fn changes(a: &Harness, b: &Harness) -> Vec<(i64, i64)> {
    let mut all: Vec<(i64, i64)> = a
        .audit_events()
        .await
        .into_iter()
        .chain(b.audit_events().await)
        .filter(|e| e.kind == EventKind::PolicyChange)
        .map(|e| {
            (
                e.data["version"].as_i64().expect("version"),
                e.data["previous_version"]
                    .as_i64()
                    .expect("previous_version"),
            )
        })
        .collect();
    all.sort_unstable();
    all
}

/// The bug: B still holds `small` in memory while A has made `large` active.
/// Applying `small` through B used to compare it with B's stale copy, find no
/// difference, and answer "unchanged" without applying, leaving `large`
/// active. It must apply, and audit the version it really replaced.
#[tokio::test]
async fn a_stale_replica_does_not_skip_an_apply() {
    let Some((a, b, admin)) = Box::pin(pair()).await else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL");
        return;
    };
    let first = apply(&a, &admin, small()).await;
    assert!(first.applied);
    // Let B load `small`, as its refresh would.
    b.state.policy.refresh(&b.state.db).await.expect("refresh");
    assert_eq!(b.state.policy.base().version, first.version);

    let second = apply(&a, &admin, large()).await;
    assert!(second.applied);
    // B hasn't refreshed: its copy is still `small`. (Its own refresh job
    // could catch up at any moment; the assertions below hold either way.)
    let third = apply(&b, &admin, small()).await;
    assert!(
        third.applied,
        "B compared against its stale copy and skipped the apply"
    );
    assert!(third.version > second.version);
    let diff = third.diff.expect("diff");
    assert!(
        !diff.removed.is_empty(),
        "the diff must remove the database resources that `large` added"
    );
    assert!(
        changes(&a, &b)
            .await
            .contains(&(third.version, second.version))
    );
}

/// Concurrent applies through both replicas: every `policy.change` names the
/// version it really replaced, so the chain has no gaps or forks.
#[tokio::test]
async fn concurrent_applies_on_two_replicas_audit_an_unbroken_chain() {
    let Some((a, b, admin)) = Box::pin(pair()).await else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL");
        return;
    };
    let writes = (0..8).map(|i| {
        let (h, sources) = match i % 4 {
            0 => (&a, small()),
            1 => (&b, large()),
            2 => (&a, large()),
            _ => (&b, small()),
        };
        apply(h, &admin, sources)
    });
    let results = futures::future::join_all(writes).await;
    let mut applied: Vec<i64> = results
        .iter()
        .filter(|r| r.applied)
        .map(|r| r.version)
        .collect();
    applied.sort_unstable();
    let chain = changes(&a, &b).await;
    assert_eq!(
        chain.iter().map(|(v, _)| *v).collect::<Vec<_>>(),
        applied,
        "one policy.change per applied version"
    );
    let mut previous = 0;
    for (version, before) in chain {
        assert_eq!(
            before, previous,
            "version {version} names the wrong predecessor"
        );
        previous = version;
    }
}
