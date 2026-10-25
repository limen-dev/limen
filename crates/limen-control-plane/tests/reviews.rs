//! Access reviews, deny overrides, and evidence packs (ADR-0029) against a
//! real PostgreSQL. Set `LIMEN_TEST_DATABASE_URL` to run them.

// A whole control plane is started in each test.
#![allow(clippy::large_futures, clippy::assert_is_empty)]

mod common;

use common::{Harness, forwarded};
use limen_audit::EventKind;
use limen_control_plane::{evidence, reviews};
use limen_proto::v1::policy_sync_client::PolicySyncClient;
use limen_proto::v1::resources_client::ResourcesClient;
use limen_proto::v1::reviews_client::ReviewsClient;
use limen_proto::v1::{
    DecideReviewItemRequest, ExportEvidenceRequest, GetPolicySnapshotRequest, LiftDenyRequest,
    ListDeniesRequest, ListResourcesRequest, ListReviewItemsRequest, ListReviewsRequest,
    ReviewItemInfo, StartReviewRequest,
};
use limen_testkit::users::{ADMIN, AUDITOR, CONTRACTOR, DEVELOPER, ONCALL};
use rustls_pki_types::CertificateDer;
use tonic::{Code, transport::Channel};

const POLICY: &str = r"
kind: resource
version: v1
metadata: { name: web-1, labels: { env: prod, owner: oncall@example.com } }
spec: { ssh: { address: '10.0.0.1:22', host_key: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl' } }
---
kind: resource
version: v1
metadata: { name: db-1, labels: { env: prod } }
spec: { postgres: { endpoint: 'db.internal:5432' } }
---
kind: role
version: v1
metadata: { name: ops }
spec:
  allow:
    - resources: { kind: [ssh], labels: { env: [prod] } }
      ssh: { logins: [ubuntu] }
---
kind: role
version: v1
metadata: { name: dba, labels: { owner: dba-lead@example.com } }
spec:
  allow:
    - resources: { kind: [postgres], labels: { env: [prod] } }
      db: { roles: [limen_read], databases: ['*'] }
---
kind: role_mapping
version: v1
metadata: { name: m }
spec:
  - { idp_group: ops-group, roles: [ops] }
  - { idp_group: dba-group, roles: [dba] }
  - { idp_group: auditors, roles: ['limen:auditor'] }
";

struct Rig {
    h: Harness,
    ch: Channel,
    admin: CertificateDer<'static>,
    oncall: CertificateDer<'static>,
    dev: CertificateDer<'static>,
    auditor: CertificateDer<'static>,
}

async fn rig() -> Option<Rig> {
    let h = Harness::start().await?;
    h.set_policy(&[("p.yaml", POLICY)]);
    let (_, proxy) = h.enroll_proxy().await;
    let ch = h.channel(Some(proxy));
    let (_, admin) = h.login(ADMIN, &["admins"]).await.expect("admin");
    // `oncall` owns web-1 (by label) and holds ops; `developer` holds dba.
    let (_, oncall) = h.login(ONCALL, &["ops-group"]).await.expect("oncall");
    let (_, dev) = h.login(DEVELOPER, &["dba-group"]).await.expect("dev");
    let (_, auditor) = h.login(AUDITOR, &["auditors"]).await.expect("auditor");
    Some(Rig {
        h,
        ch,
        admin,
        oncall,
        dev,
        auditor,
    })
}

impl Rig {
    fn c(&self) -> ReviewsClient<Channel> {
        ReviewsClient::new(self.ch.clone())
    }

    async fn start(&self) -> String {
        self.c()
            .start_review(forwarded(
                StartReviewRequest {
                    name: "Q4".into(),
                    due_days: 14,
                    override_days: 30,
                },
                Some(&self.admin),
            ))
            .await
            .expect("start")
            .into_inner()
            .id
    }

    async fn items(&self, who: &CertificateDer<'static>, review: &str) -> Vec<ReviewItemInfo> {
        self.c()
            .list_review_items(forwarded(
                ListReviewItemsRequest {
                    review_id: review.into(),
                    mine: false,
                    open_only: false,
                },
                Some(who),
            ))
            .await
            .expect("items")
            .into_inner()
            .items
    }

    async fn decide(
        &self,
        who: &CertificateDer<'static>,
        item: &str,
        certify: bool,
        comment: &str,
    ) -> Result<ReviewItemInfo, tonic::Status> {
        self.c()
            .decide_review_item(forwarded(
                DecideReviewItemRequest {
                    item_id: item.into(),
                    certify,
                    comment: comment.into(),
                },
                Some(who),
            ))
            .await
            .map(tonic::Response::into_inner)
    }

    fn find<'a>(items: &'a [ReviewItemInfo], user: &str, role: &str) -> &'a ReviewItemInfo {
        items
            .iter()
            .find(|i| i.subject == user && i.role == role)
            .expect("item")
    }
}

#[tokio::test]
async fn items_go_to_owners_and_nobody_reviews_their_own_access() {
    let Some(r) = rig().await else { return };
    let id = r.start().await;
    let items = r.items(&r.admin, &id).await;
    // One item per person and role they hold.
    let ops = Rig::find(&items, ONCALL, "ops");
    // `ops` has no owner label, but the one resource it reaches names `oncall`.
    // That is also who holds it, so it goes to the admins instead.
    assert_eq!(ops.reviewer, "*admin");
    assert_eq!(ops.reaches.len(), 1);
    assert_eq!(ops.reaches[0].name, "web-1");
    assert!(ops.unused, "nobody has used it");
    // The `dba` role names its owner.
    let dba = Rig::find(&items, DEVELOPER, "dba");
    assert_eq!(dba.reviewer, "dba-lead@example.com");
    // The admin's own role goes to the admin pool, not to themselves.
    let admin = Rig::find(&items, ADMIN, "limen:admin");
    assert_eq!(admin.reviewer, "*admin");
    assert!(!admin.can_decide, "they can't review themselves");
    assert!(ops.can_decide, "another admin can review it");
    // Only admins and auditors see everything; someone else sees only theirs.
    let mine = r.items(&r.dev, &id).await;
    assert!(mine.is_empty(), "the developer owns no items");
    assert_eq!(r.items(&r.auditor, &id).await.len(), items.len());
}

#[tokio::test]
async fn certifying_and_flagging_and_what_a_flag_does() {
    let Some(r) = rig().await else { return };
    let id = r.start().await;
    let items = r.items(&r.admin, &id).await;
    let ops = Rig::find(&items, ONCALL, "ops").id.clone();
    let dba = Rig::find(&items, DEVELOPER, "dba").id.clone();

    // Flagging needs a reason; someone who doesn't own the item can't decide it.
    let err = r
        .decide(&r.admin, &ops, false, "")
        .await
        .expect_err("a flag needs a reason");
    assert_eq!(err.code(), Code::InvalidArgument);
    let err = r
        .decide(&r.oncall, &ops, true, "")
        .await
        .expect_err("their own");
    assert_eq!(err.code(), Code::PermissionDenied);
    let err = r
        .decide(&r.dev, &ops, true, "")
        .await
        .expect_err("not theirs");
    assert_eq!(err.code(), Code::PermissionDenied);
    let err = r
        .decide(&r.auditor, &ops, true, "")
        .await
        .expect_err("auditors read only");
    assert_eq!(err.code(), Code::PermissionDenied);

    // A session the person has open on what the role reaches.
    let session = uuid::Uuid::now_v7();
    sqlx::query("INSERT INTO sessions (session_id, username, resource, started_at) VALUES ($1, $2, 'web-1', now())")
        .bind(session)
        .bind(ONCALL)
        .execute(&r.h.state.db)
        .await
        .expect("session");
    assert_eq!(
        ResourcesClient::new(r.ch.clone())
            .list_resources(forwarded(ListResourcesRequest {}, Some(&r.oncall)))
            .await
            .expect("ls")
            .into_inner()
            .resources
            .len(),
        1
    );

    let flagged = r
        .decide(&r.admin, &ops, false, "left the team")
        .await
        .expect("flag");
    assert_eq!(flagged.decision, "flag");
    // The role is withheld at once: not in `ls`, and the snapshot says so.
    assert!(
        ResourcesClient::new(r.ch.clone())
            .list_resources(forwarded(ListResourcesRequest {}, Some(&r.oncall)))
            .await
            .expect("ls")
            .into_inner()
            .resources
            .is_empty()
    );
    let signed = PolicySyncClient::new(r.ch.clone())
        .get_policy_snapshot(GetPolicySnapshotRequest {})
        .await
        .expect("snapshot")
        .into_inner();
    let snap = limen_session::snapshot::verify_snapshot(&signed, r.h.state.cas.internal.cert_der())
        .expect("verify");
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    assert_eq!(
        snap.restrictions
            .effective_roles(ONCALL, &["ops".to_owned()], "web-1", now)
            .roles,
        Vec::<String>::new(),
        "the certificate still says ops, the override says no"
    );
    assert_eq!(
        snap.restrictions
            .effective_roles(DEVELOPER, &["dba".to_owned()], "db-1", now)
            .roles,
        ["dba"],
        "other people are untouched"
    );
    // What they had open on it ends.
    assert!(
        snap.restrictions
            .killed_sessions
            .contains(&session.to_string())
    );

    // It can't be decided twice, and the dba lead's item is theirs alone.
    assert_eq!(
        r.decide(&r.admin, &ops, true, "")
            .await
            .expect_err("twice")
            .code(),
        Code::AlreadyExists
    );
    let (_, lead) =
        r.h.login("dba-lead@example.com", &["dba-group"])
            .await
            .expect("lead");
    assert_eq!(r.items(&lead, &id).await.len(), 1);
    r.decide(&lead, &dba, true, "still needed")
        .await
        .expect("certify");

    // The review closed when the admin items were left? Not yet: others remain.
    let all = r.items(&r.admin, &id).await;
    assert!(all.iter().any(|i| i.decision.is_empty()));
    let kinds = r.h.audit_kinds().await;
    for want in [
        EventKind::ReviewStart,
        EventKind::ReviewDecide,
        EventKind::AccessDenyOverride,
    ] {
        assert!(kinds.contains(&want), "{want:?}");
    }
}

#[tokio::test]
async fn a_review_closes_when_its_last_item_is_decided_and_counts_silent_certifications() {
    let Some(r) = rig().await else { return };
    // A second admin, so every admin item has someone else to decide it.
    let (_, admin2) =
        r.h.login(CONTRACTOR, &["admins"])
            .await
            .expect("second admin");
    let id = r.start().await;
    let (_, lead) =
        r.h.login("dba-lead@example.com", &["dba-group"])
            .await
            .expect("lead");
    loop {
        let open: Vec<ReviewItemInfo> = r
            .items(&r.admin, &id)
            .await
            .into_iter()
            .filter(|i| i.decision.is_empty())
            .collect();
        let Some(item) = open.first() else { break };
        let decider = if item.reviewer == "dba-lead@example.com" {
            &lead
        } else if item.subject == ADMIN {
            &admin2
        } else {
            &r.admin
        };
        // One with a comment, the rest without.
        let comment = if item.subject == DEVELOPER {
            "still needed"
        } else {
            ""
        };
        r.decide(decider, &item.id, true, comment)
            .await
            .unwrap_or_else(|e| panic!("{item:?}: {e}"));
    }
    let review = r
        .c()
        .list_reviews(forwarded(
            ListReviewsRequest {
                scope: "all".into(),
            },
            Some(&r.admin),
        ))
        .await
        .expect("list")
        .into_inner()
        .reviews
        .remove(0);
    assert_eq!(review.status, "complete");
    assert_eq!(review.items, review.decided);
    assert!(
        review.certified_silently > 0,
        "the dashboard can show certify-without-comment"
    );
    assert!(r.h.audit_kinds().await.contains(&EventKind::ReviewComplete));
    // A closed review takes no more decisions.
    let any = r.items(&r.admin, &id).await[0].id.clone();
    assert_eq!(
        r.decide(&r.admin, &any, true, "")
            .await
            .expect_err("closed")
            .code(),
        Code::FailedPrecondition
    );
}

#[tokio::test]
async fn an_override_lifts_itself_when_the_idp_change_shows_up_and_admins_can_lift_it() {
    let Some(r) = rig().await else { return };
    let id = r.start().await;
    let items = r.items(&r.admin, &id).await;
    let dba = Rig::find(&items, DEVELOPER, "dba").id.clone();
    let (_, lead) =
        r.h.login("dba-lead@example.com", &["dba-group"])
            .await
            .expect("lead");
    r.decide(&lead, &dba, false, "moved teams")
        .await
        .expect("flag");
    let denies = r
        .c()
        .list_denies(forwarded(
            ListDeniesRequest {
                include_ended: false,
            },
            Some(&r.auditor),
        ))
        .await
        .expect("denies")
        .into_inner()
        .denies;
    assert_eq!(denies.len(), 1);
    assert_eq!(
        (denies[0].username.as_str(), denies[0].role.as_str()),
        (DEVELOPER, "dba")
    );

    // Still in their group: nothing changes.
    reviews::tick(&r.h.state).await.expect("tick");
    assert_eq!(
        r.c()
            .list_denies(forwarded(
                ListDeniesRequest {
                    include_ended: false
                },
                Some(&r.admin)
            ))
            .await
            .expect("d")
            .into_inner()
            .denies
            .len(),
        1
    );
    // They log in again and the IdP no longer puts them in the group.
    r.h.login(DEVELOPER, &["ops-group"])
        .await
        .expect("signs in without the dba group");
    reviews::tick(&r.h.state).await.expect("tick");
    assert_eq!(
        r.c()
            .list_denies(forwarded(
                ListDeniesRequest {
                    include_ended: false
                },
                Some(&r.admin)
            ))
            .await
            .expect("d")
            .into_inner()
            .denies
            .len(),
        0,
        "the IdP change was confirmed"
    );

    // An admin can lift one by hand; others cannot.
    let id2 = r.start().await;
    let items = r.items(&r.admin, &id2).await;
    let ops = Rig::find(&items, ONCALL, "ops").id.clone();
    r.decide(&r.admin, &ops, false, "again")
        .await
        .expect("flag");
    let deny = r
        .c()
        .list_denies(forwarded(
            ListDeniesRequest {
                include_ended: false,
            },
            Some(&r.admin),
        ))
        .await
        .expect("d")
        .into_inner()
        .denies
        .remove(0);
    let err = r
        .c()
        .lift_deny(forwarded(
            LiftDenyRequest {
                id: deny.id.clone(),
                reason: "x".into(),
            },
            Some(&r.auditor),
        ))
        .await
        .expect_err("auditor");
    assert_eq!(err.code(), Code::PermissionDenied);
    assert!(
        r.c()
            .lift_deny(forwarded(
                LiftDenyRequest {
                    id: deny.id,
                    reason: "mistake".into()
                },
                Some(&r.admin)
            ))
            .await
            .expect("lift")
            .into_inner()
            .lifted
    );
}

#[tokio::test]
async fn overdue_items_escalate_to_the_admins_and_the_schedule_starts_one_review() {
    let Some(r) = rig().await else { return };
    let id = r.start().await;
    sqlx::query("UPDATE access_reviews SET due_at = now() - interval '1 day'")
        .execute(&r.h.state.db)
        .await
        .expect("age it");
    reviews::tick(&r.h.state).await.expect("tick");
    let items = r.items(&r.admin, &id).await;
    let dba = Rig::find(&items, DEVELOPER, "dba");
    assert_eq!(dba.reviewer, "*admin", "the owner didn't answer in time");
    let listed = r
        .c()
        .list_reviews(forwarded(
            ListReviewsRequest {
                scope: "all".into(),
            },
            Some(&r.admin),
        ))
        .await
        .expect("list")
        .into_inner()
        .reviews;
    assert!(listed[0].overdue);

    // The default schedule has started one already (this harness's first tick),
    // and further ticks don't start another.
    let before = listed.len();
    reviews::tick(&r.h.state).await.expect("tick");
    reviews::tick(&r.h.state).await.expect("tick");
    let after = r
        .c()
        .list_reviews(forwarded(
            ListReviewsRequest {
                scope: "all".into(),
            },
            Some(&r.admin),
        ))
        .await
        .expect("l")
        .into_inner()
        .reviews
        .len();
    assert_eq!(
        after, before,
        "a review was started recently: no second one"
    );
}

#[tokio::test]
async fn an_evidence_pack_is_signed_anchored_and_cannot_be_edited_quietly() {
    let Some(r) = rig().await else { return };
    let id = r.start().await;
    let items = r.items(&r.admin, &id).await;
    let ops = Rig::find(&items, ONCALL, "ops").id.clone();
    r.decide(&r.admin, &ops, true, "=HYPERLINK(\"http://evil\")")
        .await
        .expect("certify");
    sqlx::query("INSERT INTO sessions (session_id, username, kind, resource, started_at) VALUES (gen_random_uuid(), $1, 'ssh', 'web-1', now())")
        .bind(ONCALL)
        .execute(&r.h.state.db)
        .await
        .expect("session");

    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let export = |who: &CertificateDer<'static>| {
        let mut c = r.c();
        let req = forwarded(
            ExportEvidenceRequest {
                from_unix: now - 86_400,
                to_unix: now + 3600,
            },
            Some(who),
        );
        async move {
            c.export_evidence(req)
                .await
                .map(tonic::Response::into_inner)
        }
    };
    // Admins and auditors can; everyone else cannot.
    assert_eq!(
        export(&r.dev).await.expect_err("developer").code(),
        Code::PermissionDenied
    );
    let pack = export(&r.auditor).await.expect("auditor exports");
    let ca = r.h.state.cas.internal.cert_der().clone();

    let v = evidence::verify_pack(&pack.pack, &ca);
    assert!(v.ok(), "{:?}", v.problems);
    assert_eq!(v.manifest_sha256, pack.manifest_sha256);
    let parsed: serde_json::Value = serde_json::from_slice(&pack.pack).expect("json");
    let sections = parsed["sections"].as_object().expect("sections");
    for name in [
        "access_requests",
        "access_grants",
        "reviews",
        "sessions",
        "locks",
        "policy_changes",
        "meta",
        "sessions.csv",
    ] {
        assert!(sections.contains_key(name), "{name}");
    }
    assert_eq!(sections["sessions"].as_array().expect("sessions").len(), 1);
    // A spreadsheet can't run what a reviewer typed.
    let csv = sections["reviews.csv"].as_str().expect("csv");
    assert!(csv.contains("'=HYPERLINK"), "{csv}");
    assert!(!csv.contains(",=HYPERLINK"));

    // The export is in the audit trail, with the same manifest hash.
    let anchored = r.h.audit_events().await.into_iter().any(|e| {
        e.kind == EventKind::EvidenceExport
            && e.data["manifest_sha256"] == pack.manifest_sha256.as_str()
    });
    assert!(anchored);

    // Edit a section: caught. Edit the manifest: caught. Add a section: caught.
    let mut edited = parsed.clone();
    edited["sections"]["sessions"][0]["user"] = serde_json::json!("someone-else@example.com");
    let v = evidence::verify_pack(&serde_json::to_vec(&edited).expect("json"), &ca);
    assert!(
        v.problems
            .iter()
            .any(|p| p.contains("sessions") && p.contains("changed")),
        "{:?}",
        v.problems
    );
    let mut edited = parsed.clone();
    edited["sections"]["extra"] = serde_json::json!([]);
    assert!(!evidence::verify_pack(&serde_json::to_vec(&edited).expect("json"), &ca).ok());
    let mut edited = parsed.clone();
    let m = edited["manifest_json"]
        .as_str()
        .expect("m")
        .replace("\"from\":", "\"from\": ");
    edited["manifest_json"] = serde_json::json!(m);
    assert!(!evidence::verify_pack(&serde_json::to_vec(&edited).expect("json"), &ca).ok());
    // A different CA doesn't vouch for it.
    let other = rig_ca().await;
    assert!(!evidence::verify_pack(&pack.pack, &other).ok());
}

/// A certificate from a different CA.
async fn rig_ca() -> CertificateDer<'static> {
    use limen_ca::{CaPurpose, CertificateAuthority, FileSigner};
    CertificateAuthority::create_self_signed(
        CaPurpose::Internal,
        std::sync::Arc::new(FileSigner::generate().expect("key")),
    )
    .await
    .expect("ca")
    .cert_der()
    .clone()
}

#[tokio::test]
async fn a_period_that_makes_no_sense_is_refused() {
    let Some(r) = rig().await else { return };
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    for (from, to) in [(now, now - 10), (now - 86_400 * 500, now)] {
        let err = r
            .c()
            .export_evidence(forwarded(
                ExportEvidenceRequest {
                    from_unix: from,
                    to_unix: to,
                },
                Some(&r.admin),
            ))
            .await
            .expect_err("bad period");
        assert_eq!(err.code(), Code::InvalidArgument);
    }
}
