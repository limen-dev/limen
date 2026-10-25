//! Just-in-time access (ADR-0025) against a real PostgreSQL and a mock IdP.
//! Set `LIMEN_TEST_DATABASE_URL` to run them.

// A whole control plane is started in each test; `assert!(x.is_empty())`
// reads better than comparing with an empty array.
#![allow(clippy::large_futures, clippy::assert_is_empty)]

mod common;

use common::{Harness, forwarded};
use limen_audit::EventKind;
use limen_control_plane::access;
use limen_proto::v1::access_client::AccessClient;
use limen_proto::v1::policy_sync_client::PolicySyncClient;
use limen_proto::v1::resources_client::ResourcesClient;
use limen_proto::v1::{
    AccessRequestInfo, CancelAccessRequestRequest, DecideAccessRequestRequest, ExplainRequest,
    GetPolicySnapshotRequest, ListAccessGrantsRequest, ListAccessRequestsRequest,
    ListResourcesRequest, RequestAccessRequest, RevokeAccessGrantRequest,
};
use limen_testkit::users::{ADMIN, AUDITOR, CONTRACTOR, DEVELOPER, ONCALL};
use rustls_pki_types::CertificateDer;
use tonic::{Code, transport::Channel};
use uuid::Uuid;

const POLICY: &str = r"
kind: resource
version: v1
metadata: { name: web-staging, labels: { env: staging } }
spec: { ssh: { address: '10.0.0.1:22', host_key: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl' } }
---
kind: resource
version: v1
metadata: { name: web-prod, labels: { env: prod } }
spec: { ssh: { address: '10.0.0.2:22', host_key: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl' } }
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
metadata: { name: prod-ssh }
spec:
  allow:
    - resources: { kind: [ssh], labels: { env: [prod] } }
      ssh: { logins: [ubuntu] }
  request:
    who: [developers]
    approvers: [sre-leads]
    max_duration: 2h
    ticket_pattern: '^(INC|OPS)-[0-9]+'
---
kind: role
version: v1
metadata: { name: prod-db }
spec:
  allow:
    - resources: { kind: [postgres], labels: { env: [prod] } }
      db: { roles: [limen_read], databases: ['*'] }
  request:
    who: [developers]
    approvers: [sre-leads]
    approvals_required: 2
    require_reason: false
---
kind: role
version: v1
metadata: { name: emergency }
spec:
  break_glass: true
  allow:
    - resources: { kind: [ssh], labels: { env: [prod] } }
      ssh: { logins: [ubuntu] }
  request: { who: [developers] }
---
kind: role_mapping
version: v1
metadata: { name: m }
spec:
  - { idp_group: developers, roles: [dev] }
  - { idp_group: auditors, roles: ['limen:auditor'] }
";

struct Rig {
    h: Harness,
    ch: Channel,
    dev: CertificateDer<'static>,
    lead: CertificateDer<'static>,
    admin: CertificateDer<'static>,
}

impl Rig {
    async fn start() -> Option<Self> {
        Self::start_with(&[]).await
    }

    async fn start_with(extra: &[String]) -> Option<Self> {
        let h = Harness::start_with(extra).await?;
        h.set_policy(&[("policy.yaml", POLICY)]);
        let (_, proxy) = h.enroll_proxy().await;
        let ch = h.channel(Some(proxy));
        let (_, dev) = h
            .login(DEVELOPER, &["developers"])
            .await
            .expect("developer");
        let (_, lead) = h.login(ONCALL, &["sre-leads"]).await.expect("lead");
        let (_, admin) = h.login(ADMIN, &["admins"]).await.expect("admin");
        Some(Self {
            h,
            ch,
            dev,
            lead,
            admin,
        })
    }

    fn access(&self) -> AccessClient<Channel> {
        AccessClient::new(self.ch.clone())
    }

    async fn request(
        &self,
        who: &CertificateDer<'static>,
        resource: &str,
        reason: &str,
    ) -> Result<AccessRequestInfo, tonic::Status> {
        self.access()
            .request_access(forwarded(
                RequestAccessRequest {
                    resource: resource.into(),
                    role: String::new(),
                    duration_seconds: 1800,
                    reason: reason.into(),
                    break_glass: false,
                },
                Some(who),
            ))
            .await
            .map(tonic::Response::into_inner)
    }

    async fn decide(
        &self,
        who: &CertificateDer<'static>,
        id: &str,
        approve: bool,
    ) -> Result<AccessRequestInfo, tonic::Status> {
        self.access()
            .decide_access_request(forwarded(
                DecideAccessRequestRequest {
                    id: id.into(),
                    approve,
                    comment: "ok".into(),
                },
                Some(who),
            ))
            .await
            .map(tonic::Response::into_inner)
    }

    async fn listed(&self, who: &CertificateDer<'static>) -> Vec<(String, i64)> {
        ResourcesClient::new(self.ch.clone())
            .list_resources(forwarded(ListResourcesRequest {}, Some(who)))
            .await
            .expect("ls")
            .into_inner()
            .resources
            .into_iter()
            .map(|r| (r.name, r.grant_expires_at_unix))
            .collect()
    }

    async fn kinds(&self) -> Vec<EventKind> {
        self.h.audit_kinds().await
    }
}

#[tokio::test]
async fn ask_approve_use_and_expire() {
    let Some(r) = Rig::start().await else { return };

    // The developer sees what they could ask for, with no address.
    let listed = ResourcesClient::new(r.ch.clone())
        .list_resources(forwarded(ListResourcesRequest {}, Some(&r.dev)))
        .await
        .expect("ls")
        .into_inner();
    let names: Vec<&str> = listed.resources.iter().map(|x| x.name.as_str()).collect();
    assert_eq!(names, ["web-staging"]);
    let hints: Vec<&str> = listed.requestable.iter().map(|x| x.name.as_str()).collect();
    assert_eq!(hints, ["orders-prod", "web-prod"]);

    // A reason without a ticket is refused when the role wants one.
    let err = r
        .request(&r.dev, "web-prod", "just looking")
        .await
        .expect_err("ticket");
    assert_eq!(err.code(), Code::InvalidArgument);
    assert!(err.message().contains("ticket"), "{}", err.message());

    let asked = r
        .request(&r.dev, "web-prod", "INC-123 disk full")
        .await
        .expect("ask");
    assert_eq!(asked.status, "pending");
    assert_eq!(asked.role, "prod-ssh");
    assert_eq!(asked.duration_seconds, 1800);
    assert!(!asked.can_decide, "the requester can't decide");
    assert_eq!(
        r.listed(&r.dev).await,
        [("web-staging".to_owned(), 0)],
        "no access yet"
    );

    // Asking twice doesn't double the queue.
    let again = r
        .request(&r.dev, "web-prod", "INC-123 disk full")
        .await
        .expect_err("dup");
    assert_eq!(again.code(), Code::AlreadyExists);

    // The approver sees it, with what the requester has been doing.
    let queue = r
        .access()
        .list_access_requests(forwarded(
            ListAccessRequestsRequest {
                scope: "approvable".into(),
                status: String::new(),
                limit: 0,
            },
            Some(&r.lead),
        ))
        .await
        .expect("queue")
        .into_inner()
        .requests;
    assert_eq!(queue.len(), 1);
    assert!(queue[0].can_decide);
    assert_eq!(queue[0].reason, "INC-123 disk full");

    let done = r.decide(&r.lead, &asked.id, true).await.expect("approve");
    assert_eq!(done.status, "approved");
    assert!(done.grant_expires_at_unix > 0);

    // Now `ls` shows it, until the deadline.
    let listed = r.listed(&r.dev).await;
    let prod = listed
        .iter()
        .find(|(n, _)| n == "web-prod")
        .expect("granted");
    assert_eq!(prod.1, done.grant_expires_at_unix);

    // The signed snapshot carries the grant for proxies and workers.
    let signed = PolicySyncClient::new(r.ch.clone())
        .get_policy_snapshot(GetPolicySnapshotRequest {})
        .await
        .expect("snapshot")
        .into_inner();
    let snapshot =
        limen_session::snapshot::verify_snapshot(&signed, r.h.state.cas.internal.cert_der())
            .expect("verify");
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let eff =
        snapshot
            .restrictions
            .effective_roles(DEVELOPER, &["dev".to_owned()], "web-prod", now);
    assert_eq!(eff.roles, ["dev", "prod-ssh"]);
    assert_eq!(eff.request_ids, std::slice::from_ref(&asked.id));
    // ...for that resource only, and for that user only.
    assert_eq!(
        snapshot
            .restrictions
            .effective_roles(DEVELOPER, &["dev".to_owned()], "orders-prod", now)
            .roles,
        ["dev"]
    );
    assert_eq!(
        snapshot
            .restrictions
            .effective_roles(ONCALL, &[], "web-prod", now)
            .roles,
        Vec::<String>::new()
    );
    // The control plane's own check agrees, and decides the policy question.
    let own = access::effective_roles_now(&r.h.state, DEVELOPER, &["dev".to_owned()], "web-prod")
        .await
        .expect("effective");
    let decision =
        r.h.state
            .policy
            .current()
            .policy
            .evaluate(&limen_policy::AccessRequest {
                roles: &own.roles,
                resource: "web-prod",
                principal: limen_policy::Principal::SshLogin("ubuntu".into()),
            });
    assert!(decision.is_allowed());

    // Expiry: the deadline passes and everything lets go on its own.
    sqlx::query("UPDATE access_grants SET expires_at = now() - interval '1 second'")
        .execute(&r.h.state.db)
        .await
        .expect("age the grant");
    assert_eq!(r.listed(&r.dev).await, [("web-staging".to_owned(), 0)]);
    let signed = PolicySyncClient::new(r.ch.clone())
        .get_policy_snapshot(GetPolicySnapshotRequest {})
        .await
        .expect("snapshot")
        .into_inner();
    let snapshot =
        limen_session::snapshot::verify_snapshot(&signed, r.h.state.cas.internal.cert_der())
            .expect("verify");
    assert!(
        snapshot.restrictions.grants.is_empty(),
        "expired grants leave the snapshot"
    );
    access::expire(&r.h.state).await.expect("expire");
    access::expire(&r.h.state).await.expect("expire again");

    let kinds = r.kinds().await;
    for want in [
        EventKind::AccessRequest,
        EventKind::AccessApprove,
        EventKind::AccessGrant,
    ] {
        assert!(kinds.contains(&want), "{want:?} in {kinds:?}");
    }
    assert_eq!(
        kinds
            .iter()
            .filter(|k| **k == EventKind::AccessExpire)
            .count(),
        1,
        "the expiry is written once, however often the job runs"
    );
}

#[tokio::test]
async fn nobody_decides_their_own_request_and_only_approvers_decide() {
    let Some(r) = Rig::start().await else { return };
    let asked = r.request(&r.dev, "web-prod", "INC-1 x").await.expect("ask");
    let own = r.decide(&r.dev, &asked.id, true).await.expect_err("own");
    assert_eq!(own.code(), Code::PermissionDenied);
    // A person in the `who` group who is not an approver can't either.
    let (_, other) =
        r.h.login(CONTRACTOR, &["developers"])
            .await
            .expect("contractor");
    let nope = r
        .decide(&other, &asked.id, true)
        .await
        .expect_err("not an approver");
    assert_eq!(nope.code(), Code::PermissionDenied);
    // Even an admin isn't an approver unless policy says so.
    let admin = r
        .decide(&r.admin, &asked.id, true)
        .await
        .expect_err("admin");
    assert_eq!(admin.code(), Code::PermissionDenied);

    // And the database refuses it whatever the code does.
    let id: Uuid = asked.id.parse().expect("uuid");
    let err = sqlx::query(
        "INSERT INTO access_approvals (request_id, approver, decision) VALUES ($1, $2, 'approve')",
    )
    .bind(id)
    .bind(DEVELOPER.to_uppercase())
    .execute(&r.h.state.db)
    .await
    .expect_err("the trigger refuses a self-approval");
    assert!(
        err.to_string()
            .contains("cannot be decided by its requester"),
        "{err}"
    );

    // Nothing was granted.
    assert_eq!(r.listed(&r.dev).await, [("web-staging".to_owned(), 0)]);
}

#[tokio::test]
async fn a_role_that_needs_two_approvers_gets_two_different_ones() {
    let Some(r) = Rig::start().await else { return };
    let (_, lead2) =
        r.h.login(CONTRACTOR, &["sre-leads"])
            .await
            .expect("second lead");
    let asked = r
        .request(&r.dev, "orders-prod", "")
        .await
        .expect("no reason needed");
    assert_eq!(asked.approvals_required, 2);
    let first = r.decide(&r.lead, &asked.id, true).await.expect("first");
    assert_eq!(first.status, "pending", "one approval isn't enough");
    // The same person can't count twice.
    let twice = r.decide(&r.lead, &asked.id, true).await.expect_err("twice");
    assert_eq!(twice.code(), Code::AlreadyExists);
    assert_eq!(r.listed(&r.dev).await.len(), 1, "still nothing granted");
    let second = r.decide(&lead2, &asked.id, true).await.expect("second");
    assert_eq!(second.status, "approved");
    assert_eq!(second.approvals.len(), 2);
    assert!(
        r.listed(&r.dev)
            .await
            .iter()
            .any(|(n, _)| n == "orders-prod")
    );
}

#[tokio::test]
async fn a_denial_ends_it_and_a_requester_can_withdraw() {
    let Some(r) = Rig::start().await else { return };
    let asked = r.request(&r.dev, "web-prod", "INC-9 x").await.expect("ask");
    let denied = r.decide(&r.lead, &asked.id, false).await.expect("deny");
    assert_eq!(denied.status, "denied");
    let late = r
        .decide(&r.lead, &asked.id, true)
        .await
        .expect_err("already denied");
    assert_eq!(late.code(), Code::FailedPrecondition);
    assert_eq!(r.listed(&r.dev).await.len(), 1);

    let again = r
        .request(&r.dev, "web-prod", "INC-10 y")
        .await
        .expect("ask again");
    let withdrawn = r
        .access()
        .cancel_access_request(forwarded(
            CancelAccessRequestRequest {
                id: again.id.clone(),
            },
            Some(&r.dev),
        ))
        .await
        .expect("cancel")
        .into_inner();
    assert_eq!(withdrawn.status, "cancelled");
    // Somebody else's request reads as missing.
    let third = r
        .request(&r.dev, "web-prod", "INC-11 z")
        .await
        .expect("third");
    let err = r
        .access()
        .cancel_access_request(forwarded(
            CancelAccessRequestRequest { id: third.id },
            Some(&r.lead),
        ))
        .await
        .expect_err("not theirs");
    assert_eq!(err.code(), Code::NotFound);
}

#[tokio::test]
async fn what_can_be_asked_for_does_not_reveal_other_resources() {
    let Some(r) = Rig::start().await else { return };
    let missing = r
        .request(&r.dev, "no-such-thing", "INC-1 x")
        .await
        .expect_err("missing");
    let hidden = r
        .request(&r.lead, "web-prod", "INC-1 x")
        .await
        .expect_err("not requestable by a lead");
    // Same words for a resource that doesn't exist and one nothing reaches.
    assert_eq!(missing.code(), hidden.code());
    assert_eq!(
        missing.message().replace("no-such-thing", "X"),
        hidden.message().replace("web-prod", "X")
    );
    // A bot cannot ask.
    let err = access::request_access(
        &r.h.state,
        &access::Who {
            username: "bot:ci",
            is_admin: false,
            is_auditor: false,
            via: "api",
        },
        access::NewAccess {
            resource: "web-prod".into(),
            reason: "INC-1".into(),
            ..Default::default()
        },
    )
    .await
    .expect_err("bots can't ask");
    assert_eq!(err.code(), Code::PermissionDenied);
}

#[tokio::test]
async fn a_locked_user_can_neither_ask_nor_use_a_grant() {
    let Some(r) = Rig::start().await else { return };
    let asked = r.request(&r.dev, "web-prod", "INC-1 x").await.expect("ask");
    r.decide(&r.lead, &asked.id, true).await.expect("approve");
    limen_control_plane::services::ops::lock_user(
        &r.h.state,
        limen_control_plane::services::ops::Actor {
            username: ADMIN,
            via: "api",
        },
        DEVELOPER,
        "test",
    )
    .await
    .expect("lock");
    let err = r
        .request(&r.dev, "orders-prod", "")
        .await
        .expect_err("locked");
    assert_eq!(err.code(), Code::PermissionDenied);
    // The lock is in the snapshot next to the grant, and wins over it.
    let signed = PolicySyncClient::new(r.ch.clone())
        .get_policy_snapshot(GetPolicySnapshotRequest {})
        .await
        .expect("snapshot")
        .into_inner();
    let snapshot =
        limen_session::snapshot::verify_snapshot(&signed, r.h.state.cas.internal.cert_der())
            .expect("verify");
    assert_eq!(
        snapshot.restrictions.blocks(DEVELOPER, "any-login", ""),
        Some("user locked")
    );
    assert!(!snapshot.restrictions.grants.is_empty());
}

#[tokio::test]
async fn break_glass_is_granted_at_once_with_a_reason_and_shouts() {
    let Some(r) = Rig::start().await else { return };
    let err = r
        .access()
        .request_access(forwarded(
            RequestAccessRequest {
                resource: "web-prod".into(),
                role: String::new(),
                duration_seconds: 600,
                reason: String::new(),
                break_glass: true,
            },
            Some(&r.dev),
        ))
        .await
        .expect_err("a reason is mandatory");
    assert_eq!(err.code(), Code::InvalidArgument);
    // More than an hour is refused.
    let err = r
        .access()
        .request_access(forwarded(
            RequestAccessRequest {
                resource: "web-prod".into(),
                role: String::new(),
                duration_seconds: 7200,
                reason: "prod is down".into(),
                break_glass: true,
            },
            Some(&r.dev),
        ))
        .await
        .expect_err("too long");
    assert!(err.message().contains("at most 1h"), "{}", err.message());

    let info = r
        .access()
        .request_access(forwarded(
            RequestAccessRequest {
                resource: "web-prod".into(),
                role: String::new(),
                duration_seconds: 600,
                reason: "prod is down".into(),
                break_glass: true,
            },
            Some(&r.dev),
        ))
        .await
        .expect("break-glass")
        .into_inner();
    assert_eq!(info.status, "approved");
    assert!(info.break_glass);
    assert!(r.listed(&r.dev).await.iter().any(|(n, _)| n == "web-prod"));
    let kinds = r.kinds().await;
    assert!(kinds.contains(&EventKind::AccessBreakGlass), "{kinds:?}");
    assert!(kinds.contains(&EventKind::AccessGrant));
    // Normal requests can't pick a break-glass role by accident.
    let normal = r
        .request(&r.dev, "web-prod", "INC-1 x")
        .await
        .expect("normal");
    assert_eq!(normal.role, "prod-ssh");
}

#[tokio::test]
async fn revoking_a_grant_ends_the_sessions_it_allowed() {
    let Some(r) = Rig::start().await else { return };
    let asked = r.request(&r.dev, "web-prod", "INC-1 x").await.expect("ask");
    r.decide(&r.lead, &asked.id, true).await.expect("approve");

    // A session that started under the grant, as the audit stream reports it.
    let session = Uuid::now_v7();
    let mut start = limen_audit::Event::new(
        EventKind::SessionStart,
        limen_audit::Producer {
            component: "proxy".into(),
            instance_id: "p".into(),
            seq: 0,
        },
        serde_json::json!({
            "kind": "ssh", "resource": "web-prod", "login": "ubuntu", "request_ids": [asked.id],
        }),
    );
    start.user = Some(DEVELOPER.into());
    start.session_id = Some(session);
    limen_control_plane::console::store::project_events(&r.h.state.db, &[start])
        .await
        .expect("project");

    // Only an admin may revoke.
    let err = r
        .access()
        .revoke_access_grant(forwarded(
            RevokeAccessGrantRequest {
                request_id: asked.id.clone(),
                reason: "x".into(),
            },
            Some(&r.lead),
        ))
        .await
        .expect_err("not an admin");
    assert_eq!(err.code(), Code::PermissionDenied);

    let grants = r
        .access()
        .list_access_grants(forwarded(
            ListAccessGrantsRequest {
                include_ended: false,
            },
            Some(&r.admin),
        ))
        .await
        .expect("grants")
        .into_inner()
        .grants;
    assert_eq!(grants.len(), 1);
    let revoked = r
        .access()
        .revoke_access_grant(forwarded(
            RevokeAccessGrantRequest {
                request_id: asked.id.clone(),
                reason: "mistake".into(),
            },
            Some(&r.admin),
        ))
        .await
        .expect("revoke")
        .into_inner();
    assert!(revoked.revoked);
    assert_eq!(revoked.sessions_ended, 1);

    // The kill reaches proxies in the snapshot; the grant is gone from it.
    let signed = PolicySyncClient::new(r.ch.clone())
        .get_policy_snapshot(GetPolicySnapshotRequest {})
        .await
        .expect("snapshot")
        .into_inner();
    let snapshot =
        limen_session::snapshot::verify_snapshot(&signed, r.h.state.cas.internal.cert_der())
            .expect("verify");
    assert!(
        snapshot
            .restrictions
            .killed_sessions
            .contains(&session.to_string())
    );
    assert!(snapshot.restrictions.grants.is_empty());
    assert!(
        snapshot
            .restrictions
            .grant_ended(std::slice::from_ref(&asked.id), 0)
    );
    assert!(r.listed(&r.dev).await.iter().all(|(n, _)| n != "web-prod"));
    assert!(r.kinds().await.contains(&EventKind::AccessRevoke));
    // Revoking again says it had ended.
    let again = r
        .access()
        .revoke_access_grant(forwarded(
            RevokeAccessGrantRequest {
                request_id: asked.id,
                reason: "again".into(),
            },
            Some(&r.admin),
        ))
        .await
        .expect("again")
        .into_inner();
    assert!(!again.revoked);
}

#[tokio::test]
async fn people_who_can_only_ask_still_sign_in() {
    let Some(r) = Rig::start().await else { return };
    // `interns` have no role mapped but may ask for one.
    r.h.set_policy(&[(
        "policy.yaml",
        &format!(
            "{POLICY}\n---\nkind: role\nversion: v1\nmetadata: {{ name: intern-ssh }}\nspec:\n  allow:\n    - resources: {{ kind: [ssh], labels: {{ env: [staging] }} }}\n      ssh: {{ logins: [ubuntu] }}\n  request: {{ who: [interns], approvers: [sre-leads] }}\n"
        ),
    )]);
    let (resp, _) =
        r.h.login("intern@example.com", &["interns"])
            .await
            .expect("signs in");
    assert!(resp.roles.is_empty());
    // Someone with nothing to ask for is still refused.
    let refused =
        r.h.login("stranger@example.com", &["nobody"])
            .await
            .expect_err("refused");
    assert_eq!(refused.code(), Code::PermissionDenied);
}

#[tokio::test]
async fn a_pending_request_lapses_and_is_audited() {
    let Some(r) = Rig::start().await else { return };
    let asked = r.request(&r.dev, "web-prod", "INC-1 x").await.expect("ask");
    sqlx::query("UPDATE access_requests SET expires_at = now() - interval '1 minute'")
        .execute(&r.h.state.db)
        .await
        .expect("age it");
    let late = r
        .decide(&r.lead, &asked.id, true)
        .await
        .expect_err("lapsed");
    assert_eq!(late.code(), Code::FailedPrecondition);
    access::expire(&r.h.state).await.expect("expire");
    let mine = r
        .access()
        .list_access_requests(forwarded(
            ListAccessRequestsRequest {
                scope: "mine".into(),
                status: String::new(),
                limit: 0,
            },
            Some(&r.dev),
        ))
        .await
        .expect("mine")
        .into_inner()
        .requests;
    assert_eq!(mine[0].status, "expired");
    assert!(r.kinds().await.contains(&EventKind::AccessExpire));
}

#[tokio::test]
async fn auditors_read_the_queue_but_cannot_change_it() {
    let Some(r) = Rig::start().await else { return };
    let (resp, auditor) = r.h.login(AUDITOR, &["auditors"]).await.expect("auditor");
    assert_eq!(resp.roles, ["limen:auditor"]);
    let asked = r.request(&r.dev, "web-prod", "INC-1 x").await.expect("ask");
    let list = |who: &CertificateDer<'static>, scope: &str| {
        let mut access = r.access();
        let req = forwarded(
            ListAccessRequestsRequest {
                scope: scope.into(),
                status: String::new(),
                limit: 0,
            },
            Some(who),
        );
        async move {
            access
                .list_access_requests(req)
                .await
                .map(|r| r.into_inner().requests)
        }
    };
    // They can read every request, with the context an approver sees.
    assert_eq!(list(&auditor, "all").await.expect("all").len(), 1);
    // But the developer can't, and an auditor can't decide, revoke, or lock.
    let err = list(&r.dev, "all").await.expect_err("developers can't");
    assert_eq!(err.code(), Code::PermissionDenied);
    let err = r
        .decide(&auditor, &asked.id, true)
        .await
        .expect_err("not an approver");
    assert_eq!(err.code(), Code::PermissionDenied);
    r.decide(&r.lead, &asked.id, true).await.expect("approve");
    let grants = r
        .access()
        .list_access_grants(forwarded(
            ListAccessGrantsRequest {
                include_ended: false,
            },
            Some(&auditor),
        ))
        .await
        .expect("an auditor reads grants")
        .into_inner()
        .grants;
    assert_eq!(grants.len(), 1);
    let err = r
        .access()
        .revoke_access_grant(forwarded(
            RevokeAccessGrantRequest {
                request_id: asked.id,
                reason: "x".into(),
            },
            Some(&auditor),
        ))
        .await
        .expect_err("revoking is for admins");
    assert_eq!(err.code(), Code::PermissionDenied);
    // The admin sees everything too.
    assert_eq!(list(&r.admin, "all").await.expect("admin").len(), 1);
}

#[tokio::test]
async fn explain_tells_users_their_own_story_and_admins_the_trace() {
    let Some(r) = Rig::start().await else { return };
    let ask = |who: &CertificateDer<'static>, resource: &str, user: &str| {
        let mut access = r.access();
        let req = forwarded(
            ExplainRequest {
                resource: resource.into(),
                principal: "login=ubuntu".into(),
                database: String::new(),
                user: user.into(),
            },
            Some(who),
        );
        async move { access.explain(req).await.map(tonic::Response::into_inner) }
    };
    let hidden = ask(&r.lead, "web-prod", "").await.expect("hidden").lines;
    let missing = ask(&r.lead, "ghost", "").await.expect("missing").lines;
    assert_eq!(
        hidden
            .iter()
            .map(|l| l.replace("web-prod", "X"))
            .collect::<Vec<_>>(),
        missing
            .iter()
            .map(|l| l.replace("ghost", "X"))
            .collect::<Vec<_>>(),
        "hidden reads like missing"
    );
    let dev = ask(&r.dev, "web-prod", "")
        .await
        .expect("dev")
        .lines
        .join("\n");
    assert!(dev.contains("you can ask for it"), "{dev}");
    // Only admins may ask about someone else, and get the trace.
    let err = ask(&r.dev, "web-prod", ONCALL)
        .await
        .expect_err("not admin");
    assert_eq!(err.code(), Code::PermissionDenied);
    let trace = ask(&r.admin, "web-prod", DEVELOPER).await.expect("trace");
    assert!(trace.full_trace);
    let text = trace.lines.join("\n");
    assert!(
        text.contains("needs env in [staging], the resource has env=prod"),
        "{text}"
    );
    assert!(text.contains("requestable"), "{text}");
}

/// A server that records every POST it gets and says 200.
async fn capture() -> (
    String,
    std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let seen: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>> = Arc::default();
    let sink = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let sink = Arc::clone(&sink);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let n = sock.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf).to_string();
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        let len = head
                            .lines()
                            .find_map(|l| {
                                l.to_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        if body.len() >= len {
                            sink.lock()
                                .expect("lock")
                                .push((head.to_lowercase(), body.to_owned()));
                            let _ = sock
                                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                                .await;
                            return;
                        }
                    }
                }
            });
        }
    });
    (format!("http://{addr}"), seen)
}

use std::sync::Arc;

#[tokio::test]
async fn notifiers_link_to_the_console_and_never_carry_the_decision() {
    let (hook, hooked) = capture().await;
    let (slack, slacked) = capture().await;
    let Some(r) = Rig::start_with(&[
        format!("--notify-webhook-url={hook}/hook"),
        "--notify-webhook-secret=s3cr3t".to_owned(),
        format!("--break-glass-slack-url={slack}/services/T/B/x"),
    ])
    .await
    else {
        return;
    };
    let asked = r
        .request(&r.dev, "web-prod", "INC-1 secret-reason")
        .await
        .expect("ask");
    common::wait_for("the webhook", || !hooked.lock().expect("lock").is_empty()).await;
    let (head, body) = hooked.lock().expect("lock")[0].clone();
    let json: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(json["event"], "access.requested");
    assert_eq!(json["request_id"], asked.id);
    // Names stay inside Limen unless asked for.
    for leaked in ["web-prod", "prod-ssh", DEVELOPER, "secret-reason"] {
        assert!(!body.contains(leaked), "{leaked} leaked: {body}");
    }
    // Signed over the timestamp and the body.
    let ts = head
        .lines()
        .find_map(|l| l.strip_prefix("x-limen-timestamp: "))
        .expect("timestamp header");
    let sig = head
        .lines()
        .find_map(|l| l.strip_prefix("x-limen-signature: sha256="))
        .expect("signature header");
    assert_eq!(sig, access::notify::signature(b"s3cr3t", ts, &body));
    // No decision rides in it: there is nothing to click.
    assert!(!body.contains("approve"), "{body}");
    assert!(slacked.lock().expect("lock").is_empty(), "break-glass only");

    // Break-glass also goes to its own channel, flagged critical.
    r.access()
        .request_access(forwarded(
            RequestAccessRequest {
                resource: "web-prod".into(),
                role: String::new(),
                duration_seconds: 600,
                reason: "prod is down".into(),
                break_glass: true,
            },
            Some(&r.dev),
        ))
        .await
        .expect("break-glass");
    common::wait_for("slack", || !slacked.lock().expect("lock").is_empty()).await;
    let text = slacked.lock().expect("lock")[0].1.clone();
    assert!(text.contains("BREAK-GLASS"), "{text}");
    assert!(
        !text.contains("prod is down"),
        "reasons stay inside Limen: {text}"
    );
}
