//! The management API (ADR-0042) end to end: a bot writer logs in with a
//! CI-shaped token and registers a resource from a profile, the way the
//! Terraform provider does. Real PostgreSQL, mock issuer. Set
//! `LIMEN_TEST_DATABASE_URL` to run them.
#![allow(clippy::large_futures, clippy::too_many_lines, clippy::assert_is_empty)]

mod common;

use std::collections::HashMap;

use common::{Harness, forwarded};
use limen_audit::EventKind;
use limen_proto::manage::v1 as pb;
use limen_proto::manage::v1::management_service_client::ManagementServiceClient;
use limen_proto::v1::admin_client::AdminClient;
use limen_proto::v1::{ApplyPolicyRequest, PolicySource};
use limen_testkit::idp::WorkloadToken;
use limen_testkit::users::{ADMIN, DEVELOPER, ONCALL};
use rustls_pki_types::CertificateDer;
use tonic::Code;
use tonic_types::StatusExt;

const STACK: &str = include_str!("../../../examples/policy/stacks/delegation/policy.yaml");
const ENDPOINT: &str = "orders.c9xk2p.eu-west-1.rds.amazonaws.com:5432";

struct Fixture {
    h: Harness,
    /// One proxy for every call: enrollment is rate limited per address.
    proxy: limen_tunnel::tls::Identity,
    admin: CertificateDer<'static>,
    bot: CertificateDer<'static>,
    /// The writer grant's `kinds`, as YAML.
    kinds: &'static str,
}

/// The example stack, with the mock issuer, a quota of two, and `kinds`.
fn stack(issuer: &str, kinds: &str) -> String {
    STACK
        .replace("kinds: [resource]", &format!("kinds: {kinds}"))
        .replace(
            "    method: github_actions\n",
            &format!("    method: github_actions\n    issuer: {issuer}\n"),
        )
        // Two for the quota test; room for roles, mappings, and tests.
        .replace(
            "max_documents: 50",
            if kinds == "[resource]" {
                "max_documents: 2"
            } else {
                "max_documents: 10"
            },
        )
        + "---\nkind: role_mapping\nversion: v1\nmetadata: { name: people }\nspec:\n  - { idp_group: developers, roles: [payments-ci] }\n  - { idp_group: security, roles: [payments-ci] }\n"
}

async fn start() -> Option<Fixture> {
    start_with(&[]).await
}

async fn start_with(extra: &[&str]) -> Option<Fixture> {
    start_writing(extra, "[resource]").await
}

/// A fixture whose bot writer may write `kinds`.
async fn start_writing(extra: &[&str], kinds: &'static str) -> Option<Fixture> {
    let args: Vec<String> = std::iter::once("--bot-allow-insecure-issuers")
        .chain(extra.iter().copied())
        .map(str::to_owned)
        .collect();
    let h = Harness::start_with(&args).await?;
    let (_, admin) = h.login(ADMIN, &["admins"]).await.expect("admin");
    let (_, proxy) = h.enroll_proxy().await;
    let f = Fixture {
        bot: CertificateDer::from(Vec::new()),
        h,
        proxy,
        admin,
        kinds,
    };
    f.apply_files().await;
    let token = f.h.idp.workload_token(&WorkloadToken::github(
        "acme/payments-infra",
        "refs/heads/main",
        Some("staging"),
    ));
    let (resp, bot) =
        f.h.bot_login("github_actions", token, "")
            .await
            .expect("bot login");
    assert_eq!(resp.username, "bot:payments-terraform");
    Some(Fixture { bot, ..f })
}

impl Fixture {
    fn proxy(&self) -> limen_tunnel::connect::TracedChannel {
        self.h.channel(Some(self.proxy.clone()))
    }

    /// An admin applies the stack from files, as CI does.
    async fn apply_files(&self) -> limen_proto::v1::ApplyPolicyResponse {
        AdminClient::new(self.proxy())
            .apply_policy(forwarded(
                ApplyPolicyRequest {
                    source: String::new(),
                    sources: vec![PolicySource {
                        name: "delegation.yaml".into(),
                        content: stack(&self.h.idp.issuer, self.kinds),
                    }],
                    dry_run: false,
                    source_ref: String::new(),
                    require_tests: false,
                },
                Some(&self.admin),
            ))
            .await
            .expect("apply")
            .into_inner()
    }

    fn api(&self) -> ManagementServiceClient<limen_tunnel::connect::TracedChannel> {
        ManagementServiceClient::new(self.proxy())
    }

    async fn create(
        &self,
        name: &str,
        spec: &str,
        labels: &[(&str, &str)],
        options: pb::WriteOptions,
    ) -> Result<pb::WriteResult, tonic::Status> {
        self.create_in("payments", name, "payments-postgres", spec, labels, options)
            .await
    }

    async fn create_in(
        &self,
        namespace: &str,
        name: &str,
        profile: &str,
        spec: &str,
        labels: &[(&str, &str)],
        options: pb::WriteOptions,
    ) -> Result<pb::WriteResult, tonic::Status> {
        let request = pb::CreateDocumentRequest {
            document: Some(pb::Document {
                kind: pb::DocumentKind::Resource.into(),
                name: name.into(),
                profile: profile.into(),
                spec_json: spec.into(),
                labels: labels
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect::<HashMap<_, _>>(),
                ..pb::Document::default()
            }),
            ownership: Some(pb::Ownership {
                source: "terraform/test".into(),
                namespace: namespace.into(),
                ..pb::Ownership::default()
            }),
            options: Some(options),
        };
        self.api()
            .create_document(forwarded(request, Some(&self.bot)))
            .await
            .map(|r| r.into_inner().result.expect("result"))
    }
}

impl Fixture {
    /// A person creates a whole resource (no profile) in `default`.
    async fn person_creates(
        &self,
        who: &CertificateDer<'static>,
        name: &str,
        team: &str,
        options: pb::WriteOptions,
    ) -> Result<pb::WriteResult, tonic::Status> {
        let request = pb::CreateDocumentRequest {
            document: Some(pb::Document {
                kind: pb::DocumentKind::Resource.into(),
                name: name.into(),
                spec_json: r#"{"postgres":{"endpoint":"ledger.internal:5432","default_database":"ledger"}}"#.into(),
                labels: HashMap::from([
                    ("team".to_owned(), team.to_owned()),
                    ("env".to_owned(), "staging".to_owned()),
                ]),
                ..pb::Document::default()
            }),
            ownership: Some(pb::Ownership {
                source: "console-test".into(),
                ..pb::Ownership::default()
            }),
            options: Some(options),
        };
        self.api()
            .create_document(forwarded(request, Some(who)))
            .await
            .map(|r| r.into_inner().result.expect("result"))
    }

    async fn approve(
        &self,
        who: &CertificateDer<'static>,
        id: &str,
    ) -> Result<pb::PolicyChange, tonic::Status> {
        self.api()
            .approve_change(forwarded(
                pb::ApproveChangeRequest {
                    id: id.into(),
                    note: "looked at it".into(),
                },
                Some(who),
            ))
            .await
            .map(|r| r.into_inner().change.expect("change"))
    }

    async fn exists(&self, name: &str) -> bool {
        self.api()
            .get_document(forwarded(
                pb::GetDocumentRequest {
                    kind: pb::DocumentKind::Resource.into(),
                    name: name.into(),
                    policy_version: 0,
                },
                Some(&self.admin),
            ))
            .await
            .is_ok()
    }
}

impl Fixture {
    /// Create any document as `who`, from `source`.
    async fn put(
        &self,
        who: &CertificateDer<'static>,
        kind: pb::DocumentKind,
        name: &str,
        spec: &str,
        options: pb::WriteOptions,
    ) -> Result<pb::WriteResult, tonic::Status> {
        let request = pb::CreateDocumentRequest {
            document: Some(pb::Document {
                kind: kind.into(),
                name: name.into(),
                spec_json: spec.into(),
                ..pb::Document::default()
            }),
            ownership: Some(pb::Ownership {
                source: "terraform/test".into(),
                ..pb::Ownership::default()
            }),
            options: Some(options),
        };
        self.api()
            .create_document(forwarded(request, Some(who)))
            .await
            .map(|r| r.into_inner().result.expect("result"))
    }

    async fn get(&self, kind: pb::DocumentKind, name: &str) -> Option<pb::Document> {
        self.api()
            .get_document(forwarded(
                pb::GetDocumentRequest {
                    kind: kind.into(),
                    name: name.into(),
                    policy_version: 0,
                },
                Some(&self.admin),
            ))
            .await
            .ok()
            .and_then(|r| r.into_inner().document)
    }
}

fn reason(status: &tonic::Status) -> String {
    status
        .get_details_error_info()
        .map(|i| i.reason)
        .unwrap_or_default()
}

fn endpoint(endpoint: &str) -> String {
    format!(r#"{{"postgres":{{"endpoint":"{endpoint}"}}}}"#)
}

fn rule(status: &tonic::Status) -> (String, String) {
    let info = status.get_details_error_info().expect("error info");
    (
        info.reason.clone(),
        info.metadata.get("rule").cloned().unwrap_or_default(),
    )
}

#[tokio::test]
async fn a_bot_writer_registers_a_resource_from_its_profile() {
    let Some(f) = start().await else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL");
        return;
    };
    let mut api = f.api();

    let me = api
        .describe_caller(forwarded(pb::DescribeCallerRequest {}, Some(&f.bot)))
        .await
        .expect("describe")
        .into_inner();
    assert_eq!(me.principal, "bot:payments-terraform");
    assert!(!me.admin);
    let grant = me.grant.expect("grant");
    assert_eq!(grant.namespace, "payments");
    assert_eq!(grant.profiles, ["payments-postgres"]);

    // Create, retry with the same request_id: one write.
    let options = pb::WriteOptions {
        request_id: "8a1f4c2e-0b7d-4e6a-9c3b-5d2e1f0a9b8c".into(),
        source_ref: "https://ci.example/run/1".into(),
        ..pb::WriteOptions::default()
    };
    let spec = endpoint(ENDPOINT);
    let created = f
        .create(
            "payments-orders-db",
            &spec,
            &[("env", "staging")],
            options.clone(),
        )
        .await
        .expect("create");
    assert_eq!(created.outcome, i32::from(pb::WriteOutcome::Applied));
    let doc = &created.documents[0];
    assert_eq!(
        doc.spec_json, spec,
        "the caller's half round-trips unchanged"
    );
    assert_eq!(doc.labels.get("env").map(String::as_str), Some("staging"));
    assert_eq!(
        doc.effective_labels.get("team").map(String::as_str),
        Some("payments")
    );
    assert!(
        doc.effective_spec_json.contains("\"iam_auth\":true"),
        "{}",
        doc.effective_spec_json
    );
    assert!(doc.effective_spec_json.contains("delegated"));
    assert!(!doc.etag.is_empty());
    let replay = f
        .create(
            "payments-orders-db",
            &spec,
            &[("env", "staging")],
            options.clone(),
        )
        .await
        .expect("replay");
    assert_eq!(replay, created, "a retry returns the first result");
    let reused = f
        .create("payments-other-db", &spec, &[], options)
        .await
        .expect_err("same id, different body");
    assert_eq!(rule(&reused).0, "REQUEST_ID_REUSED");
    let enforced = f.h.state.policy.base();
    let resource = enforced
        .policy
        .resource("payments-orders-db")
        .expect("enforced");
    assert!(resource.spec.postgres.as_ref().expect("pg").iam_auth);

    // A file apply leaves the writer's resource alone.
    f.apply_files().await;
    assert!(
        f.h.state
            .policy
            .base()
            .policy
            .resource("payments-orders-db")
            .is_some()
    );

    // Reads: its namespace and its profile, nothing else.
    let listed = api
        .list_documents(forwarded(
            pb::ListDocumentsRequest {
                kind: pb::DocumentKind::Resource.into(),
                ..pb::ListDocumentsRequest::default()
            },
            Some(&f.bot),
        ))
        .await
        .expect("list")
        .into_inner();
    assert_eq!(listed.documents.len(), 1);
    let hidden = api
        .get_document(forwarded(
            pb::GetDocumentRequest {
                kind: pb::DocumentKind::Role.into(),
                name: "payments-ci".into(),
                policy_version: 0,
            },
            Some(&f.bot),
        ))
        .await
        .expect_err("a role in default isn't the writer's");
    assert_eq!(hidden.code(), Code::NotFound);
    api.get_document(forwarded(
        pb::GetDocumentRequest {
            kind: pb::DocumentKind::ResourceProfile.into(),
            name: "payments-postgres".into(),
            policy_version: 0,
        },
        Some(&f.bot),
    ))
    .await
    .expect("its own profile is readable");

    // Update: a stale etag is refused, the right one works.
    let update = |etag: &str, db: &str| pb::UpdateDocumentRequest {
        document: Some(pb::Document {
            kind: pb::DocumentKind::Resource.into(),
            name: "payments-orders-db".into(),
            profile: "payments-postgres".into(),
            spec_json: format!(
                r#"{{"postgres":{{"default_database":"{db}","endpoint":"{ENDPOINT}"}}}}"#
            ),
            labels: HashMap::from([("env".to_owned(), "staging".to_owned())]),
            ..pb::Document::default()
        }),
        etag: etag.into(),
        options: None,
        ownership: Some(pb::Ownership {
            source: "terraform/test".into(),
            namespace: "payments".into(),
            ..pb::Ownership::default()
        }),
    };
    let stale = api
        .update_document(forwarded(update("stale", "orders"), Some(&f.bot)))
        .await
        .expect_err("stale");
    assert_eq!(rule(&stale).0, "ETAG_MISMATCH");
    let updated = api
        .update_document(forwarded(update(&doc.etag, "orders"), Some(&f.bot)))
        .await
        .expect("update")
        .into_inner()
        .result
        .expect("result");
    let new_etag = updated.documents[0].etag.clone();
    assert_ne!(new_etag, doc.etag);

    // A live session on it ends when it's deleted.
    let session = uuid::Uuid::now_v7();
    sqlx::query("INSERT INTO sessions (session_id, username, resource, started_at) VALUES ($1, 'alice', 'payments-orders-db', now())")
        .bind(session)
        .execute(&f.h.state.db)
        .await
        .expect("session");
    let delete = |etag: &str, allow_missing: bool| pb::DeleteDocumentRequest {
        kind: pb::DocumentKind::Resource.into(),
        name: "payments-orders-db".into(),
        etag: etag.into(),
        allow_missing,
        options: None,
        ownership: Some(pb::Ownership {
            source: "terraform/test".into(),
            namespace: "payments".into(),
            ..pb::Ownership::default()
        }),
    };
    let deleted = api
        .delete_document(forwarded(delete(&new_etag, false), Some(&f.bot)))
        .await
        .expect("delete")
        .into_inner()
        .result
        .expect("result");
    assert_eq!(deleted.outcome, i32::from(pb::WriteOutcome::Applied));
    assert!(
        f.h.state
            .policy
            .base()
            .policy
            .resource("payments-orders-db")
            .is_none()
    );
    let killed: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM session_kills WHERE session_id = $1)")
            .bind(session.to_string())
            .fetch_one(&f.h.state.db)
            .await
            .expect("kills");
    assert!(killed, "the session on the deleted resource is ended");
    let again = api
        .delete_document(forwarded(delete("", true), Some(&f.bot)))
        .await
        .expect("allow_missing")
        .into_inner()
        .result
        .expect("result");
    assert_eq!(again.outcome, i32::from(pb::WriteOutcome::Unchanged));
}

#[tokio::test]
async fn a_bot_writer_is_refused_outside_its_grant_and_audited() {
    let Some(f) = start().await else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL");
        return;
    };
    let none = pb::WriteOptions::default;
    let spec = endpoint(ENDPOINT);
    let cases = [
        (f.create_in("other", "payments-db", "payments-postgres", &spec, &[], none()).await, "namespace"),
        (f.create("orders-db", &spec, &[], none()).await, "name_pattern"),
        (f.create_in("payments", "payments-db", "", &spec, &[], none()).await, "profile"),
        (f.create_in("payments", "payments-db", "someone-elses", &spec, &[], none()).await, "profile"),
        (
            f.create(
                "payments-db",
                &format!(r#"{{"postgres":{{"endpoint":"{ENDPOINT}","admin_secret_arn":"arn:aws:secretsmanager:eu-west-1:1:secret:x"}}}}"#),
                &[],
                none(),
            )
            .await,
            "field",
        ),
        (f.create("payments-db", &endpoint("169.254.169.254:5432"), &[], none()).await, "field"),
        (f.create("payments-db", &spec, &[("env", "prod")], none()).await, "label"),
    ];
    for (result, expected) in cases {
        let err = result.expect_err("refused");
        assert_eq!(
            err.code(),
            Code::PermissionDenied,
            "{expected}: {}",
            err.message()
        );
        assert_eq!(
            rule(&err),
            ("OUTSIDE_GRANT".to_owned(), expected.to_owned()),
            "{}",
            err.message()
        );
    }
    // A dry run that's refused leaves a trace too.
    let dry = pb::WriteOptions {
        validate_only: true,
        ..pb::WriteOptions::default()
    };
    f.create("orders-db", &spec, &[], dry)
        .await
        .expect_err("refused dry run");
    let denials =
        f.h.audit_events()
            .await
            .into_iter()
            .filter(|e| e.kind == EventKind::PolicyWriteDenied)
            .count();
    assert_eq!(denials, 8);
    assert!(
        f.h.state.policy.base().policy.resources().count() == 0,
        "nothing was written"
    );

    // A dry run inside the grant changes nothing either.
    let ok = f
        .create(
            "payments-a",
            &spec,
            &[],
            pb::WriteOptions {
                validate_only: true,
                ..pb::WriteOptions::default()
            },
        )
        .await
        .expect("dry run");
    assert_eq!(ok.outcome, i32::from(pb::WriteOutcome::Validated));
    assert!(
        f.h.state
            .policy
            .base()
            .policy
            .resource("payments-a")
            .is_none()
    );

    // The quota (two here) holds.
    f.create("payments-a", &spec, &[], none())
        .await
        .expect("first");
    f.create("payments-b", &spec, &[], none())
        .await
        .expect("second");
    let over = f
        .create("payments-c", &spec, &[], none())
        .await
        .expect_err("third");
    assert_eq!(over.code(), Code::ResourceExhausted);

    // Files can't take over the writer's resource.
    let mut admin_files = AdminClient::new(f.proxy());
    let err = admin_files
        .apply_policy(forwarded(
            ApplyPolicyRequest {
                source: String::new(),
                sources: vec![
                    PolicySource {
                        name: "delegation.yaml".into(),
                        content: stack(&f.h.idp.issuer, f.kinds),
                    },
                    PolicySource {
                        name: "steal.yaml".into(),
                        content: "kind: resource\nversion: v1\nmetadata: { name: payments-a }\nspec:\n  tcp: { address: \"db:5432\" }\n".into(),
                    },
                ],
                dry_run: false,
                source_ref: String::new(),
                require_tests: false,
            },
            Some(&f.admin),
        ))
        .await
        .expect_err("owned by terraform/test");
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert!(
        err.message().contains("terraform/test"),
        "{}",
        err.message()
    );

    // A person without limen:admin can't use the API at all.
    let (_, developer) =
        f.h.login(limen_testkit::users::DEVELOPER, &["developers"])
            .await
            .expect("developer");
    let err = f
        .api()
        .list_documents(forwarded(
            pb::ListDocumentsRequest {
                kind: pb::DocumentKind::Resource.into(),
                ..pb::ListDocumentsRequest::default()
            },
            Some(&developer),
        ))
        .await
        .expect_err("not an admin or a writer");
    assert_eq!(err.code(), Code::PermissionDenied);
}

#[tokio::test]
async fn a_writer_moves_documents_between_its_own_sources_only() {
    let Some(f) = start().await else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL");
        return;
    };
    let created = f
        .create(
            "payments-db",
            &endpoint(ENDPOINT),
            &[],
            pb::WriteOptions::default(),
        )
        .await
        .expect("create");
    let etag = created.documents[0].etag.clone();
    let transfer = |etag: &str, namespace: &str| pb::TransferDocumentRequest {
        kind: pb::DocumentKind::Resource.into(),
        name: "payments-db".into(),
        etag: etag.into(),
        ownership: Some(pb::Ownership {
            source: "terraform/other-state".into(),
            namespace: namespace.into(),
            ..pb::Ownership::default()
        }),
        options: None,
    };
    let err = f
        .api()
        .transfer_document(forwarded(transfer(&etag, "elsewhere"), Some(&f.bot)))
        .await
        .expect_err("out of the namespace");
    assert_eq!(
        rule(&err),
        ("OUTSIDE_GRANT".to_owned(), "namespace".to_owned())
    );
    let moved = f
        .api()
        .transfer_document(forwarded(transfer(&etag, ""), Some(&f.bot)))
        .await
        .expect("transfer")
        .into_inner()
        .result
        .expect("result");
    assert_eq!(moved.outcome, i32::from(pb::WriteOutcome::Applied));
    let owner = moved.documents[0].ownership.clone().expect("owner");
    assert_eq!(owner.source, "terraform/other-state");
    assert_ne!(moved.documents[0].etag, etag, "the etag follows the owner");
    assert!(
        f.h.audit_kinds()
            .await
            .contains(&EventKind::PolicyOwnershipTransfer),
        "the move is audited"
    );
    // A document in default isn't the writer's to move.
    let err = f
        .api()
        .transfer_document(forwarded(
            pb::TransferDocumentRequest {
                kind: pb::DocumentKind::Role.into(),
                name: "payments-ci".into(),
                etag: "x".into(),
                ownership: Some(pb::Ownership {
                    source: "terraform/test".into(),
                    ..pb::Ownership::default()
                }),
                options: None,
            },
            Some(&f.bot),
        ))
        .await
        .expect_err("not its document");
    assert_eq!(rule(&err).1, "kind");
}

#[tokio::test]
async fn widening_by_a_person_waits_for_a_second_admin() {
    let Some(f) = start_with(&["--widening-approval=all"]).await else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL");
        return;
    };
    // team=payments, env=staging: developers' payments-ci role reaches it.
    let options = pb::WriteOptions {
        reason: "the ledger moves to RDS".into(),
        ..pb::WriteOptions::default()
    };
    // A plan that can't wait learns it early.
    let err = f
        .person_creates(
            &f.admin,
            "payments-ledger",
            "payments",
            pb::WriteOptions {
                validate_only: true,
                fail_if_approval_needed: true,
                ..pb::WriteOptions::default()
            },
        )
        .await
        .expect_err("needs approval");
    assert_eq!(reason(&err), "APPROVAL_REQUIRED");
    // Without it, a dry run says so in its warnings.
    let dry = f
        .person_creates(
            &f.admin,
            "payments-ledger",
            "payments",
            pb::WriteOptions {
                validate_only: true,
                ..pb::WriteOptions::default()
            },
        )
        .await
        .expect("dry run");
    assert_eq!(dry.outcome, i32::from(pb::WriteOutcome::Validated));
    assert!(dry.pending_change.is_none(), "a dry run holds nothing");
    assert!(
        dry.impact
            .expect("impact")
            .warnings
            .iter()
            .any(|w| w.contains("waits for a person's approval")),
        "the plan learns it would wait"
    );

    let held = f
        .person_creates(&f.admin, "payments-ledger", "payments", options)
        .await
        .expect("held");
    assert_eq!(held.outcome, i32::from(pb::WriteOutcome::PendingApproval));
    let change = held.pending_change.expect("the held change");
    assert_eq!(change.state, i32::from(pb::policy_change::State::Pending));
    assert_eq!(change.reason, "the ledger moves to RDS");
    assert!(
        change
            .impact
            .as_ref()
            .is_some_and(|i| i.widens_standing_access),
        "the approver sees what it gives"
    );
    assert_eq!(change.writes.len(), 1);
    assert!(!f.exists("payments-ledger").await, "nothing applied yet");

    // Not its author.
    let err = f.approve(&f.admin, &change.id).await.expect_err("author");
    assert_eq!(reason(&err), "CHANGE_NOT_DECIDABLE");
    // Bots see nothing that isn't theirs, and never decide.
    let err = f
        .api()
        .get_change(forwarded(
            pb::GetChangeRequest {
                id: change.id.clone(),
            },
            Some(&f.bot),
        ))
        .await
        .expect_err("not the bot's");
    assert_eq!(err.code(), Code::NotFound);

    // Resources a writer completes from its profile are approved by the
    // grant: never held, even with --widening-approval=all.
    let bot_write = f
        .create(
            "payments-orders-db",
            &endpoint(ENDPOINT),
            &[("env", "staging")],
            pb::WriteOptions::default(),
        )
        .await
        .expect("bot create");
    assert_eq!(bot_write.outcome, i32::from(pb::WriteOutcome::Applied));

    let (_, second) = f.h.login(ONCALL, &["admins"]).await.expect("second admin");
    let pending = f
        .api()
        .list_changes(forwarded(pb::ListChangesRequest::default(), Some(&second)))
        .await
        .expect("list")
        .into_inner()
        .changes;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, change.id);

    let applied = f.approve(&second, &change.id).await.expect("approve");
    assert_eq!(applied.state, i32::from(pb::policy_change::State::Applied));
    assert_eq!(applied.decided_by, ONCALL);
    assert!(applied.applied_policy_version > change.base_policy_version);
    assert!(f.exists("payments-ledger").await, "applied on approval");
    let err = f.approve(&second, &change.id).await.expect_err("decided");
    assert_eq!(reason(&err), "CHANGE_NOT_DECIDABLE");

    let events = f.h.audit_events().await;
    assert!(
        events
            .iter()
            .any(|e| e.kind == EventKind::PolicyChangePending)
    );
    assert!(
        events
            .iter()
            .any(|e| e.kind == EventKind::PolicyChangeDecided && e.data["state"] == "applied")
    );
    let applied_event = events
        .iter()
        .rfind(|e| e.kind == EventKind::PolicyChange)
        .expect("policy.change");
    assert_eq!(applied_event.data["approval"]["approved_by"], ONCALL);
    assert_eq!(
        applied_event.user.as_deref(),
        Some(ADMIN),
        "written as its author"
    );
}

#[tokio::test]
async fn held_changes_are_rejected_cancelled_or_superseded() {
    let Some(f) = start_with(&["--widening-approval=all"]).await else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL");
        return;
    };
    let (_, second) = f.h.login(ONCALL, &["admins"]).await.expect("second admin");
    let f = &f;
    let hold = |name: &'static str| async move {
        f.person_creates(&f.admin, name, "payments", pb::WriteOptions::default())
            .await
            .expect("held")
            .pending_change
            .expect("held change")
    };

    // Rejected, with a reason.
    let rejected = hold("payments-a").await;
    let reject = |note: &str| pb::RejectChangeRequest {
        id: rejected.id.clone(),
        note: note.into(),
    };
    let err = f
        .api()
        .reject_change(forwarded(reject(""), Some(&second)))
        .await
        .expect_err("a reason is required");
    assert_eq!(err.code(), Code::InvalidArgument);
    let decided = f
        .api()
        .reject_change(forwarded(reject("not this quarter"), Some(&second)))
        .await
        .expect("reject")
        .into_inner()
        .change
        .expect("change");
    assert_eq!(decided.state, i32::from(pb::policy_change::State::Rejected));
    assert_eq!(decided.decision_note, "not this quarter");

    // Withdrawn by its author only.
    let cancelled = hold("payments-b").await;
    let cancel = || pb::CancelChangeRequest {
        id: cancelled.id.clone(),
    };
    let err = f
        .api()
        .cancel_change(forwarded(cancel(), Some(&second)))
        .await
        .expect_err("not the author");
    assert_eq!(err.code(), Code::PermissionDenied);
    let decided = f
        .api()
        .cancel_change(forwarded(cancel(), Some(&f.admin)))
        .await
        .expect("cancel")
        .into_inner()
        .change
        .expect("change");
    assert_eq!(
        decided.state,
        i32::from(pb::policy_change::State::Cancelled)
    );

    // Superseded: the document it creates was made since, in another way.
    let superseded = hold("payments-c").await;
    let other = f
        .person_creates(
            &f.admin,
            "payments-c",
            "elsewhere",
            pb::WriteOptions::default(),
        )
        .await
        .expect("a write that gives nobody access goes through");
    assert_eq!(other.outcome, i32::from(pb::WriteOutcome::Applied));
    let decided = f.approve(&second, &superseded.id).await.expect("decide");
    assert_eq!(
        decided.state,
        i32::from(pb::policy_change::State::Superseded)
    );
    assert!(
        decided.decision_note.contains("already exists"),
        "{}",
        decided.decision_note
    );

    let listed = f
        .api()
        .list_changes(forwarded(
            pb::ListChangesRequest {
                state: pb::policy_change::State::Superseded.into(),
                ..pb::ListChangesRequest::default()
            },
            Some(&f.admin),
        ))
        .await
        .expect("list")
        .into_inner()
        .changes;
    assert_eq!(listed.len(), 1);
    assert!(
        f.api()
            .list_changes(forwarded(pb::ListChangesRequest::default(), Some(&f.admin)))
            .await
            .expect("list")
            .into_inner()
            .changes
            .is_empty(),
        "nothing pending is left"
    );
}

#[tokio::test]
async fn required_tests_refuse_writes_that_break_them() {
    let Some(f) = start_with(&["--policy-tests=required"]).await else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL");
        return;
    };
    // Without tests in the policy, required changes nothing.
    let created = f
        .person_creates(
            &f.admin,
            "payments-ledger",
            "elsewhere",
            pb::WriteOptions::default(),
        )
        .await
        .expect("no tests yet");
    let etag = created.documents[0].etag.clone();
    // Tests from their own source: developers never reach the ledger.
    AdminClient::new(f.proxy())
        .apply_policy(forwarded(
            ApplyPolicyRequest {
                source: "tests".into(),
                sources: vec![PolicySource {
                    name: "tests.yaml".into(),
                    content: "kind: policy_test\nversion: v1\nmetadata: { name: ledger-closed }\nspec:\n  cases:\n    - name: developers can't reach the ledger\n      who: { groups: [developers] }\n      resource: payments-ledger\n      principal: { db_role: limen_read, database: ledger }\n      expect: deny\n".into(),
                }],
                dry_run: false,
                source_ref: String::new(),
                require_tests: false,
            },
            Some(&f.admin),
        ))
        .await
        .expect("apply the tests");
    let mut doc = created.documents[0].clone();
    doc.labels.insert("team".into(), "payments".into());
    let err = f
        .api()
        .update_document(forwarded(
            pb::UpdateDocumentRequest {
                document: Some(doc),
                etag,
                options: None,
                ownership: Some(pb::Ownership {
                    source: "console-test".into(),
                    ..pb::Ownership::default()
                }),
            },
            Some(&f.admin),
        ))
        .await
        .expect_err("it breaks the test");
    assert_eq!(reason(&err), "TESTS_FAILED", "{err:?}");
    assert!(err.message().contains("ledger-closed"), "{}", err.message());
}

#[tokio::test]
async fn a_held_apply_never_undoes_a_newer_one() {
    let Some(f) = start_with(&["--widening-approval=all"]).await else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL");
        return;
    };
    let ledger = |team: &str| {
        format!(
            "kind: resource\nversion: v1\nmetadata: {{ name: payments-ledger, labels: {{ team: {team}, env: staging }} }}\nspec:\n  postgres: {{ endpoint: \"ledger.internal:5432\", default_database: ledger }}\n"
        )
    };
    let f = &f;
    let apply = |content: String| async move {
        AdminClient::new(f.proxy())
            .apply_policy(forwarded(
                ApplyPolicyRequest {
                    source: "ledger".into(),
                    sources: vec![PolicySource {
                        name: "ledger.yaml".into(),
                        content,
                    }],
                    dry_run: false,
                    source_ref: String::new(),
                    require_tests: false,
                },
                Some(&f.admin),
            ))
            .await
            .expect("apply")
            .into_inner()
    };
    let held = apply(ledger("payments")).await;
    assert!(!held.applied);
    assert!(
        !held.pending_change_id.is_empty(),
        "held for a second admin"
    );
    // Meanwhile the same source is applied again, giving nobody access.
    let newer = apply(ledger("elsewhere")).await;
    assert!(newer.applied && newer.pending_change_id.is_empty());

    let (_, second) = f.h.login(ONCALL, &["admins"]).await.expect("second admin");
    let decided = f
        .approve(&second, &held.pending_change_id)
        .await
        .expect("decide");
    assert_eq!(
        decided.state,
        i32::from(pb::policy_change::State::Superseded),
        "{}",
        decided.decision_note
    );
    let doc = f
        .api()
        .get_document(forwarded(
            pb::GetDocumentRequest {
                kind: pb::DocumentKind::Resource.into(),
                name: "payments-ledger".into(),
                policy_version: 0,
            },
            Some(&f.admin),
        ))
        .await
        .expect("get")
        .into_inner()
        .document
        .expect("doc");
    assert_eq!(
        doc.labels.get("team").map(String::as_str),
        Some("elsewhere"),
        "the newer apply stands"
    );
}

#[tokio::test]
async fn held_changes_expire() {
    let Some(f) = start_with(&["--widening-approval=all", "--policy-change-ttl=1s"]).await else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL");
        return;
    };
    let change = f
        .person_creates(
            &f.admin,
            "payments-ledger",
            "payments",
            pb::WriteOptions::default(),
        )
        .await
        .expect("held")
        .pending_change
        .expect("held change");
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let (_, second) = f.h.login(ONCALL, &["admins"]).await.expect("second admin");
    let err = f.approve(&second, &change.id).await.expect_err("expired");
    assert_eq!(reason(&err), "CHANGE_NOT_DECIDABLE");
    let expired = f
        .api()
        .list_changes(forwarded(
            pb::ListChangesRequest {
                state: pb::policy_change::State::Expired.into(),
                ..pb::ListChangesRequest::default()
            },
            Some(&second),
        ))
        .await
        .expect("list")
        .into_inner()
        .changes;
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].decided_by, "limen", "marked, not only shown");
    assert!(
        f.h.audit_events()
            .await
            .iter()
            .any(|e| e.kind == EventKind::PolicyChangeDecided && e.data["state"] == "expired")
    );
    assert!(!f.exists("payments-ledger").await);
}

#[tokio::test]
async fn admins_write_every_kind_through_the_api() {
    use pb::DocumentKind as K;
    let Some(f) = start().await else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL");
        return;
    };
    let none = pb::WriteOptions::default;
    let admin = &f.admin;
    f.put(
        admin,
        K::Role,
        "sre",
        r#"{"allow":[{"resources":{"kind":["ssh"],"labels":{"team":["sre"]}},"ssh":{"logins":["ubuntu"]}}]}"#,
        none(),
    )
    .await
    .expect("role");
    f.put(
        admin,
        K::RoleMapping,
        "sre-people",
        r#"[{"idp_group":"sre","roles":["sre"]}]"#,
        none(),
    )
    .await
    .expect("mapping");
    f.person_creates(admin, "sre-ledger", "sre", none())
        .await
        .expect("resource");
    let tested = f
        .put(admin, K::PolicyTest, "sre-only", r#"{"cases":[{"name":"guests never reach the ledger","who":{"groups":["guests"]},"resource":"sre-ledger","principal":{"db_role":"limen_read","database":"ledger"},"expect":"deny"}]}"#, none())
        .await
        .expect("test");
    assert!(
        tested
            .impact
            .expect("impact")
            .tests
            .iter()
            .any(|t| t.test == "sre-only" && t.passed),
        "its result comes back with the write"
    );
    f.put(admin, K::Bot, "nightly", r#"{"join":{"method":"github_actions","match":{"repository":"acme/nightly","ref":"refs/heads/main"}},"roles":["sre"]}"#, none())
        .await
        .expect("bot");
    let profile = f
        .get(K::ResourceProfile, "payments-postgres")
        .await
        .expect("profile from files");
    f.put(
        admin,
        K::ResourceProfile,
        "sre-postgres",
        &profile.spec_json,
        none(),
    )
    .await
    .expect("profile");
    f.put(admin, K::PolicyWriter, "nightly", r#"{"bot":"nightly","namespace":"sre","names":["sre-*"],"kinds":["resource","role"],"profiles":["sre-postgres"]}"#, none())
        .await
        .expect("writer grant");
    let mapping = f.get(K::RoleMapping, "sre-people").await.expect("mapping");
    assert_eq!(mapping.ownership.expect("owner").source, "terraform/test");
    assert!(
        mapping.spec_json.starts_with('['),
        "a mapping's spec is a list"
    );

    // A mapping's spec is a list, everything else an object.
    let err = f
        .put(admin, K::RoleMapping, "bad", r#"{"idp_group":"x"}"#, none())
        .await
        .expect_err("shape");
    assert_eq!(err.code(), Code::InvalidArgument);
    let err = f
        .put(admin, K::Role, "bad", "[]", none())
        .await
        .expect_err("shape");
    assert_eq!(err.code(), Code::InvalidArgument);

    // What a writer grant names can't go while it does.
    let bot = f.get(K::Bot, "nightly").await.expect("bot");
    let err = f
        .api()
        .delete_document(forwarded(
            pb::DeleteDocumentRequest {
                kind: K::Bot.into(),
                name: "nightly".into(),
                etag: bot.etag,
                allow_missing: false,
                options: None,
                ownership: Some(pb::Ownership {
                    source: "terraform/test".into(),
                    ..pb::Ownership::default()
                }),
            },
            Some(admin),
        ))
        .await
        .expect_err("in use");
    assert_eq!(reason(&err), "IN_USE", "{err:?}");
    let used_by = err
        .get_details_error_info()
        .and_then(|i| i.metadata.get("used_by").cloned())
        .unwrap_or_default();
    assert!(used_by.contains("policy_writer/nightly"), "{used_by}");
    // A grant naming a bot that never existed is an invalid document.
    let err = f
        .put(
            admin,
            K::PolicyWriter,
            "ghost",
            r#"{"bot":"ghost","namespace":"ghosts","names":["gh-*"],"kinds":["role"]}"#,
            none(),
        )
        .await
        .expect_err("unknown bot");
    assert_eq!(reason(&err), "INVALID_DOCUMENT", "{err:?}");

    // People-only kinds stay people-only.
    let err = f
        .put(&f.bot, K::Bot, "payments-sneaky", "{}", none())
        .await
        .expect_err("a bot never writes bots");
    assert_eq!(rule(&err), ("OUTSIDE_GRANT".to_owned(), "kind".to_owned()));
}

#[tokio::test]
async fn a_bot_writer_writes_roles_and_its_widening_waits_for_a_person() {
    use pb::DocumentKind as K;
    let Some(f) = start_writing(&[], "[resource, role, role_mapping, policy_test]").await else {
        eprintln!("SKIPPED: set LIMEN_TEST_DATABASE_URL");
        return;
    };
    let none = pb::WriteOptions::default;
    let bot = &f.bot;
    let me = f
        .api()
        .describe_caller(forwarded(pb::DescribeCallerRequest {}, Some(bot)))
        .await
        .expect("describe")
        .into_inner();
    assert_eq!(
        me.grant.expect("grant").kinds.len(),
        4,
        "the grant's kinds, not only resources"
    );

    // A role alone gives nobody anything: applied.
    let role = r#"{"allow":[{"resources":{"kind":["postgres"],"labels":{"team":["payments"],"env":["staging"]}},"db":{"roles":["limen_read"]}}]}"#;
    let made = f
        .put(bot, K::Role, "payments-readers", role, none())
        .await
        .expect("role");
    assert_eq!(made.outcome, i32::from(pb::WriteOutcome::Applied));

    // The escalation rules, before anything is held.
    for (kind, name, spec, want) in [
        (
            K::RoleMapping,
            "payments-admins",
            r#"[{"idp_group":"payments","roles":["limen:admin"]}]"#,
            "builtin_role",
        ),
        (
            K::RoleMapping,
            "payments-borrow",
            r#"[{"idp_group":"payments","roles":["payments-ci"]}]"#,
            "role",
        ),
        (
            K::Role,
            "payments-ask",
            r#"{"allow":[],"request":{"who":{"groups":["payments"]},"approvers":{"groups":["payments"]},"max_duration":"1h"}}"#,
            "field",
        ),
        (K::Role, "sre-readers", role, "name_pattern"),
        (K::Discovery, "payments-aws", "{}", "kind"),
    ] {
        let err = f.put(bot, kind, name, spec, none()).await.expect_err(name);
        assert_eq!(
            rule(&err),
            ("OUTSIDE_GRANT".to_owned(), want.to_owned()),
            "{name}: {err:?}"
        );
    }

    // A mapping to a role that reaches nothing yet gives nobody anything...
    let mapping = r#"[{"idp_group":"payments","roles":["payments-readers"]}]"#;
    let mapped = f
        .put(bot, K::RoleMapping, "payments-people", mapping, none())
        .await
        .expect("mapping");
    assert_eq!(mapped.outcome, i32::from(pb::WriteOutcome::Applied));
    // ...but the resource it would reach then waits: the access comes from
    // the writer's own mapping, not from roles people wrote, so a person
    // decides it, whatever order the writer built things in.
    let err = f
        .create(
            "payments-orders-db",
            &endpoint(ENDPOINT),
            &[("env", "staging")],
            pb::WriteOptions {
                validate_only: true,
                fail_if_approval_needed: true,
                ..pb::WriteOptions::default()
            },
        )
        .await
        .expect_err("a plan learns it would wait");
    assert_eq!(reason(&err), "APPROVAL_REQUIRED");
    let held = f
        .create(
            "payments-orders-db",
            &endpoint(ENDPOINT),
            &[("env", "staging")],
            pb::WriteOptions {
                reason: "the payments team reads its databases".into(),
                ..pb::WriteOptions::default()
            },
        )
        .await
        .expect("held");
    assert_eq!(held.outcome, i32::from(pb::WriteOutcome::PendingApproval));
    let change = held.pending_change.expect("change");
    assert_eq!(change.author, "bot:payments-terraform");
    assert_eq!(
        change.author_ci.get("actor").map(String::as_str),
        Some("octocat")
    );
    assert!(f.get(K::Resource, "payments-orders-db").await.is_none());
    // One the writer's role doesn't reach goes through (one only people's
    // roles reach does too: a_bot_writer_registers_a_resource_from_its_profile).
    let approved = f
        .create(
            "payments-other-db",
            &endpoint(ENDPOINT),
            &[("env", "dev")],
            none(),
        )
        .await
        .expect("create");
    assert_eq!(
        approved.outcome,
        i32::from(pb::WriteOutcome::Applied),
        "env=dev: nothing the writer wrote reaches it"
    );

    // The bot sees its own change but never decides it.
    let mine = f
        .api()
        .list_changes(forwarded(pb::ListChangesRequest::default(), Some(bot)))
        .await
        .expect("list")
        .into_inner()
        .changes;
    assert_eq!(mine.len(), 1);
    let err = f
        .approve(bot, &change.id)
        .await
        .expect_err("bots never decide");
    assert_eq!(err.code(), Code::PermissionDenied);
    // Whoever pushed the run can't approve it, even in the approver group.
    let (_, pusher) =
        f.h.login("octocat@example.com", &["security"])
            .await
            .expect("pusher");
    let err = f
        .approve(&pusher, &change.id)
        .await
        .expect_err("started the run");
    assert_eq!(reason(&err), "CHANGE_NOT_DECIDABLE");
    // Someone in neither the approver groups nor admins doesn't see it.
    let (_, developer) =
        f.h.login(DEVELOPER, &["developers"])
            .await
            .expect("developer");
    let err = f
        .approve(&developer, &change.id)
        .await
        .expect_err("not an approver");
    assert_eq!(err.code(), Code::NotFound);
    // A member of the grant's approver group decides.
    let (_, security) = f.h.login(ONCALL, &["security"]).await.expect("security");
    let applied = f.approve(&security, &change.id).await.expect("approve");
    assert_eq!(
        applied.state,
        i32::from(pb::policy_change::State::Applied),
        "{}",
        applied.decision_note
    );
    let doc = f
        .get(K::RoleMapping, "payments-people")
        .await
        .expect("applied");
    assert_eq!(
        doc.updated_by, "bot:payments-terraform",
        "written as its author"
    );

    // Tests: a writer writes its own, and can't delete anyone else's.
    let test = r#"{"cases":[{"name":"guests never read payments","who":{"groups":["guests"]},"resource":"payments-orders-db","principal":{"db_role":"limen_read","database":"orders"},"expect":"deny"}]}"#;
    let written = f
        .put(bot, K::PolicyTest, "payments-guests", test, none())
        .await
        .expect("test");
    assert_eq!(written.outcome, i32::from(pb::WriteOutcome::Applied));
    f.put(&f.admin, K::PolicyTest, "payments-guarded", test, none())
        .await
        .expect("admin test");
    // The admin's lives in default, outside the writer's namespace.
    let theirs = f
        .get(K::PolicyTest, "payments-guarded")
        .await
        .expect("theirs");
    let err = f
        .api()
        .delete_document(forwarded(
            pb::DeleteDocumentRequest {
                kind: K::PolicyTest.into(),
                name: "payments-guarded".into(),
                etag: theirs.etag,
                allow_missing: false,
                options: None,
                ownership: Some(pb::Ownership {
                    source: "terraform/test".into(),
                    ..pb::Ownership::default()
                }),
            },
            Some(bot),
        ))
        .await
        .expect_err("not its test");
    assert_eq!(reason(&err), "OWNED_ELSEWHERE", "{err:?}");
}
