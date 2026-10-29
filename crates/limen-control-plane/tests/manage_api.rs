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
use limen_testkit::users::ADMIN;
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
}

/// The example stack, with the mock issuer and a quota of two.
fn stack(issuer: &str) -> String {
    STACK
        .replace(
            "    method: github_actions\n",
            &format!("    method: github_actions\n    issuer: {issuer}\n"),
        )
        .replace("max_documents: 50", "max_documents: 2")
        + "---\nkind: role_mapping\nversion: v1\nmetadata: { name: people }\nspec:\n  - { idp_group: developers, roles: [payments-ci] }\n"
}

async fn start() -> Option<Fixture> {
    let h = Harness::start_with(&["--bot-allow-insecure-issuers".to_owned()]).await?;
    let (_, admin) = h.login(ADMIN, &["admins"]).await.expect("admin");
    let (_, proxy) = h.enroll_proxy().await;
    let f = Fixture {
        bot: CertificateDer::from(Vec::new()),
        h,
        proxy,
        admin,
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
                        content: stack(&self.h.idp.issuer),
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
                        content: stack(&f.h.idp.issuer),
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
