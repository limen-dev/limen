//! Administrative API. Every call requires the `limen:admin` role.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use limen_audit::{Context, EventKind};
use limen_core::labels::Labels;
use limen_policy::Policy;
use limen_proto::v1::admin_server::Admin;
use limen_proto::v1::{
    ApplyPolicyRequest, ApplyPolicyResponse, Component, CreateJoinTokenRequest,
    CreateJoinTokenResponse, DiscoveredInfo, GetPolicyDocumentsRequest, GetPolicyDocumentsResponse,
    GetPolicyRequest, GetPolicyResponse, KillSessionRequest, KillSessionResponse,
    ListComponentsRequest, ListComponentsResponse, ListDiscoveredRequest, ListDiscoveredResponse,
    ListLocksRequest, ListLocksResponse, Lock, LockUserRequest, LockUserResponse, PolicyDiff,
    PolicyTestResult, ReviewDiscoveredRequest, RevokeComponentRequest, RevokeComponentResponse,
    TunnelInfo, UnlockUserRequest, UnlockUserResponse,
};
use serde_json::json;
use time::OffsetDateTime;
use tonic::{Request, Response, Status};

use super::{b64url, ops};
use crate::caller;
use crate::db;
use crate::state::{AppState, LoadedPolicy, internal, unix};

const MAX_POLICY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct AdminService(pub AppState);

/// Prefix that makes leaked join tokens easy to recognize in secret scanners.
pub const TOKEN_PREFIX: &str = "lmn_join_";

#[must_use]
pub fn new_token() -> String {
    let bytes: [u8; 32] = rand::random();
    format!("{TOKEN_PREFIX}{}", b64url(&bytes))
}

pub fn parse_labels<S: std::hash::BuildHasher>(
    map: &std::collections::HashMap<String, String, S>,
) -> Result<Labels, Status> {
    let sorted: BTreeMap<String, String> =
        map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    Labels::try_from(sorted).map_err(|e| Status::invalid_argument(e.to_string()))
}

#[tonic::async_trait]
impl Admin for AdminService {
    async fn apply_policy(
        &self,
        request: Request<ApplyPolicyRequest>,
    ) -> Result<Response<ApplyPolicyResponse>, Status> {
        let caller = caller::resolve(&request, &self.0.cas)?;
        let admin = caller.admin()?.clone();
        let req = request.into_inner();
        let total: usize = req.sources.iter().map(|s| s.content.len()).sum();
        if total > MAX_POLICY_BYTES {
            return Err(Status::invalid_argument(format!(
                "policy exceeds {MAX_POLICY_BYTES} bytes"
            )));
        }
        let next = Policy::parse_yaml(
            req.sources
                .iter()
                .map(|s| (s.name.as_str(), s.content.as_str())),
        )
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
        // Versions and diffs are about what admins applied, not discovered resources.
        let current = self.0.policy.base();
        let diff = current.policy.diff(&next);
        let digest = next.digest();
        let proto_diff = PolicyDiff {
            added: diff.added.clone(),
            removed: diff.removed.clone(),
            changed: diff.changed.clone(),
        };
        // Who gains or loses access, the policy's own tests, and anything
        // valid but suspicious (ADR-0028). The same engine as enforcement.
        let access = current.policy.access_diff(&next);
        let access_changes: Vec<String> = access
            .changes
            .iter()
            .map(|c| {
                let sign = if c.change == limen_policy::tooling::ChangeKind::Gain {
                    '+'
                } else {
                    '-'
                };
                format!("{sign} {}", c.text())
            })
            .collect();
        let report = next.run_tests();
        let test_results: Vec<PolicyTestResult> = report
            .results
            .iter()
            .map(|r| PolicyTestResult {
                test: r.test.clone(),
                case_number: u32::try_from(r.case).unwrap_or(u32::MAX),
                name: r.name.clone(),
                passed: r.passed,
                expected: r.expected.clone(),
                got: r.got.clone(),
                detail: r.detail.clone(),
            })
            .collect();
        let warnings = next.warnings();
        if req.require_tests && !req.dry_run {
            if report.results.is_empty() {
                return Err(Status::failed_precondition(
                    "--require-tests: the policy has no policy_test documents",
                ));
            }
            if !report.ok() {
                let failed: Vec<String> = report
                    .results
                    .iter()
                    .filter(|r| !r.passed)
                    .map(|r| {
                        format!(
                            "{} #{} {}: expected {}, got {} {}",
                            r.test, r.case, r.name, r.expected, r.got, r.detail
                        )
                    })
                    .collect();
                return Err(Status::failed_precondition(format!(
                    "--require-tests: {} policy test(s) failed:\n{}",
                    failed.len(),
                    failed.join("\n")
                )));
            }
        }
        let response = |version: i64, applied: bool| ApplyPolicyResponse {
            diff: Some(proto_diff.clone()),
            version,
            digest: digest.clone(),
            applied,
            access_changes: access_changes.clone(),
            warnings: warnings.clone(),
            test_results: test_results.clone(),
        };
        if req.dry_run || diff.is_empty() {
            return Ok(Response::new(response(current.version, false)));
        }

        let documents = serde_json::to_value(next.documents())
            .map_err(|e| internal("serializing policy", e))?;
        let source_ref = Some(req.source_ref.as_str()).filter(|s| !s.is_empty());
        let mut tx = self
            .0
            .db
            .begin()
            .await
            .map_err(|e| internal("starting transaction", e))?;
        let version = db::insert_policy(&mut tx, &digest, &documents, &admin.username, source_ref)
            .await
            .map_err(|e| internal("storing policy", e))?;
        // Audit before commit: if the event can't be written, the change isn't applied.
        let data = json!({
            "version": version,
            "previous_version": current.version,
            "digest": digest,
            "source_ref": source_ref,
            "diff": diff,
            // Who gained or lost access, so a reviewer of the trail sees
            // what the change meant, not only which documents moved.
            "access_changes": access_changes.iter().take(200).collect::<Vec<_>>(),
        });
        self.0
            .audit
            .emit(
                EventKind::PolicyChange,
                Context {
                    user: Some(admin.username.clone()),
                    session_id: None,
                },
                data,
            )
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "audit unavailable; refusing policy change");
                Status::unavailable("audit unavailable")
            })?;
        tx.commit()
            .await
            .map_err(|e| internal("committing policy", e))?;
        self.0.policy.set(LoadedPolicy {
            version,
            policy: Arc::new(next),
            author: admin.username.clone(),
            created_at: Some(OffsetDateTime::now_utc()),
        });
        tracing::info!(version, %digest, author = %admin.username, "policy applied");
        Ok(Response::new(response(version, true)))
    }

    async fn list_discovered(
        &self,
        request: Request<ListDiscoveredRequest>,
    ) -> Result<Response<ListDiscoveredResponse>, Status> {
        caller::resolve(&request, &self.0.cas)?.admin()?;
        let items = crate::discovery::list(&self.0.db, &request.into_inner().state).await?;
        Ok(Response::new(ListDiscoveredResponse { items }))
    }

    async fn review_discovered(
        &self,
        request: Request<ReviewDiscoveredRequest>,
    ) -> Result<Response<DiscoveredInfo>, Status> {
        let admin = caller::resolve(&request, &self.0.cas)?.admin()?.clone();
        let r = request.into_inner();
        crate::discovery::review(
            &self.0,
            &admin.username,
            "api",
            &r.key,
            r.accept,
            &r.note,
            None,
        )
        .await
        .map(Response::new)
    }

    async fn get_policy_documents(
        &self,
        request: Request<GetPolicyDocumentsRequest>,
    ) -> Result<Response<GetPolicyDocumentsResponse>, Status> {
        caller::resolve(&request, &self.0.cas)?.admin()?;
        let loaded = self.0.policy.current();
        let documents_json = serde_json::to_string(&loaded.policy.documents())
            .map_err(|e| internal("serializing policy", e))?;
        Ok(Response::new(GetPolicyDocumentsResponse {
            version: loaded.version,
            documents_json,
        }))
    }

    async fn get_policy(
        &self,
        request: Request<GetPolicyRequest>,
    ) -> Result<Response<GetPolicyResponse>, Status> {
        caller::resolve(&request, &self.0.cas)?.admin()?;
        let loaded = self.0.policy.current();
        Ok(Response::new(GetPolicyResponse {
            version: loaded.version,
            digest: loaded.policy.digest(),
            author: loaded.author.clone(),
            created_at_unix: loaded.created_at.map_or(0, unix),
            resource_count: u32::try_from(loaded.policy.resource_count()).unwrap_or(u32::MAX),
        }))
    }

    async fn create_join_token(
        &self,
        request: Request<CreateJoinTokenRequest>,
    ) -> Result<Response<CreateJoinTokenResponse>, Status> {
        let admin = caller::resolve(&request, &self.0.cas)?.admin()?.clone();
        let req = request.into_inner();
        let labels = parse_labels(&req.labels)?;
        let ttl = (req.ttl_seconds != 0).then(|| Duration::from_secs(u64::from(req.ttl_seconds)));
        let (token, expires_at) = ops::create_join_token(
            &self.0,
            ops::Actor {
                username: &admin.username,
                via: "api",
            },
            &req.kind,
            &labels.into(),
            ttl,
            &req.dns_names,
            Some(req.name.as_str()),
        )
        .await?;
        Ok(Response::new(CreateJoinTokenResponse {
            token,
            expires_at_unix: unix(expires_at),
        }))
    }

    async fn list_components(
        &self,
        request: Request<ListComponentsRequest>,
    ) -> Result<Response<ListComponentsResponse>, Status> {
        caller::resolve(&request, &self.0.cas)?.admin()?;
        let (components, tunnels) = db::list_components(&self.0.db)
            .await
            .map_err(|e| internal("listing components", e))?;
        let components = components
            .into_iter()
            .map(|c| {
                let labels: BTreeMap<String, String> =
                    serde_json::from_value(c.labels).unwrap_or_default();
                Component {
                    tunnels: tunnels
                        .iter()
                        .filter(|t| t.worker_id == c.id || t.proxy_id == c.id)
                        .map(|t| TunnelInfo {
                            proxy_id: t.proxy_id.clone(),
                            tunnel_id: format!("{}->{}", t.worker_id, t.tunnel_id),
                            lease_expires_at_unix: unix(t.lease_expires_at),
                            proxy_name: t.proxy_name.clone().unwrap_or_default(),
                        })
                        .collect(),
                    id: c.id,
                    kind: c.kind,
                    labels: labels.into_iter().collect(),
                    enrolled_at_unix: unix(c.enrolled_at),
                    last_seen_at_unix: unix(c.last_seen_at),
                    cert_expires_at_unix: c.cert_expires_at.map_or(0, unix),
                    name: c.name.unwrap_or_default(),
                }
            })
            .collect();
        Ok(Response::new(ListComponentsResponse { components }))
    }

    async fn lock_user(
        &self,
        request: Request<LockUserRequest>,
    ) -> Result<Response<LockUserResponse>, Status> {
        let admin = caller::resolve(&request, &self.0.cas)?.admin()?.clone();
        let req = request.into_inner();
        let locked =
            ops::lock_user(&self.0, actor(&admin.username), &req.username, &req.reason).await?;
        Ok(Response::new(LockUserResponse { locked }))
    }

    async fn unlock_user(
        &self,
        request: Request<UnlockUserRequest>,
    ) -> Result<Response<UnlockUserResponse>, Status> {
        let admin = caller::resolve(&request, &self.0.cas)?.admin()?.clone();
        let unlocked = ops::unlock_user(
            &self.0,
            actor(&admin.username),
            &request.into_inner().username,
        )
        .await?;
        Ok(Response::new(UnlockUserResponse { unlocked }))
    }

    async fn list_locks(
        &self,
        request: Request<ListLocksRequest>,
    ) -> Result<Response<ListLocksResponse>, Status> {
        caller::resolve(&request, &self.0.cas)?.admin()?;
        let locks = db::active_locks(&self.0.db)
            .await
            .map_err(|e| internal("listing locks", e))?
            .into_iter()
            .map(|l| Lock {
                username: l.username,
                reason: l.reason,
                locked_by: l.locked_by,
                locked_at_unix: unix(l.locked_at),
            })
            .collect();
        Ok(Response::new(ListLocksResponse { locks }))
    }

    async fn kill_session(
        &self,
        request: Request<KillSessionRequest>,
    ) -> Result<Response<KillSessionResponse>, Status> {
        let admin = caller::resolve(&request, &self.0.cas)?.admin()?.clone();
        let req = request.into_inner();
        let killed = ops::kill_session(
            &self.0,
            actor(&admin.username),
            &req.session_id,
            &req.reason,
        )
        .await?;
        Ok(Response::new(KillSessionResponse { killed }))
    }

    async fn revoke_component(
        &self,
        request: Request<RevokeComponentRequest>,
    ) -> Result<Response<RevokeComponentResponse>, Status> {
        let admin = caller::resolve(&request, &self.0.cas)?.admin()?.clone();
        let req = request.into_inner();
        let revoked = ops::revoke_component(
            &self.0,
            actor(&admin.username),
            &req.component_id,
            &req.reason,
        )
        .await?;
        Ok(Response::new(RevokeComponentResponse { revoked }))
    }
}

fn actor(username: &str) -> ops::Actor<'_> {
    ops::Actor {
        username,
        via: "api",
    }
}
