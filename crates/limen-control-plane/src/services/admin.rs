//! Administrative API. Every call requires the `limen:admin` role.

use std::collections::BTreeMap;
use std::time::Duration;

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
use tonic::{Request, Response, Status};

use super::{b64url, ops};
use crate::caller;
use crate::db;
use crate::policy_store::{self, Change, Input, Owner, StoreError};
use crate::state::{AppState, internal, unix};

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
        let documents = Policy::parse_yaml_documents(
            req.sources
                .iter()
                .map(|s| (s.name.as_str(), s.content.as_str())),
        )
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
        // Files replace their own source only (ADR-0042 §3): without
        // `--source`, the default one, which is everything applied before
        // Phase 14. Other owners' documents stay, and naming one is refused.
        let owner = Owner {
            source: if req.source.is_empty() {
                "default".into()
            } else {
                policy_store::validate_source(&req.source).map_err(Status::invalid_argument)?;
                req.source.clone()
            },
            ..Owner::default_git()
        };
        let inputs = documents
            .iter()
            .map(Input::document)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| store_status(&e))?;
        let outcome = policy_store::write(
            &self.0,
            policy_store::Request {
                actor: admin.username.clone(),
                changes: vec![Change::ReplaceSource {
                    owner,
                    documents: inputs,
                }],
                dry_run: req.dry_run,
                require_tests: req.require_tests,
                source_ref: Some(req.source_ref).filter(|s| !s.is_empty()),
                expected_version: None,
                guard: None,
            },
        )
        .await
        .map_err(|e| store_status(&e))?;
        Ok(Response::new(ApplyPolicyResponse {
            diff: Some(PolicyDiff {
                added: outcome.diff.added,
                removed: outcome.diff.removed,
                changed: outcome.diff.changed,
            }),
            version: outcome.version,
            digest: outcome.digest,
            applied: outcome.applied,
            access_changes: outcome
                .access
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
                .collect(),
            warnings: outcome.warnings,
            test_results: outcome
                .tests
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
                .collect(),
        }))
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
        // The snapshot view: older CLIs can't parse the control plane's own
        // kinds, and they don't change who can reach what.
        let documents_json = serde_json::to_string(&loaded.policy.snapshot_documents())
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

/// The gRPC status for a store error.
#[must_use]
pub fn store_status(e: &StoreError) -> Status {
    match e {
        StoreError::Invalid(_) => Status::invalid_argument(e.to_string()),
        StoreError::OwnedElsewhere { .. }
        | StoreError::EtagMismatch { .. }
        | StoreError::TestsFailed(_)
        | StoreError::InUse { .. }
        | StoreError::VersionMismatch { .. } => Status::failed_precondition(e.to_string()),
        StoreError::NotFound(_) => Status::not_found(e.to_string()),
        StoreError::Denied { .. } => Status::permission_denied(e.to_string()),
        StoreError::QuotaExceeded { .. } => Status::resource_exhausted(e.to_string()),
        StoreError::AlreadyExists(_) => Status::already_exists(e.to_string()),
        StoreError::AuditUnavailable => Status::unavailable("audit unavailable"),
        StoreError::Internal(m) => internal("writing policy", m),
    }
}
