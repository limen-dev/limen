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
    CreateJoinTokenResponse, GetPolicyRequest, GetPolicyResponse, ListComponentsRequest,
    ListComponentsResponse, PolicyDiff, TunnelInfo,
};
use serde_json::json;
use time::OffsetDateTime;
use tonic::{Request, Response, Status};

use super::{b64url, sha256};
use crate::caller;
use crate::db;
use crate::state::{AppState, LoadedPolicy, internal, unix};

const MAX_POLICY_BYTES: usize = 1024 * 1024;
const DEFAULT_TOKEN_TTL: Duration = Duration::from_mins(15);
const MAX_TOKEN_TTL: Duration = Duration::from_hours(24);

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
        let current = self.0.policy.current();
        let diff = current.policy.diff(&next);
        let digest = next.digest();
        let proto_diff = PolicyDiff {
            added: diff.added.clone(),
            removed: diff.removed.clone(),
            changed: diff.changed.clone(),
        };
        if req.dry_run || diff.is_empty() {
            return Ok(Response::new(ApplyPolicyResponse {
                diff: Some(proto_diff),
                version: current.version,
                digest,
                applied: false,
            }));
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
        Ok(Response::new(ApplyPolicyResponse {
            diff: Some(proto_diff),
            version,
            digest,
            applied: true,
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
        let caller = caller::resolve(&request, &self.0.cas)?;
        let admin = caller.admin()?.clone();
        let req = request.into_inner();
        if !matches!(req.kind.as_str(), "proxy" | "worker") {
            return Err(Status::invalid_argument("kind must be proxy or worker"));
        }
        if req.kind == "worker" && !req.dns_names.is_empty() {
            return Err(Status::invalid_argument(
                "worker certificates carry no DNS names",
            ));
        }
        let labels = parse_labels(&req.labels)?;
        let ttl = if req.ttl_seconds == 0 {
            DEFAULT_TOKEN_TTL
        } else {
            Duration::from_secs(u64::from(req.ttl_seconds))
        };
        if ttl > MAX_TOKEN_TTL {
            return Err(Status::invalid_argument("ttl must be at most 24h"));
        }
        let token = new_token();
        let expires_at = OffsetDateTime::now_utc() + ttl;
        let labels_json = serde_json::to_value(&labels).map_err(|e| internal("labels", e))?;
        db::insert_join_token(
            &self.0.db,
            &sha256(token.as_bytes()),
            &req.kind,
            &labels_json,
            &req.dns_names,
            &admin.username,
            expires_at,
        )
        .await
        .map_err(|e| internal("storing join token", e))?;
        let data = json!({ "kind": req.kind, "labels": labels, "dns_names": req.dns_names, "expires_at": unix(expires_at) });
        self.0
            .audit
            .emit(
                EventKind::JoinTokenCreate,
                Context {
                    user: Some(admin.username),
                    session_id: None,
                },
                data,
            )
            .await
            .map_err(|_| Status::unavailable("audit unavailable"))?;
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
                        })
                        .collect(),
                    id: c.id,
                    kind: c.kind,
                    labels: labels.into_iter().collect(),
                    enrolled_at_unix: unix(c.enrolled_at),
                    last_seen_at_unix: unix(c.last_seen_at),
                    cert_expires_at_unix: c.cert_expires_at.map_or(0, unix),
                }
            })
            .collect();
        Ok(Response::new(ListComponentsResponse { components }))
    }
}
