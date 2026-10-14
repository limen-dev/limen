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
    CreateJoinTokenResponse, GetPolicyRequest, GetPolicyResponse, KillSessionRequest,
    KillSessionResponse, ListComponentsRequest, ListComponentsResponse, ListLocksRequest,
    ListLocksResponse, Lock, LockUserRequest, LockUserResponse, PolicyDiff, TunnelInfo,
    UnlockUserRequest, UnlockUserResponse,
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

    async fn lock_user(
        &self,
        request: Request<LockUserRequest>,
    ) -> Result<Response<LockUserResponse>, Status> {
        let admin = caller::resolve(&request, &self.0.cas)?.admin()?.clone();
        let req = request.into_inner();
        let username = req.username.trim();
        if username.is_empty() || username.len() > 256 {
            return Err(Status::invalid_argument("username is required"));
        }
        let reason = clean_reason(&req.reason)?;
        let locked = db::lock_user(&self.0.db, username, &reason, &admin.username)
            .await
            .map_err(|e| internal("locking user", e))?;
        if locked {
            self.audit_admin(
                EventKind::UserLock,
                &admin.username,
                None,
                json!({ "target_user": username, "reason": reason }),
            )
            .await?;
            tracing::warn!(user = username, by = %admin.username, %reason, "user locked");
        }
        Ok(Response::new(LockUserResponse { locked }))
    }

    async fn unlock_user(
        &self,
        request: Request<UnlockUserRequest>,
    ) -> Result<Response<UnlockUserResponse>, Status> {
        let admin = caller::resolve(&request, &self.0.cas)?.admin()?.clone();
        let username = request.into_inner().username;
        let unlocked = db::unlock_user(&self.0.db, username.trim(), &admin.username)
            .await
            .map_err(|e| internal("unlocking user", e))?;
        if unlocked {
            self.audit_admin(
                EventKind::UserUnlock,
                &admin.username,
                None,
                json!({ "target_user": username.trim() }),
            )
            .await?;
            tracing::info!(user = username.trim(), by = %admin.username, "user unlocked");
        }
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
        let session_id = uuid::Uuid::parse_str(req.session_id.trim())
            .map_err(|_| Status::invalid_argument("session_id must be a session UUID"))?;
        let reason = clean_reason(&req.reason)?;
        let killed = db::kill_session(
            &self.0.db,
            &session_id.to_string(),
            &reason,
            &admin.username,
        )
        .await
        .map_err(|e| internal("killing session", e))?;
        if killed {
            self.audit_admin(
                EventKind::SessionKill,
                &admin.username,
                Some(session_id),
                json!({ "reason": reason }),
            )
            .await?;
            tracing::warn!(session = %session_id, by = %admin.username, %reason, "session kill requested");
        }
        Ok(Response::new(KillSessionResponse { killed }))
    }
}

impl AdminService {
    /// Audit an admin action. If the event can't be written, the caller
    /// returns an error: a lock nobody can audit still applies, but the admin
    /// is told it wasn't recorded.
    async fn audit_admin(
        &self,
        kind: EventKind,
        admin: &str,
        session_id: Option<uuid::Uuid>,
        mut data: serde_json::Value,
    ) -> Result<(), Status> {
        data["by"] = json!(admin);
        self.0
            .audit
            .emit(
                kind,
                Context {
                    user: Some(admin.to_owned()),
                    session_id,
                },
                data,
            )
            .await
            .map(|_| ())
            .map_err(|e| {
                tracing::error!(error = %e, "audit unavailable for an admin action");
                Status::unavailable("the change was applied but audit is unavailable")
            })
    }
}

/// Reasons are free text shown to the user and stored in audit.
fn clean_reason(reason: &str) -> Result<String, Status> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(Status::invalid_argument("a reason is required"));
    }
    if reason.len() > 500 || reason.chars().any(char::is_control) {
        return Err(Status::invalid_argument(
            "reason must be at most 500 characters, without control characters",
        ));
    }
    Ok(reason.to_owned())
}
