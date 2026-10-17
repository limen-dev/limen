//! Component enrollment and certificate renewal.

use std::collections::BTreeMap;

use limen_audit::{Context, EventKind};
use limen_ca::ComponentCertRequest;
use limen_core::identity::ComponentKind;
use limen_core::names::{NAME_LABEL, NamePattern, validate_name};
use limen_proto::v1::enrollment_server::Enrollment;
use limen_proto::v1::{
    EnrollRequest, EnrollResponse, RenewCertificateRequest, RenewCertificateResponse,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use tonic::{Request, Response, Status};

use super::sha256;
use crate::caller;
use crate::db;
use crate::state::{AppState, internal, unix};

#[derive(Debug, Clone)]
pub struct EnrollmentService(pub AppState);

fn ca_error(e: limen_ca::CaError) -> Status {
    match e {
        limen_ca::CaError::InvalidCsr(m) | limen_ca::CaError::InvalidRequest(m) => {
            Status::invalid_argument(m)
        }
        other => internal("issuing component certificate", other),
    }
}

/// The token's labels with the name, if any, as [`NAME_LABEL`]. A
/// `NAME_LABEL` in the token's own labels is dropped: only an approved,
/// unique name may carry it.
fn with_name(mut labels: serde_json::Value, name: Option<&str>) -> serde_json::Value {
    if let Some(map) = labels.as_object_mut() {
        map.remove(NAME_LABEL);
        if let Some(name) = name {
            map.insert(NAME_LABEL.to_owned(), json!(name));
        }
    }
    labels
}

/// The name a component gets: the one it asked for, if the token approves
/// it (`Err` if not); else a single-use token's exact name; else none. (A
/// static token's name is always a pattern, so it never names on its own.)
fn choose_name(
    requested: Option<&str>,
    approved: Option<&NamePattern>,
    single_use: bool,
) -> Result<Option<String>, ()> {
    match (requested, approved) {
        (Some(name), Some(pattern)) if pattern.matches(name) => Ok(Some(name.to_owned())),
        (Some(_), _) => Err(()),
        (None, Some(pattern)) if single_use => Ok(pattern.exact().map(str::to_owned)),
        (None, _) => Ok(None),
    }
}

/// Constant-time comparison of two secrets, by comparing their hashes.
fn same_secret(a: &str, b: &str) -> bool {
    Sha256::digest(a.as_bytes()) == Sha256::digest(b.as_bytes())
}

impl EnrollmentService {
    /// Audit a refused enrollment (`auth.denied`). Best effort: the
    /// enrollment is refused either way.
    async fn audit_denial(&self, data: serde_json::Value) {
        let _ = self
            .0
            .audit
            .emit(EventKind::AuthDenied, Context::default(), data)
            .await;
    }
}

#[tonic::async_trait]
impl Enrollment for EnrollmentService {
    async fn enroll(
        &self,
        request: Request<EnrollRequest>,
    ) -> Result<Response<EnrollResponse>, Status> {
        let caller = caller::resolve(&request, &self.0.cas)?;
        self.0.limits.check_unauthenticated(caller.addr())?;
        let req = request.into_inner();
        let kind = match req.kind.as_str() {
            "proxy" => ComponentKind::Proxy,
            "worker" => ComponentKind::Worker,
            _ => return Err(Status::invalid_argument("kind must be proxy or worker")),
        };
        if req.join_token.is_empty() || req.join_token.len() > 256 {
            return Err(Status::invalid_argument("invalid join token"));
        }
        // Validated as sent: never trimmed or lowered.
        let requested = (!req.name.is_empty()).then_some(req.name.as_str());
        if let Some(name) = requested {
            validate_name(name).map_err(|e| Status::invalid_argument(e.to_string()))?;
        }
        let id = format!(
            "{}-{}",
            req.kind,
            &uuid::Uuid::now_v7().simple().to_string()[20..]
        );

        let mut tx = self
            .0
            .db
            .begin()
            .await
            .map_err(|e| internal("starting transaction", e))?;
        let static_match = self
            .0
            .config
            .static_join_tokens
            .iter()
            .find(|t| t.kind == req.kind && same_secret(t.token.expose(), &req.join_token));
        let (labels, allowed_dns, approved, token_type) = if let Some(token) = static_match {
            let allowed = if kind == ComponentKind::Proxy {
                self.0.config.proxy_dns_names.clone()
            } else {
                Vec::new()
            };
            let labels = serde_json::to_value(&token.labels)
                .map_err(|e| internal("static token labels", e))?;
            (labels, allowed, token.name.clone(), "static")
        } else {
            match db::consume_join_token(
                &mut tx,
                &sha256(req.join_token.as_bytes()),
                &req.kind,
                &id,
            )
            .await
            .map_err(|e| internal("consuming join token", e))?
            {
                Some(token) => {
                    let approved = token
                        .name
                        .as_deref()
                        .map(NamePattern::parse)
                        .transpose()
                        .map_err(|e| internal("join token name", e))?;
                    (token.labels, token.dns_names, approved, "single_use")
                }
                None => {
                    drop(tx);
                    tracing::warn!(kind = %req.kind, addr = ?caller.addr(), "enrollment rejected: invalid, expired, or used join token");
                    self.audit_denial(json!({ "action": "enroll", "kind": req.kind, "reason": "invalid join token", "client_addr": caller.addr().map(|a| a.to_string()) })).await;
                    return Err(Status::permission_denied(
                        "invalid, expired, or already used join token",
                    ));
                }
            }
        };
        if let Some(bad) = req.dns_names.iter().find(|n| !allowed_dns.contains(n)) {
            return Err(Status::permission_denied(format!(
                "DNS name {bad:?} is not allowed by this join token"
            )));
        }
        let Ok(name) = choose_name(requested, approved.as_ref(), token_type == "single_use") else {
            // Rolls back: a single-use token stays usable.
            drop(tx);
            tracing::warn!(kind = %req.kind, name = req.name, addr = ?caller.addr(), "enrollment rejected: name not approved by the join token");
            self.audit_denial(json!({ "action": "enroll", "kind": req.kind, "reason": "name not approved by join token", "name": req.name, "token_type": token_type, "client_addr": caller.addr().map(|a| a.to_string()) })).await;
            return Err(Status::permission_denied(format!(
                "name {:?} is not approved by this join token",
                req.name
            )));
        };
        let labels = with_name(labels, name.as_deref());

        let issued = self
            .0
            .cas
            .internal
            .issue_component(ComponentCertRequest {
                csr_der: req.csr_der,
                kind,
                id: id.clone(),
                dns_names: req.dns_names.clone(),
                labels: serde_json::from_value(labels.clone())
                    .map_err(|e| internal("join token labels", e))?,
                ttl: self.0.config.component_cert_ttl,
            })
            .await
            .map_err(ca_error)?;
        // Claims the name in the same transaction as the token: a name
        // conflict rolls both back, so the token is not used up.
        if let Err(e) = db::insert_component(
            &mut tx,
            &id,
            &req.kind,
            name.as_deref(),
            &labels,
            &req.dns_names,
            issued.not_after,
        )
        .await
        {
            if db::is_name_taken(&e) {
                tracing::warn!(kind = %req.kind, name = name.as_deref(), client = ?caller.addr(), "enrollment rejected: name already in use");
                // Someone holding a valid token tried to take a live
                // component's name: record it like the other refusals. The
                // transaction (and so the token) is released first; the
                // audit write must not sit inside a failed transaction.
                drop(tx);
                self.audit_denial(json!({ "action": "enroll", "kind": req.kind, "reason": "name already in use", "name": name, "token_type": token_type, "client_addr": caller.addr().map(|a| a.to_string()) })).await;
                return Err(Status::already_exists(format!(
                    "name {:?} is already used by another enrolled proxy or worker; revoke that one first, or choose another name",
                    name.unwrap_or_default()
                )));
            }
            return Err(internal("storing component", e));
        }
        let mut data = json!({ "component_id": id, "kind": req.kind, "labels": labels, "dns_names": req.dns_names, "token_type": token_type, "cert_serial": issued.serial_hex });
        if let Some(name) = &name {
            data["component_name"] = json!(name);
        }
        self.0
            .audit
            .emit(EventKind::WorkerEnroll, Context::default(), data)
            .await
            .map_err(|_| Status::unavailable("audit unavailable"))?;
        tx.commit()
            .await
            .map_err(|e| internal("committing enrollment", e))?;
        tracing::info!(component_id = %id, name = name.as_deref(), kind = %req.kind, token_type, "component enrolled");

        let labels: BTreeMap<String, String> = serde_json::from_value(labels).unwrap_or_default();
        Ok(Response::new(EnrollResponse {
            component_id: id,
            cert_pem: issued.pem,
            internal_ca_pem: self.0.cas.internal.cert_pem().to_owned(),
            user_ca_pem: self.0.cas.user.cert_pem().to_owned(),
            expires_at_unix: unix(issued.not_after),
            labels: labels.into_iter().collect(),
            name: name.unwrap_or_default(),
        }))
    }

    async fn renew_certificate(
        &self,
        request: Request<RenewCertificateRequest>,
    ) -> Result<Response<RenewCertificateResponse>, Status> {
        let caller = caller::resolve(&request, &self.0.cas)?;
        let identity = caller.component()?.clone();
        let row = db::component(&self.0.db, &identity.id)
            .await
            .map_err(|e| internal("loading component", e))?
            .ok_or_else(|| Status::permission_denied("unknown component"))?;
        if row.revoked_at.is_some() || row.kind != identity.kind.as_str() {
            return Err(Status::permission_denied("component is revoked"));
        }
        let req = request.into_inner();
        let issued = self
            .0
            .cas
            .internal
            .issue_component(ComponentCertRequest {
                csr_der: req.csr_der,
                kind: identity.kind,
                id: identity.id.clone(),
                dns_names: row.dns_names,
                labels: serde_json::from_value(row.labels)
                    .map_err(|e| internal("component labels", e))?,
                ttl: self.0.config.component_cert_ttl,
            })
            .await
            .map_err(ca_error)?;
        db::record_renewal(&self.0.db, &identity.id, issued.not_after)
            .await
            .map_err(|e| internal("recording renewal", e))?;
        tracing::info!(component_id = %identity.id, expires_at = unix(issued.not_after), "certificate renewed");
        Ok(Response::new(RenewCertificateResponse {
            cert_pem: issued.pem,
            expires_at_unix: unix(issued.not_after),
        }))
    }
}
