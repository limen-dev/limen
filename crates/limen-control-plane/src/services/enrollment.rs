//! Component enrollment and certificate renewal.

use std::collections::BTreeMap;

use limen_audit::{Context, EventKind};
use limen_ca::ComponentCertRequest;
use limen_core::identity::ComponentKind;
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

/// Constant-time comparison of two secrets, by comparing their hashes.
fn same_secret(a: &str, b: &str) -> bool {
    Sha256::digest(a.as_bytes()) == Sha256::digest(b.as_bytes())
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
        let (labels, allowed_dns, token_type) = if static_match.is_some() {
            let allowed = if kind == ComponentKind::Proxy {
                self.0.config.proxy_dns_names.clone()
            } else {
                Vec::new()
            };
            (serde_json::json!({}), allowed, "static")
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
                Some((labels, dns)) => (labels, dns, "single_use"),
                None => {
                    drop(tx);
                    tracing::warn!(kind = %req.kind, addr = ?caller.addr(), "enrollment rejected: invalid, expired, or used join token");
                    let data = json!({ "action": "enroll", "kind": req.kind, "reason": "invalid join token", "client_addr": caller.addr().map(|a| a.to_string()) });
                    let _ = self
                        .0
                        .audit
                        .emit(EventKind::AuthDenied, Context::default(), data)
                        .await;
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

        let issued = self
            .0
            .cas
            .internal
            .issue_component(ComponentCertRequest {
                csr_der: req.csr_der,
                kind,
                id: id.clone(),
                dns_names: req.dns_names.clone(),
                ttl: self.0.config.component_cert_ttl,
            })
            .await
            .map_err(ca_error)?;
        db::insert_component(
            &mut tx,
            &id,
            &req.kind,
            &labels,
            &req.dns_names,
            issued.not_after,
        )
        .await
        .map_err(|e| internal("storing component", e))?;
        let data = json!({ "component_id": id, "kind": req.kind, "labels": labels, "dns_names": req.dns_names, "token_type": token_type, "cert_serial": issued.serial_hex });
        self.0
            .audit
            .emit(EventKind::WorkerEnroll, Context::default(), data)
            .await
            .map_err(|_| Status::unavailable("audit unavailable"))?;
        tx.commit()
            .await
            .map_err(|e| internal("committing enrollment", e))?;
        tracing::info!(component_id = %id, kind = %req.kind, token_type, "component enrolled");

        let labels: BTreeMap<String, String> = serde_json::from_value(labels).unwrap_or_default();
        Ok(Response::new(EnrollResponse {
            component_id: id,
            cert_pem: issued.pem,
            internal_ca_pem: self.0.cas.internal.cert_pem().to_owned(),
            user_ca_pem: self.0.cas.user.cert_pem().to_owned(),
            expires_at_unix: unix(issued.not_after),
            labels: labels.into_iter().collect(),
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
