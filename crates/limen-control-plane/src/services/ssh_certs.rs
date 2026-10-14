//! Per-session SSH certificates (ADR-0007, amended in Phase 2).
//!
//! A worker asks for them while setting up a session a proxy granted. The
//! control plane checks the grant itself, re-evaluates its current policy,
//! checks the worker may serve the resource, and allows one issuance per
//! grant. A compromised worker therefore can only get certificates for
//! sessions users actually opened through it.

use std::time::Duration;

use limen_core::identity::ComponentKind;
use limen_policy::{AccessRequest, Principal};
use limen_proto::v1::ssh_certificates_server::SshCertificates;
use limen_proto::v1::{IssueSessionCertificatesRequest, IssueSessionCertificatesResponse};
use limen_session::grant::verify_grant;
use ssh_key::{Algorithm, PublicKey};
use time::OffsetDateTime;
use tonic::{Request, Response, Status};

use super::sha256;
use crate::caller;
use crate::db;
use crate::state::{AppState, internal};

/// Long enough to authenticate to the target, no longer.
const USER_CERT_TTL: Duration = Duration::from_secs(60);
const HOST_CERT_TTL: Duration = Duration::from_mins(5);

#[derive(Debug, Clone)]
pub struct SshCertificatesService(pub AppState);

fn parse_key(what: &str, openssh: &str) -> Result<PublicKey, Status> {
    let key = PublicKey::from_openssh(openssh)
        .map_err(|e| Status::invalid_argument(format!("{what}: {e}")))?;
    match key.algorithm() {
        Algorithm::Ed25519 | Algorithm::Ecdsa { .. } => Ok(key),
        other => Err(Status::invalid_argument(format!(
            "{what}: unsupported algorithm {other}"
        ))),
    }
}

#[tonic::async_trait]
impl SshCertificates for SshCertificatesService {
    async fn issue_session_certificates(
        &self,
        request: Request<IssueSessionCertificatesRequest>,
    ) -> Result<Response<IssueSessionCertificatesResponse>, Status> {
        let caller = caller::resolve(&request, &self.0.cas)?;
        let worker = caller.component()?.clone();
        if worker.kind != ComponentKind::Worker {
            return Err(Status::permission_denied(
                "only workers request session certificates",
            ));
        }
        let req = request.into_inner();
        let signed = req
            .grant
            .ok_or_else(|| Status::invalid_argument("grant is required"))?;
        let now = OffsetDateTime::now_utc();
        let verified = verify_grant(
            &signed,
            self.0.cas.internal.cert_der(),
            self.0.cas.user.cert_der(),
            now,
        )
        .map_err(|e| Status::permission_denied(e.to_string()))?;
        let grant = &verified.grant;
        if grant.worker_id != worker.id || grant.kind != "ssh" {
            return Err(Status::permission_denied(
                "grant is for another worker or protocol",
            ));
        }

        // The control plane's own, current view of policy has the last word.
        let loaded = self.0.policy.current();
        let decision = loaded.policy.evaluate(&AccessRequest {
            roles: &verified.user.roles,
            resource: &grant.resource,
            principal: Principal::SshLogin(grant.principal.clone()),
        });
        if !decision.is_allowed() {
            return Err(Status::permission_denied(format!(
                "policy no longer allows this session: {decision:?}"
            )));
        }
        if !loaded
            .policy
            .worker_may_serve(&grant.resource, &worker.labels)
        {
            return Err(Status::permission_denied(
                "this worker may not serve the resource",
            ));
        }

        // One issuance per grant, across all control plane replicas.
        let expires = OffsetDateTime::from_unix_timestamp(grant.establish_by_unix).unwrap_or(now);
        let mut key = b"ssh-grant:".to_vec();
        key.extend_from_slice(&grant.nonce);
        if !db::use_nonce(self.0.db.clone(), sha256(&key), expires)
            .await
            .map_err(|e| internal("recording grant use", e))?
        {
            return Err(Status::permission_denied("grant already used"));
        }

        let user_key = parse_key("user_public_key", &req.user_public_key)?;
        let host_key = parse_key("host_public_key", &req.host_public_key)?;
        let user_cert = self
            .0
            .cas
            .ssh_user
            .issue_user_cert(limen_ca::ssh::SshUserCertRequest {
                public_key: user_key,
                principal: grant.principal.clone(),
                key_id: format!("limen:{}:{}", grant.session_id, grant.username),
                ttl: USER_CERT_TTL,
                permit_pty: true,
                // Phase 2 doesn't forward ports; the worker refuses forwarding too.
                permit_port_forwarding: false,
            })
            .await
            .map_err(|e| internal("issuing SSH user certificate", e))?;
        let host_cert = self
            .0
            .cas
            .ssh_host
            .issue_host_cert(limen_ca::ssh::SshHostCertRequest {
                public_key: host_key,
                principals: vec![grant.resource.clone(), format!("{}.limen", grant.resource)],
                key_id: format!("limen:{}:{}", grant.session_id, worker.id),
                ttl: HOST_CERT_TTL,
            })
            .await
            .map_err(|e| internal("issuing SSH host certificate", e))?;
        tracing::info!(session = %grant.session_id, user = %grant.username, resource = %grant.resource, login = %grant.principal, worker = %worker.id, "issued SSH session certificates");
        Ok(Response::new(IssueSessionCertificatesResponse {
            user_certificate: user_cert
                .to_openssh()
                .map_err(|e| internal("encoding certificate", e))?,
            host_certificate: host_cert
                .to_openssh()
                .map_err(|e| internal("encoding certificate", e))?,
        }))
    }
}
