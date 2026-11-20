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
        let caller = caller::resolve_checked(&request, &self.0).await?;
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

        // A revoked proxy's grants are refused at once, from the database.
        if db::revoked_components(&self.0.db)
            .await
            .map_err(|e| internal("checking revoked components", e))?
            .contains(&verified.proxy.id)
        {
            return Err(Status::permission_denied("the proxy has been revoked"));
        }

        // The control plane's own, current view of policy has the last word.
        let loaded = self.0.policy.current();
        // Roles from approved access requests count, and the session's
        // certificate never outlives the grant it depends on (ADR-0025).
        let effective = crate::access::effective_roles_now(
            &self.0,
            &verified.user.username,
            &verified.user.roles,
            &grant.resource,
        )
        .await
        .map_err(|e| internal("reading access grants", e))?;
        let decision = loaded.policy.evaluate(&AccessRequest {
            roles: &effective.roles,
            resource: &grant.resource,
            principal: Principal::SshLogin(grant.principal.clone()),
        });
        if !decision.is_allowed() {
            return Err(Status::permission_denied(format!(
                "policy no longer allows this session: {decision:?}"
            )));
        }
        // Locks are read from the database, so a lock takes effect here at once.
        if db::is_locked(&self.0.db, &verified.user.username)
            .await
            .map_err(|e| internal("checking locks", e))?
        {
            return Err(Status::permission_denied("user locked"));
        }
        if db::is_login_revoked(&self.0.db, &verified.user.login_id)
            .await
            .map_err(|e| internal("checking ended logins", e))?
        {
            return Err(Status::permission_denied("logged out"));
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

        // A certificate issued under a grant ends no later than the grant.
        let user_cert_ttl = match effective.earliest_expiry_unix {
            Some(deadline) => {
                let left = deadline - now.unix_timestamp();
                if left <= 0 {
                    return Err(Status::permission_denied("the access grant has ended"));
                }
                USER_CERT_TTL.min(Duration::from_secs(left.unsigned_abs()))
            }
            None => USER_CERT_TTL,
        };
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
                ttl: user_cert_ttl,
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

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use ssh_key::{Algorithm, EcdsaCurve, PrivateKey};
    use tonic::Code;

    use super::parse_key;

    /// An OpenSSH public key line built from its wire fields (RFC 4253
    /// §6.6), so key types the CA must refuse can be written without a key
    /// generator for them.
    fn openssh_line(algorithm: &str, fields: &[&[u8]]) -> String {
        let mut blob = Vec::new();
        for field in std::iter::once(algorithm.as_bytes()).chain(fields.iter().copied()) {
            blob.extend_from_slice(&u32::try_from(field.len()).expect("len").to_be_bytes());
            blob.extend_from_slice(field);
        }
        format!(
            "{algorithm} {} test",
            base64::engine::general_purpose::STANDARD.encode(blob)
        )
    }

    /// A positive mpint of `bytes` bytes with the high bit set (so it needs
    /// the leading zero), odd, as an RSA modulus or DSA prime would be.
    fn mpint(bytes: usize) -> Vec<u8> {
        let mut v = vec![0x00, 0xc5];
        v.extend(std::iter::repeat_n(0x5a, bytes - 2));
        v.push(0x01);
        v
    }

    fn refusal(what: &str, line: &str) -> String {
        match parse_key(what, line) {
            Err(status) => {
                assert_eq!(status.code(), Code::InvalidArgument, "{line}");
                status.message().to_owned()
            }
            Ok(key) => panic!("{what}: accepted a {} key", key.algorithm()),
        }
    }

    /// Session certificates are only signed for Ed25519 and ECDSA keys.
    #[test]
    fn ed25519_and_ecdsa_keys_are_accepted() {
        let ed = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
        assert_eq!(
            parse_key("user_public_key", ed)
                .expect("ed25519")
                .algorithm(),
            Algorithm::Ed25519
        );
        let ecdsa = Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        };
        let line = PrivateKey::random(&mut rand::rng(), ecdsa.clone())
            .expect("key")
            .public_key()
            .to_openssh()
            .expect("openssh");
        assert_eq!(
            parse_key("user_public_key", &line)
                .expect("ecdsa")
                .algorithm(),
            ecdsa
        );
    }

    /// A worker asking for a certificate over an RSA or DSA key is refused by
    /// algorithm, not signed: the CA never vouches for a key type Limen
    /// doesn't issue for (SHA-1 `ssh-rsa` signatures, 1024-bit DSA).
    #[test]
    fn rsa_and_dsa_keys_are_refused() {
        let e: &[u8] = &[0x01, 0x00, 0x01];
        let rsa = openssh_line("ssh-rsa", &[e, &mpint(257)]);
        let why = refusal("user_public_key", &rsa);
        assert!(
            why.starts_with("user_public_key: unsupported algorithm"),
            "{why}"
        );

        let (p, q, g, y) = (mpint(129), mpint(21), mpint(128), mpint(128));
        let dsa = openssh_line("ssh-dss", &[&p, &q, &g, &y]);
        let why = refusal("host_public_key", &dsa);
        assert!(
            why.starts_with("host_public_key: unsupported algorithm"),
            "{why}"
        );
    }

    /// Text that isn't an OpenSSH public key is refused with the field named.
    #[test]
    fn malformed_keys_are_refused() {
        for bad in [
            "",
            "ssh-ed25519",
            "ssh-ed25519 not-base64!",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
        ] {
            let why = refusal("user_public_key", bad);
            assert!(why.starts_with("user_public_key: "), "{bad:?}: {why}");
        }
    }
}
