//! Read-only access to the audit bucket for `limen audit verify` (ADR-0009
//! amendment). Limen decides who may and records that it did; it does not run
//! the check or vouch for the result, so the caller reads the bucket and
//! verifies the chain itself against the CA it already trusts.

use limen_audit::{Context, EventKind};
use limen_proto::v1::VerifierAccessResponse;
use serde_json::json;
use tonic::Status;

use crate::state::AppState;

/// AWS accepts 15 minutes to 12 hours for an assumed role.
const MIN_TTL_SECS: u64 = 900;
const MAX_TTL_SECS: u64 = 43_200;

/// A session name AWS accepts: `[\w+=,.@-]`, at most 64 characters.
fn session_name(username: &str) -> String {
    let safe: String = username
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "+=,.@-_".contains(c) {
                c
            } else {
                '-'
            }
        })
        .collect();
    format!("limen-verify-{safe}").chars().take(64).collect()
}

/// Issue credentials for `username`, who has already been checked to be an
/// admin or an auditor. The grant is audited first: no event, no credentials.
pub async fn grant(state: &AppState, username: &str) -> Result<VerifierAccessResponse, Status> {
    let cfg = &state.config;
    let Some(bucket) = cfg.audit_s3_bucket.clone() else {
        return Err(Status::failed_precondition(
            "this control plane has no audit bucket to verify",
        ));
    };
    let role = cfg.audit_verifier_role_arn.clone();
    let fixed = cfg
        .audit_verifier_access_key_id
        .clone()
        .zip(cfg.audit_verifier_secret_access_key.clone());
    // A fixed key never expires, so one grant would leak read access for good.
    // It exists for S3-compatible stores without STS, in development only.
    if role.is_none() && fixed.is_some() && cfg.environment != "dev" {
        return Err(Status::failed_precondition(
            "a fixed verifier key is only allowed with --environment dev; use a verifier role",
        ));
    }
    if role.is_none() && fixed.is_none() {
        return Err(Status::failed_precondition(
            "verification access is not set up: give the control plane a verifier role (LIMEN_AUDIT_VERIFIER_ROLE_ARN)",
        ));
    }

    state
        .audit
        .emit(
            EventKind::AuditVerifyAccess,
            Context {
                user: Some(username.to_owned()),
                session_id: None,
            },
            json!({
                "bucket": bucket,
                "mode": if role.is_some() { "role" } else { "static" },
            }),
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "audit unavailable; refusing verifier access");
            Status::unavailable("audit unavailable")
        })?;
    metrics::counter!("limen_audit_verifier_access_total").increment(1);

    let shared = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .load()
        .await;
    let region = shared
        .region()
        .map_or_else(|| "us-east-1".to_owned(), ToString::to_string);
    let mut out = VerifierAccessResponse {
        bucket,
        prefix: cfg.audit_s3_prefix.clone(),
        endpoint: cfg
            .audit_verifier_s3_endpoint
            .clone()
            .or_else(|| cfg.audit_s3_endpoint.clone())
            .unwrap_or_default(),
        path_style: cfg.audit_s3_path_style,
        region,
        ..VerifierAccessResponse::default()
    };

    if let Some(arn) = role {
        let ttl = cfg
            .audit_verifier_ttl
            .as_secs()
            .clamp(MIN_TTL_SECS, MAX_TTL_SECS);
        let assumed = aws_sdk_sts::Client::new(&shared)
            .assume_role()
            .role_arn(arn)
            .role_session_name(session_name(username))
            .duration_seconds(i32::try_from(ttl).unwrap_or(900))
            .send()
            .await
            .map_err(|e| {
                tracing::error!(
                    error = %aws_sdk_sts::error::DisplayErrorContext(&e),
                    "could not assume the verifier role"
                );
                Status::unavailable("could not get verifier credentials")
            })?;
        let c = assumed
            .credentials()
            .ok_or_else(|| Status::unavailable("could not get verifier credentials"))?;
        c.access_key_id().clone_into(&mut out.access_key_id);
        c.secret_access_key().clone_into(&mut out.secret_access_key);
        c.session_token().clone_into(&mut out.session_token);
        out.expires_unix = c.expiration().secs();
    } else if let Some((key, secret)) = fixed {
        out.access_key_id = key;
        out.secret_access_key.clone_from(secret.expose());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::session_name;

    #[test]
    fn session_names_are_what_aws_accepts() {
        assert_eq!(
            session_name("alice@example.com"),
            "limen-verify-alice@example.com"
        );
        assert_eq!(session_name("a b/c"), "limen-verify-a-b-c");
        assert!(session_name(&"x".repeat(200)).len() <= 64);
    }
}
