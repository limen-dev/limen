//! Verifying workload identity tokens for bots (ADR-0019).
//!
//! A bot presents the OIDC token its CI platform issued for the job. The
//! control plane only looks at issuers that policy names (so a token can't
//! make it fetch keys from anywhere else), verifies the signature, audience,
//! and expiry, requires a recent `iat`, and hands back the claims for policy
//! to match. Whether the claims are *enough* is the policy's decision.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use openidconnect::core::{
    CoreGenderClaim, CoreIdTokenVerifier, CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
};
use openidconnect::{AdditionalClaims, ClientId, IdToken, IssuerUrl};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::http_client::HttpClient;
use crate::oidc::{KeyCache, OidcError};

/// Every claim the standard set doesn't cover, such as `repository` and `ref`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BotClaims {
    #[serde(flatten)]
    pub all: BTreeMap<String, serde_json::Value>,
}

impl AdditionalClaims for BotClaims {}

type BotIdToken =
    IdToken<BotClaims, CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm>;

/// A verified workload identity token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BotToken {
    pub issuer: String,
    pub subject: String,
    /// String, boolean, and number claims as text, plus `sub` and `iss`.
    /// Policy matches against these.
    pub claims: BTreeMap<String, String>,
    pub expires_at: time::OffsetDateTime,
    /// What to record so the same token can't log in twice...
    pub replay_key: Vec<u8>,
    /// ...and until when: the later of the token's `exp` and the end of the
    /// window in which its `iat` still lets it log in. Forgetting it earlier
    /// would let a token that expires soon be used again.
    pub replay_until: time::OffsetDateTime,
}

#[derive(Debug, thiserror::Error)]
pub enum BotTokenError {
    /// Not a token we may accept: wrong shape, issuer, signature, audience,
    /// age, or expiry. The message is for logs, not for the caller.
    #[error("invalid bot token: {0}")]
    Invalid(String),
    #[error("identity provider unavailable: {0}")]
    Unavailable(String),
}

impl From<OidcError> for BotTokenError {
    fn from(e: OidcError) -> Self {
        match e {
            OidcError::Unavailable(m) => BotTokenError::Unavailable(m),
            OidcError::Invalid(m) => BotTokenError::Invalid(m),
        }
    }
}

/// Clock skew tolerated on `iat`.
const SKEW: Duration = Duration::from_secs(60);
const MAX_TOKEN_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone)]
pub struct BotVerifier {
    audience: String,
    max_age: Duration,
    allow_insecure: bool,
    http: HttpClient,
    /// Key caches by issuer, without a trailing slash, so `https://x` and
    /// `https://x/` share one.
    caches: Arc<Mutex<HashMap<String, KeyCache>>>,
}

impl BotVerifier {
    #[must_use]
    pub fn new(audience: &str, max_age: Duration, allow_insecure: bool, http: HttpClient) -> Self {
        Self {
            audience: audience.to_owned(),
            max_age,
            allow_insecure,
            http,
            caches: Arc::default(),
        }
    }

    /// The audience tokens must be minted for. The CLI asks for it.
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Verify `raw`, which must come from one of `allowed` issuers (without a
    /// trailing slash). Nothing is fetched for any other issuer.
    pub async fn verify(
        &self,
        allowed: &BTreeSet<String>,
        raw: &str,
    ) -> Result<BotToken, BotTokenError> {
        if raw.len() > MAX_TOKEN_BYTES {
            return Err(BotTokenError::Invalid("token too large".into()));
        }
        let issuer = unverified_issuer(raw)
            .ok_or_else(|| BotTokenError::Invalid("no readable iss claim".into()))?;
        let normalized = issuer.trim_end_matches('/');
        if !allowed.contains(normalized) {
            return Err(BotTokenError::Invalid(format!(
                "issuer {normalized:?} is not named by any bot"
            )));
        }
        if !normalized.starts_with("https://") && !self.allow_insecure {
            return Err(BotTokenError::Invalid(format!(
                "issuer {normalized:?} is not https"
            )));
        }
        let cache = self.cache_for(normalized)?;

        let token: BotIdToken = raw
            .parse()
            .map_err(|e| BotTokenError::Invalid(format!("malformed: {e}")))?;
        let mut last_err = String::new();
        for force in [false, true] {
            let jwks = cache.current_keys(force).await?;
            let verifier = CoreIdTokenVerifier::new_public_client(
                ClientId::new(self.audience.clone()),
                IssuerUrl::new(issuer.clone())
                    .map_err(|e| BotTokenError::Invalid(format!("issuer: {e}")))?,
                jwks,
            )
            .set_allowed_algs([
                CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
                CoreJwsSigningAlgorithm::EcdsaP256Sha256,
                CoreJwsSigningAlgorithm::EdDsa,
            ]);
            // Workload tokens carry no nonce; replay is prevented by the
            // caller recording `replay_key`.
            match token.claims(&verifier, |_: Option<&openidconnect::Nonce>| Ok(())) {
                Ok(claims) => return self.accept(&issuer, claims, raw),
                Err(e) => last_err = e.to_string(),
            }
        }
        Err(BotTokenError::Invalid(last_err))
    }

    /// How many issuers have a key cache (for tests).
    #[must_use]
    pub fn cached_issuers(&self) -> usize {
        self.caches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    fn cache_for(&self, issuer: &str) -> Result<KeyCache, BotTokenError> {
        let mut caches = self
            .caches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(c) = caches.get(issuer) {
            return Ok(c.clone());
        }
        let c = KeyCache::new(issuer, None, self.http.clone())?.same_origin_keys();
        caches.insert(issuer.to_owned(), c.clone());
        Ok(c)
    }

    fn accept(
        &self,
        issuer: &str,
        claims: &openidconnect::IdTokenClaims<BotClaims, CoreGenderClaim>,
        raw: &str,
    ) -> Result<BotToken, BotTokenError> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let minted = claims.issue_time().timestamp();
        let skew = i64::try_from(SKEW.as_secs()).unwrap_or(60);
        let max_age = i64::try_from(self.max_age.as_secs()).unwrap_or(900);
        if minted > now + skew {
            return Err(BotTokenError::Invalid("issued in the future".into()));
        }
        if now - minted > max_age + skew {
            return Err(BotTokenError::Invalid(format!(
                "issued {}s ago; bots must log in within {max_age}s of the token being minted",
                now - minted
            )));
        }
        let expires_at = time::OffsetDateTime::from_unix_timestamp(claims.expiration().timestamp())
            .map_err(|e| BotTokenError::Invalid(format!("exp: {e}")))?;

        let mut text: BTreeMap<String, String> = claims
            .additional_claims()
            .all
            .iter()
            .filter_map(|(k, v)| claim_text(v).map(|t| (k.clone(), t)))
            .collect();
        let subject = claims.subject().to_string();
        text.insert("sub".into(), subject.clone());
        text.insert("iss".into(), issuer.trim_end_matches('/').to_owned());

        // GitHub and GitLab put a `jti` in every token. Without one, the
        // token's own hash does the same job.
        let replay_until = expires_at.max(
            time::OffsetDateTime::from_unix_timestamp(minted + max_age + skew)
                .map_err(|e| BotTokenError::Invalid(format!("iat: {e}")))?,
        );
        let replay_key = replay_key(issuer, text.get("jti").map(String::as_str), raw);
        Ok(BotToken {
            issuer: issuer.trim_end_matches('/').to_owned(),
            subject,
            claims: text,
            expires_at,
            replay_key,
            replay_until,
        })
    }
}

/// What identifies one token for the purpose of "one login per token".
///
/// GitHub and GitLab put a `jti` in every token. Without one, the token's
/// *signed part* (`header.payload`) does the same job. The signature must not
/// be part of it: an ECDSA signature has a second valid form, and a lenient
/// base64 decoder may accept other spellings of the same one, so a signature
/// could be altered without invalidating the token and the whole-token hash
/// would change.
fn replay_key(issuer: &str, jti: Option<&str>, raw: &str) -> Vec<u8> {
    match jti {
        Some(jti) => Sha256::digest(format!("bot-jti\0{issuer}\0{jti}").as_bytes()).to_vec(),
        None => {
            let signed = raw
                .rsplit_once('.')
                .map_or(raw, |(signed, _signature)| signed);
            Sha256::digest(format!("bot-signed\0{signed}").as_bytes()).to_vec()
        }
    }
}

/// A claim as text, for exact matching. Arrays and objects never match.
fn claim_text(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// The `iss` claim of a JWT, read **without** verifying anything. It is only
/// used to choose which allow-listed issuer's keys to verify with.
fn unverified_issuer(raw: &str) -> Option<String> {
    let payload = raw.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value.get("iss")?.as_str().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt(payload: &str) -> String {
        let enc = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s);
        format!("{}.{}.sig", enc(r#"{"alg":"none"}"#), enc(payload))
    }

    #[test]
    fn reads_the_issuer_without_trusting_it() {
        assert_eq!(
            unverified_issuer(&jwt(
                r#"{"iss":"https://token.actions.githubusercontent.com"}"#
            ))
            .as_deref(),
            Some("https://token.actions.githubusercontent.com")
        );
        assert_eq!(unverified_issuer(&jwt(r#"{"sub":"x"}"#)), None);
        assert_eq!(unverified_issuer(&jwt(r#"{"iss":7}"#)), None);
        assert_eq!(unverified_issuer("not-a-jwt"), None);
        assert_eq!(unverified_issuer("a.!!!.c"), None);
    }

    #[test]
    fn a_token_without_a_jti_is_identified_by_what_was_signed_not_by_its_signature() {
        let signed = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2kifQ";
        let original = format!("{signed}.c2lnbmF0dXJl");
        // The same token with the signature's other valid form (or another spelling).
        let altered = format!("{signed}.b3RoZXItZm9ybQ");
        let key = |t: &str| replay_key("https://i", None, t);
        assert_eq!(
            key(&original),
            key(&altered),
            "a changed signature is the same token"
        );
        assert_ne!(
            key(&original),
            key("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL290aGVyIn0.c2lnbmF0dXJl"),
            "different content is a different token"
        );
        // With a jti, that and the issuer decide, whatever else changes.
        assert_eq!(
            replay_key("https://i", Some("abc"), &original),
            replay_key("https://i", Some("abc"), "anything.at.all")
        );
        assert_ne!(
            replay_key("https://i", Some("abc"), &original),
            replay_key("https://other", Some("abc"), &original),
            "the same jti from another issuer is another token"
        );
    }

    #[test]
    fn only_scalars_are_matchable_claims() {
        use serde_json::json;
        assert_eq!(claim_text(&json!("a/b")).as_deref(), Some("a/b"));
        assert_eq!(claim_text(&json!(true)).as_deref(), Some("true"));
        assert_eq!(claim_text(&json!(42)).as_deref(), Some("42"));
        assert_eq!(claim_text(&json!(["x"])), None);
        assert_eq!(claim_text(&json!({"a": 1})), None);
        assert_eq!(claim_text(&json!(null)), None);
    }

    #[tokio::test]
    async fn an_issuer_policy_doesnt_name_is_never_contacted() {
        let verifier = BotVerifier::new(
            "limen",
            Duration::from_mins(15),
            false,
            HttpClient::new().expect("client"),
        );
        let allowed: BTreeSet<String> =
            ["https://token.actions.githubusercontent.com".to_owned()].into();
        let err = verifier
            .verify(&allowed, &jwt(r#"{"iss":"https://evil.example.com"}"#))
            .await
            .expect_err("rejected");
        assert!(err.to_string().contains("not named by any bot"), "{err}");
        let err = verifier
            .verify(&allowed, &"x".repeat(MAX_TOKEN_BYTES + 1))
            .await
            .expect_err("rejected");
        assert!(err.to_string().contains("too large"));
    }

    #[tokio::test]
    async fn plain_http_issuers_need_the_development_switch() {
        let http = HttpClient::new().expect("client");
        let allowed: BTreeSet<String> = ["http://ci.internal:8130".to_owned()].into();
        let token = jwt(r#"{"iss":"http://ci.internal:8130"}"#);
        let strict = BotVerifier::new("limen", Duration::from_mins(15), false, http);
        let err = strict.verify(&allowed, &token).await.expect_err("rejected");
        assert!(err.to_string().contains("not https"), "{err}");
    }
}
