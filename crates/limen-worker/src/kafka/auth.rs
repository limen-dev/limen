//! SASL toward the cluster (ADR-0037): the worker logs in; the person never
//! sees the credential. `PLAIN`, `SCRAM-SHA-256` and `SCRAM-SHA-512`
//! (RFC 5802, RFC 7677), and `AWS_MSK_IAM` for Amazon MSK. The message
//! building is pure, so it is tested against fixtures.
//!
//! Passwords are used as given: `SASLprep` is not applied, so a password with
//! non-ASCII characters must be created the same way on the cluster.
//!
//! `AWS_MSK_IAM` is written from Amazon's published format of the client
//! payload (a `SigV4` presigned `kafka-cluster:Connect` request, as JSON). It
//! is *unverified against a real MSK cluster*.

use std::num::NonZeroU32;

use aws_lc_rs::{digest, hmac, pbkdf2};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use limen_core::secret::Secret;
use serde_json::{Map, Value, json};
use time::OffsetDateTime;

use crate::db::sigv4::{self, Credentials, EMPTY_PAYLOAD_SHA256, Target};

/// Most iterations a server may ask for. Kafka defaults to 4096.
const MAX_ITERATIONS: u32 = 1_000_000;
/// MSK IAM payloads are valid for 15 minutes.
const IAM_LIFETIME_SECS: u32 = 900;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("malformed SCRAM message")]
    Malformed,
    #[error("the server's nonce doesn't extend ours")]
    Nonce,
    #[error("the server asked for an unreasonable iteration count")]
    Iterations,
    #[error("the server's signature is wrong")]
    ServerSignature,
    #[error("the server reported: {0}")]
    Server(String),
}

/// `PLAIN`: `authzid NUL user NUL password`, with no authorization id.
#[must_use]
pub fn plain(user: &str, password: &str) -> Vec<u8> {
    let mut out = vec![0];
    out.extend_from_slice(user.as_bytes());
    out.push(0);
    out.extend_from_slice(password.as_bytes());
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScramHash {
    Sha256,
    Sha512,
}

impl ScramHash {
    /// The SASL mechanism name.
    #[must_use]
    pub fn mechanism(self) -> &'static str {
        match self {
            ScramHash::Sha256 => "SCRAM-SHA-256",
            ScramHash::Sha512 => "SCRAM-SHA-512",
        }
    }

    fn len(self) -> usize {
        match self {
            ScramHash::Sha256 => 32,
            ScramHash::Sha512 => 64,
        }
    }

    fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        let alg = match self {
            ScramHash::Sha256 => hmac::HMAC_SHA256,
            ScramHash::Sha512 => hmac::HMAC_SHA512,
        };
        hmac::sign(&hmac::Key::new(alg, key), data)
            .as_ref()
            .to_vec()
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        let alg = match self {
            ScramHash::Sha256 => &digest::SHA256,
            ScramHash::Sha512 => &digest::SHA512,
        };
        digest::digest(alg, data).as_ref().to_vec()
    }

    fn pbkdf2(self, password: &[u8], salt: &[u8], rounds: NonZeroU32) -> Vec<u8> {
        let alg = match self {
            ScramHash::Sha256 => pbkdf2::PBKDF2_HMAC_SHA256,
            ScramHash::Sha512 => pbkdf2::PBKDF2_HMAC_SHA512,
        };
        let mut out = vec![0u8; self.len()];
        pbkdf2::derive(alg, rounds, salt, password, &mut out);
        out
    }
}

/// A SCRAM client (no channel binding).
pub struct Scram {
    hash: ScramHash,
    password: Secret<String>,
    first_bare: String,
    expected_server_signature: Option<Vec<u8>>,
}

impl std::fmt::Debug for Scram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scram")
            .field("hash", &self.hash)
            .finish_non_exhaustive()
    }
}

/// `=` and `,` in a user name are written `=3D` and `=2C`.
fn escape(user: &str) -> String {
    user.replace('=', "=3D").replace(',', "=2C")
}

impl Scram {
    #[must_use]
    pub fn new(hash: ScramHash, user: &str, password: Secret<String>, nonce: &str) -> Self {
        Self {
            hash,
            password,
            first_bare: format!("n={},r={nonce}", escape(user)),
            expected_server_signature: None,
        }
    }

    /// A fresh client nonce.
    #[must_use]
    pub fn new_nonce() -> String {
        B64.encode(rand::random::<[u8; 18]>())
    }

    /// The client-first message.
    #[must_use]
    pub fn first(&self) -> Vec<u8> {
        format!("n,,{}", self.first_bare).into_bytes()
    }

    /// The client-final message, from the server-first one.
    ///
    /// # Errors
    /// If the message is malformed, the nonce isn't ours extended, or the
    /// iteration count is absurd.
    pub fn respond(&mut self, server_first: &[u8]) -> Result<Vec<u8>, AuthError> {
        let server_first = std::str::from_utf8(server_first).map_err(|_| AuthError::Malformed)?;
        if let Some(e) = server_first.strip_prefix("e=") {
            return Err(AuthError::Server(e.to_owned()));
        }
        let (mut nonce, mut salt, mut iterations) = (None, None, None);
        for part in server_first.split(',') {
            match part.split_once('=') {
                Some(("r", v)) => nonce = Some(v),
                Some(("s", v)) => salt = Some(B64.decode(v).map_err(|_| AuthError::Malformed)?),
                Some(("i", v)) => {
                    iterations = Some(v.parse::<u32>().map_err(|_| AuthError::Malformed)?);
                }
                _ => {}
            }
        }
        let (Some(nonce), Some(salt), Some(iterations)) = (nonce, salt, iterations) else {
            return Err(AuthError::Malformed);
        };
        let ours = self
            .first_bare
            .split(',')
            .find_map(|p| p.strip_prefix("r="))
            .ok_or(AuthError::Malformed)?;
        if !nonce.starts_with(ours) || nonce.len() == ours.len() {
            return Err(AuthError::Nonce);
        }
        if iterations == 0 || iterations > MAX_ITERATIONS {
            return Err(AuthError::Iterations);
        }
        let rounds = NonZeroU32::new(iterations).ok_or(AuthError::Iterations)?;
        let salted = self
            .hash
            .pbkdf2(self.password.expose().as_bytes(), &salt, rounds);
        let client_key = self.hash.hmac(&salted, b"Client Key");
        let stored_key = self.hash.digest(&client_key);
        let without_proof = format!("c=biws,r={nonce}");
        let auth_message = format!("{},{server_first},{without_proof}", self.first_bare);
        let client_signature = self.hash.hmac(&stored_key, auth_message.as_bytes());
        let proof: Vec<u8> = client_key
            .iter()
            .zip(&client_signature)
            .map(|(a, b)| a ^ b)
            .collect();
        let server_key = self.hash.hmac(&salted, b"Server Key");
        self.expected_server_signature = Some(self.hash.hmac(&server_key, auth_message.as_bytes()));
        Ok(format!("{without_proof},p={}", B64.encode(proof)).into_bytes())
    }

    /// Check the server-final message.
    ///
    /// # Errors
    /// If it reports an error or its signature isn't the one we computed.
    pub fn verify(&self, server_final: &[u8]) -> Result<(), AuthError> {
        let text = std::str::from_utf8(server_final).map_err(|_| AuthError::Malformed)?;
        if let Some(e) = text.strip_prefix("e=") {
            return Err(AuthError::Server(e.to_owned()));
        }
        let v = text.strip_prefix("v=").ok_or(AuthError::Malformed)?;
        let got = B64.decode(v.trim()).map_err(|_| AuthError::Malformed)?;
        let expected = self
            .expected_server_signature
            .as_ref()
            .ok_or(AuthError::Malformed)?;
        if subtle::ConstantTimeEq::ct_eq(&got[..], &expected[..]).into() {
            Ok(())
        } else {
            Err(AuthError::ServerSignature)
        }
    }
}

/// The region in an MSK broker host name (`b-1.name.abc.c2.kafka.eu-west-1.amazonaws.com`).
#[must_use]
pub fn msk_region(host: &str) -> Option<&str> {
    let rest = host.strip_suffix(".amazonaws.com")?;
    let (_, tail) = rest.rsplit_once(".kafka")?;
    // `kafka.eu-west-1` or `kafka-serverless.eu-west-1`
    let region = tail.rsplit('.').next()?;
    (!region.is_empty() && region.contains('-')).then_some(region)
}

/// The `AWS_MSK_IAM` client payload: a presigned `kafka-cluster:Connect`
/// request for `host`, written as the JSON the broker expects.
#[must_use]
pub fn msk_iam_payload(
    creds: &Credentials,
    region: &str,
    host: &str,
    now: OffsetDateTime,
) -> Secret<Vec<u8>> {
    let query = sigv4::presign_query(
        &Target {
            method: "GET",
            host,
            path: "/",
            region,
            service: "kafka-cluster",
        },
        &[("Action".into(), "kafka-cluster:Connect".into())],
        creds,
        IAM_LIFETIME_SECS,
        EMPTY_PAYLOAD_SHA256,
        now,
    );
    let mut map = Map::new();
    map.insert("version".into(), json!("2020_10_22"));
    map.insert("host".into(), json!(host));
    map.insert("user-agent".into(), json!("limen"));
    map.insert("action".into(), json!("kafka-cluster:Connect"));
    for pair in query.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        let key = k.to_ascii_lowercase();
        if key == "action" {
            continue;
        }
        map.insert(key, Value::String(percent_decode(v)));
    }
    Secret::new(serde_json::to_vec(&Value::Object(map)).unwrap_or_default())
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(byte);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(s: &str) -> Secret<String> {
        Secret::new(s.to_owned())
    }

    // RFC 7677 section 3.
    #[test]
    fn scram_sha_256_matches_the_rfc_7677_example() {
        let mut c = Scram::new(
            ScramHash::Sha256,
            "user",
            secret("pencil"),
            "rOprNGfwEbeRWgbNEkqO",
        );
        assert_eq!(c.first(), b"n,,n=user,r=rOprNGfwEbeRWgbNEkqO");
        let fin = c
            .respond(b"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")
            .expect("response");
        assert_eq!(
            String::from_utf8(fin).expect("utf8"),
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );
        c.verify(b"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")
            .expect("server signature");
        assert_eq!(
            c.verify(b"v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
            Err(AuthError::ServerSignature)
        );
    }

    // Expected values computed with Python's hashlib (pbkdf2_hmac, hmac), which
    // also reproduces the RFC 7677 example above.
    #[test]
    fn scram_sha_512_matches_an_independent_implementation() {
        let mut c = Scram::new(
            ScramHash::Sha512,
            "limen-user",
            secret("hunter2"),
            "clientnonce123",
        );
        let fin = c
            .respond(b"r=clientnonce123SERVERPART,s=c2FsdHNhbHQ=,i=4096")
            .expect("response");
        assert_eq!(
            String::from_utf8(fin).expect("utf8"),
            "c=biws,r=clientnonce123SERVERPART,p=AUi5vbVleteIwu+3UG5c/O9RC3M4Zphsjtow031IPylvKl9+wHEoDI+tRks5mt7a/1poJklxmjilpMPQnBdQPw=="
        );
        c.verify(b"v=WLo8vtjengGh8d/76NB2Mm7FUxjZp1DYCFL7WwHiL451Udlh7ZtyitsUnt368nMSMe7Q6k2PkyCcn+4kbz3dwg==")
            .expect("server signature");
    }

    #[test]
    fn user_names_with_equals_and_commas_are_escaped() {
        let mut c = Scram::new(ScramHash::Sha256, "a=b,c", secret("p"), "n1");
        assert_eq!(c.first(), b"n,,n=a=3Db=2Cc,r=n1");
        // The proof is over the escaped name (`n=a=3Db=2Cc`); Python computes the same value.
        let fin = c.respond(b"r=n1S,s=c2FsdA==,i=10").expect("response");
        assert_eq!(
            String::from_utf8(fin).expect("utf8"),
            "c=biws,r=n1S,p=WqJqm7HDKiYjSexacgF+IEInagQ3IVDvO2IJitcq88A="
        );
    }

    #[test]
    fn a_bad_server_is_refused() {
        let mut c = Scram::new(ScramHash::Sha256, "u", secret("p"), "abc");
        assert_eq!(c.respond(b"r=zzz,s=c2FsdA==,i=10"), Err(AuthError::Nonce));
        assert_eq!(
            c.respond(b"r=abc,s=c2FsdA==,i=10"),
            Err(AuthError::Nonce),
            "must extend"
        );
        assert_eq!(
            c.respond(b"r=abcd,s=c2FsdA==,i=0"),
            Err(AuthError::Iterations)
        );
        assert_eq!(
            c.respond(b"r=abcd,s=c2FsdA==,i=99999999"),
            Err(AuthError::Iterations)
        );
        assert_eq!(c.respond(b"r=abcd"), Err(AuthError::Malformed));
        assert_eq!(
            c.respond(b"e=unknown-user"),
            Err(AuthError::Server("unknown-user".into()))
        );
        assert_eq!(c.verify(b"nonsense"), Err(AuthError::Malformed));
    }

    #[test]
    fn plain_is_nul_separated() {
        assert_eq!(plain("bob", "pw"), b"\0bob\0pw");
    }

    #[test]
    fn debug_never_shows_the_password() {
        let c = Scram::new(ScramHash::Sha256, "u", secret("hunter2"), "n");
        assert!(!format!("{c:?}").contains("hunter2"));
    }

    #[test]
    fn the_region_is_read_from_the_broker_name() {
        assert_eq!(
            msk_region("b-1.payments.abc123.c2.kafka.eu-west-1.amazonaws.com"),
            Some("eu-west-1")
        );
        assert_eq!(
            msk_region("boot-abc.c1.kafka-serverless.us-east-1.amazonaws.com"),
            Some("us-east-1")
        );
        assert_eq!(msk_region("kafka-1"), None);
        assert_eq!(msk_region("example.com"), None);
    }

    #[test]
    fn the_msk_payload_has_the_documented_fields_and_a_signature() {
        let creds = Credentials {
            access_key: "AKIDEXAMPLE".into(),
            secret_key: secret("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
            session_token: Some(secret("token/with+chars=")),
        };
        let now = OffsetDateTime::from_unix_timestamp(1_440_938_160).expect("time");
        let host = "b-1.payments.abc123.c2.kafka.eu-west-1.amazonaws.com";
        let payload = msk_iam_payload(&creds, "eu-west-1", host, now);
        let v: Value = serde_json::from_slice(payload.expose()).expect("json");
        assert_eq!(v["version"], "2020_10_22");
        assert_eq!(v["host"], host);
        assert_eq!(v["action"], "kafka-cluster:Connect");
        assert_eq!(v["x-amz-algorithm"], "AWS4-HMAC-SHA256");
        assert_eq!(
            v["x-amz-credential"],
            "AKIDEXAMPLE/20150830/eu-west-1/kafka-cluster/aws4_request"
        );
        assert_eq!(v["x-amz-date"], "20150830T123600Z");
        assert_eq!(v["x-amz-expires"], "900");
        assert_eq!(v["x-amz-signedheaders"], "host");
        assert_eq!(
            v["x-amz-security-token"], "token/with+chars=",
            "decoded once"
        );
        let sig = v["x-amz-signature"].as_str().expect("signature");
        assert_eq!(sig.len(), 64);
        assert!(sig.bytes().all(|b| b.is_ascii_hexdigit()));
        // The signature is deterministic for fixed inputs.
        let again = msk_iam_payload(&creds, "eu-west-1", host, now);
        assert_eq!(payload.expose(), again.expose());
    }
}
