//! SCRAM-SHA-256 client (RFC 5802, RFC 7677), as PostgreSQL uses it. The
//! worker authenticates to the target with it; the user never sees a password.
//!
//! Passwords are used as given. `SASLprep` is not applied, so a password with
//! non-ASCII characters must be created the same way on the server.

use std::num::NonZeroU32;

use aws_lc_rs::{digest, hmac, pbkdf2};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

/// Most iterations a server may ask for. PostgreSQL defaults to 4096.
const MAX_ITERATIONS: u32 = 5_000_000;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ScramError {
    #[error("malformed SCRAM message")]
    Malformed,
    #[error("the server's nonce doesn't extend ours")]
    Nonce,
    #[error("the server asked for an unreasonable iteration count")]
    Iterations,
}

/// A fresh client nonce.
#[must_use]
pub fn new_nonce() -> String {
    B64.encode(rand::random::<[u8; 18]>())
}

/// The client-first message without the GS2 header (kept for the signature).
#[must_use]
pub fn client_first_bare(nonce: &str) -> String {
    // PostgreSQL ignores the user name here (it comes from the startup message).
    format!("n=,r={nonce}")
}

/// The full client-first message, with the GS2 header (no channel binding).
#[must_use]
pub fn client_first(bare: &str) -> String {
    format!("n,,{bare}")
}

/// What the client needs to check the server's final message.
#[derive(Debug)]
pub struct Proof {
    pub client_final: String,
    expected_server_signature: Vec<u8>,
}

impl Proof {
    /// Check the `v=` value of the server-final message.
    #[must_use]
    pub fn verify_server_final(&self, server_final: &str) -> bool {
        let Some(v) = server_final.strip_prefix("v=") else {
            return false;
        };
        B64.decode(v.trim()).is_ok_and(|got| {
            subtle::ConstantTimeEq::ct_eq(&got[..], &self.expected_server_signature[..]).into()
        })
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&key, data).as_ref().to_vec()
}

/// Build the client-final message from the server-first message.
pub fn client_final(
    password: &str,
    client_first_bare: &str,
    server_first: &str,
) -> Result<Proof, ScramError> {
    let (mut nonce, mut salt, mut iterations) = (None, None, None);
    for part in server_first.split(',') {
        match part.split_once('=') {
            Some(("r", v)) => nonce = Some(v),
            Some(("s", v)) => salt = Some(B64.decode(v).map_err(|_| ScramError::Malformed)?),
            Some(("i", v)) => {
                iterations = Some(v.parse::<u32>().map_err(|_| ScramError::Malformed)?);
            }
            _ => {}
        }
    }
    let (Some(nonce), Some(salt), Some(iterations)) = (nonce, salt, iterations) else {
        return Err(ScramError::Malformed);
    };
    let our_nonce = client_first_bare
        .split(',')
        .find_map(|p| p.strip_prefix("r="))
        .ok_or(ScramError::Malformed)?;
    if !nonce.starts_with(our_nonce) || nonce.len() == our_nonce.len() {
        return Err(ScramError::Nonce);
    }
    if iterations == 0 || iterations > MAX_ITERATIONS {
        return Err(ScramError::Iterations);
    }
    let rounds = NonZeroU32::new(iterations).ok_or(ScramError::Iterations)?;

    let mut salted = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        rounds,
        &salt,
        password.as_bytes(),
        &mut salted,
    );
    let client_key = hmac_sha256(&salted, b"Client Key");
    let stored_key = digest::digest(&digest::SHA256, &client_key);
    let without_proof = format!("c=biws,r={nonce}");
    let auth_message = format!("{client_first_bare},{server_first},{without_proof}");
    let client_signature = hmac_sha256(stored_key.as_ref(), auth_message.as_bytes());
    let proof: Vec<u8> = client_key
        .iter()
        .zip(&client_signature)
        .map(|(a, b)| a ^ b)
        .collect();
    let server_key = hmac_sha256(&salted, b"Server Key");
    Ok(Proof {
        client_final: format!("{without_proof},p={}", B64.encode(proof)),
        expected_server_signature: hmac_sha256(&server_key, auth_message.as_bytes()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7677 section 3.
    const BARE: &str = "n=user,r=rOprNGfwEbeRWgbNEkqO";
    const SERVER_FIRST: &str =
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";

    #[test]
    fn matches_the_rfc_7677_example() {
        let proof = client_final("pencil", BARE, SERVER_FIRST).expect("proof");
        assert_eq!(
            proof.client_final,
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );
        assert!(proof.verify_server_final("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="));
        assert!(!proof.verify_server_final("v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
        assert!(!proof.verify_server_final("e=invalid-proof"));
    }

    #[test]
    fn rejects_a_server_nonce_that_does_not_extend_ours() {
        let bad = "r=somethingelse,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        assert_eq!(
            client_final("pencil", BARE, bad).expect_err("must fail"),
            ScramError::Nonce
        );
        let same = "r=rOprNGfwEbeRWgbNEkqO,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        assert_eq!(
            client_final("pencil", BARE, same).expect_err("must fail"),
            ScramError::Nonce
        );
    }

    #[test]
    fn rejects_absurd_iteration_counts_and_garbage() {
        let many = "r=rOprNGfwEbeRWgbNEkqOxx,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4000000000";
        assert_eq!(
            client_final("p", BARE, many).expect_err("must fail"),
            ScramError::Iterations
        );
        assert_eq!(
            client_final("p", BARE, "nonsense").expect_err("must fail"),
            ScramError::Malformed
        );
    }

    #[test]
    fn first_messages_have_the_right_shape() {
        let bare = client_first_bare("abc");
        assert_eq!(bare, "n=,r=abc");
        assert_eq!(client_first(&bare), "n,,n=,r=abc");
        assert_ne!(new_nonce(), new_nonce());
    }
}
