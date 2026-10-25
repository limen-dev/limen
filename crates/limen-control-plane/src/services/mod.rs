pub mod access;
pub mod admin;
pub mod auth;
pub mod bot_login;
pub mod enrollment;
pub mod handoff;
pub mod ingest;
pub mod ops;
pub mod policy_sync;
pub mod registry;
pub mod resources;
pub mod ssh_certs;

use base64::Engine as _;
use sha2::{Digest, Sha256};

/// SHA-256, used for stored token and nonce hashes.
#[must_use]
pub fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

#[must_use]
pub fn b64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}
