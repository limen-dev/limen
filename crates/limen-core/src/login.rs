//! The login nonce that binds an IdP ID token to the CLI's key (ADR-0006).

use base64::Engine as _;
use sha2::{Digest, Sha256};

/// `base64url(SHA-256(spki_der || salt))`, unpadded. The CLI puts this in its
/// authorization request. The control plane recomputes it from the CSR it
/// receives and the salt, and requires the ID token's `nonce` to match. A
/// relaying party therefore can't get certificates for a key of its own.
#[must_use]
pub fn nonce(spki_der: &[u8], salt: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(spki_der);
    hasher.update(salt);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    #[test]
    fn depends_on_key_and_salt() {
        let a = super::nonce(b"key-a", b"salt");
        assert_eq!(a.len(), 43, "32 bytes, base64url without padding");
        assert_ne!(a, super::nonce(b"key-b", b"salt"));
        assert_ne!(a, super::nonce(b"key-a", b"other"));
        assert_eq!(a, super::nonce(b"key-a", b"salt"));
    }
}
