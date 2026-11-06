//! Checking an evidence pack offline (ADR-0029): the manifest is signed by a
//! control plane the internal CA issued, and every section is what the
//! manifest says.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use base64::Engine as _;
use limen_proto::v1::Signed;
use limen_session::envelope::{Purpose, verify};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const FORMAT: &str = "limen-evidence/1";

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub format: String,
    pub generated_at: i64,
    pub from: i64,
    pub to: i64,
    pub requested_by: String,
    pub control_plane: String,
    /// Section name to the SHA-256 of its canonical JSON and its size.
    pub files: BTreeMap<String, FileEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileEntry {
    pub sha256: String,
    pub bytes: usize,
}

/// Lowercase hex of `bytes`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// SHA-256 of `bytes`, in hex.
#[must_use]
pub fn sha(bytes: &[u8]) -> String {
    sha256_hex(&Sha256::digest(bytes))
}

/// What checking a pack found.
#[derive(Debug, Default)]
pub struct Verification {
    pub manifest: Option<Manifest>,
    pub manifest_sha256: String,
    pub problems: Vec<String>,
}

impl Verification {
    #[must_use]
    pub fn ok(&self) -> bool {
        self.problems.is_empty() && self.manifest.is_some()
    }
}

/// Check a pack offline: the manifest is signed by a control plane the
/// internal CA issued, and every section is what the manifest says.
#[must_use]
pub fn verify_pack(
    pack: &[u8],
    internal_ca: &rustls_pki_types::CertificateDer<'_>,
) -> Verification {
    let mut out = Verification::default();
    let b64 = base64::engine::general_purpose::STANDARD;
    let Ok(v) = serde_json::from_slice::<Value>(pack) else {
        out.problems.push("not a JSON document".into());
        return out;
    };
    if v["format"] != FORMAT {
        out.problems.push(format!("not a {FORMAT} pack"));
        return out;
    }
    let (Some(manifest_json), Some(sig), Some(cert)) = (
        v["manifest_json"].as_str(),
        v["signature_b64"].as_str().and_then(|s| b64.decode(s).ok()),
        v["signer_cert_b64"]
            .as_str()
            .and_then(|s| b64.decode(s).ok()),
    ) else {
        out.problems
            .push("the manifest or its signature is missing".into());
        return out;
    };
    out.manifest_sha256 = sha(manifest_json.as_bytes());
    if v["manifest_sha256"] != json!(out.manifest_sha256) {
        out.problems
            .push("the manifest hash in the pack doesn't match the manifest".into());
    }
    let signed = Signed {
        payload: manifest_json.as_bytes().to_vec(),
        signature: sig,
        signer_cert_der: cert,
    };
    if let Err(e) = verify(&signed, Purpose::EvidencePack, internal_ca) {
        out.problems
            .push(format!("the manifest's signature is not valid: {e}"));
        return out;
    }
    let Ok(manifest) = serde_json::from_str::<Manifest>(manifest_json) else {
        out.problems.push("the manifest is unreadable".into());
        return out;
    };
    let empty = serde_json::Map::new();
    let sections = v["sections"].as_object().unwrap_or(&empty);
    for (name, entry) in &manifest.files {
        match sections.get(name) {
            None => out.problems.push(format!("section {name} is missing")),
            Some(s) => {
                let bytes = serde_json::to_vec(s).unwrap_or_default();
                if sha(&bytes) != entry.sha256 {
                    out.problems
                        .push(format!("section {name} was changed after it was signed"));
                }
            }
        }
    }
    for name in sections.keys().filter(|n| !manifest.files.contains_key(*n)) {
        out.problems
            .push(format!("section {name} is not in the signed manifest"));
    }
    out.manifest = Some(manifest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn junk_is_not_a_pack() {
        let ca = rustls_pki_types::CertificateDer::from(vec![0u8]);
        for junk in [
            &b"not json"[..],
            b"{}",
            b"{\"format\":\"limen-evidence/1\"}",
        ] {
            assert!(!verify_pack(junk, &ca).ok());
        }
    }
}
