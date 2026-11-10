//! Checking an evidence pack offline (ADR-0029): the manifest is signed by a
//! control plane the internal CA issued, and every section is what the
//! manifest says.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use base64::Engine as _;
use limen_proto::v1::Signed;
use limen_session::envelope::{Purpose, verify_at};
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
    let Ok(manifest) = serde_json::from_str::<Manifest>(manifest_json) else {
        out.problems.push("the manifest is unreadable".into());
        return out;
    };
    // The signer's certificate lives about a day and a pack is checked long
    // after, so the certificate is judged as of the time the signed manifest
    // records, as for audit manifests (bucket.rs).
    let Ok(generated_at) = time::OffsetDateTime::from_unix_timestamp(manifest.generated_at) else {
        out.problems
            .push("the manifest's generation time is out of range".into());
        return out;
    };
    if let Err(e) = verify_at(&signed, Purpose::EvidencePack, internal_ca, generated_at) {
        out.problems
            .push(format!("the manifest's signature is not valid: {e}"));
        return out;
    }
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

    /// A pack signed with a certificate that expires in a second, generated
    /// at `generated_at` seconds from now.
    async fn pack_signed_by_a_short_lived_cert(generated_at: i64) -> (Vec<u8>, Vec<u8>) {
        use limen_ca::{CaPurpose, CertificateAuthority, ComponentCertRequest, FileSigner};
        use limen_core::identity::ComponentKind;
        use limen_session::envelope::EnvelopeSigner;
        use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

        let ca = CertificateAuthority::create_self_signed(
            CaPurpose::Internal,
            std::sync::Arc::new(FileSigner::generate().expect("key")),
        )
        .await
        .expect("ca");
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
        let csr = CertificateParams::default()
            .serialize_request(&key)
            .expect("csr");
        let cert = ca
            .issue_component(ComponentCertRequest {
                csr_der: csr.der().to_vec(),
                kind: ComponentKind::ControlPlane,
                id: "cp".into(),
                dns_names: vec![],
                labels: BTreeMap::new(),
                ttl: std::time::Duration::from_secs(1),
            })
            .await
            .expect("issue");
        let signer = EnvelopeSigner::new(&key.serialize_pem(), cert.der.to_vec()).expect("signer");
        let section = json!({"rows": [1, 2, 3]});
        let bytes = serde_json::to_vec(&section).expect("section");
        let manifest = Manifest {
            format: FORMAT.to_owned(),
            generated_at: time::OffsetDateTime::now_utc().unix_timestamp() + generated_at,
            from: 0,
            to: 1,
            requested_by: "auditor@example.com".into(),
            control_plane: "cp".into(),
            files: BTreeMap::from([(
                "sessions".to_owned(),
                FileEntry {
                    sha256: sha(&bytes),
                    bytes: bytes.len(),
                },
            )]),
        };
        let manifest_json = serde_json::to_string(&manifest).expect("manifest");
        let envelope = signer
            .sign(Purpose::EvidencePack, manifest_json.clone().into_bytes())
            .expect("sign");
        let b64 = base64::engine::general_purpose::STANDARD;
        let pack = json!({
            "format": FORMAT,
            "manifest_sha256": sha(manifest_json.as_bytes()),
            "manifest_json": manifest_json,
            "signature_b64": b64.encode(&envelope.signature),
            "signer_cert_b64": b64.encode(&envelope.signer_cert_der),
            "sections": {"sessions": section},
        });
        (
            serde_json::to_vec(&pack).expect("pack"),
            ca.cert_der().to_vec(),
        )
    }

    #[tokio::test]
    async fn a_pack_still_verifies_after_its_signers_certificate_expires() {
        let (pack, ca) = pack_signed_by_a_short_lived_cert(0).await;
        tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
        let ca = rustls_pki_types::CertificateDer::from(ca);
        let checked = verify_pack(&pack, &ca);
        assert!(checked.ok(), "{:?}", checked.problems);
    }

    #[tokio::test]
    async fn a_pack_dated_after_its_signers_certificate_expired_is_refused() {
        // The certificate lives a second; a manifest claiming an hour from now
        // was not signed while it was valid.
        let (pack, ca) = pack_signed_by_a_short_lived_cert(3600).await;
        let ca = rustls_pki_types::CertificateDer::from(ca);
        let checked = verify_pack(&pack, &ca);
        assert!(!checked.ok());
        assert!(
            checked.problems[0].contains("signature is not valid"),
            "{:?}",
            checked.problems
        );
    }
}
