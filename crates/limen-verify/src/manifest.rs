//! The files the S3 audit sink writes next to each batch (ADR-0009).

use serde::{Deserialize, Serialize};

/// What a manifest records about one batch object. Manifests chain: each
/// names the SHA-256 of the previous manifest file from the same writer, so
/// a deleted, reordered, or altered batch breaks the chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub version: u32,
    pub writer: String,
    pub seq: u64,
    pub object: String,
    pub sha256: String,
    pub count: usize,
    pub first_event_id: String,
    pub last_event_id: String,
    pub prev_manifest_sha256: String,
    pub created_at: String,
}

/// The manifest file in S3: the manifest JSON, its signature, and the signer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedManifest {
    pub manifest: String,
    pub signature: String,
    pub signer_cert: String,
}

/// The signer of a manifest is the control plane that wrote it.
#[must_use]
pub fn signer_problem(signer_id: &str, writer: &str) -> Option<String> {
    (signer_id != writer).then(|| format!("signed by {signer_id}, not by its writer {writer}"))
}
