//! Check the audit trail and evidence packs without trusting Limen.
//!
//! The control plane writes the S3 manifests and the evidence packs; this
//! crate reads and checks them, and has no dependency on the control plane.
//! `limen audit verify` is its command line.

pub mod bucket;
mod client;
pub mod controls;
pub mod manifest;
pub mod pack;

pub use client::{Access, s3_client, s3_client_with};
