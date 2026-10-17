# ADR-0012: Dependency selection and maintenance criteria

- Status: Accepted (owner approved 2026-10-13)
- Date: 2026-10-13 (data gathered that day from the crates.io API, GitHub, and the RustSec advisory DB)

## Criteria
A dependency is adopted only if all of these hold:
1. It had a release within the last 12 months, or it is "done" with a tiny surface and active issue triage.
2. It has no open RustSec advisory against the version we use.
3. Its license is permissive (see `deny.toml`).
4. It is pure Rust, or at least doesn't need OpenSSL. TLS is rustls only.

`cargo deny check` and `cargo audit` enforce criteria 2–4 in CI.

## Assessment

| Area | Crate | Latest | Last release | Verdict |
|---|---|---|---|---|
| Runtime | tokio | 1.53.3 | 2026-10-13 | Adopt |
| HTTP | hyper 1.12 / axum 0.8.9 / tower 0.5.3 | | 2026-10 / 2026-04 / 2026-01 | Adopt |
| gRPC | tonic, tonic-prost(-build) 0.14.6, prost 0.14.4 | | 2026-05 / 2026-06 | Adopt. Needs `protoc` at build time (pinned through mise) |
| TLS | rustls 0.23.45, tokio-rustls 0.26.6 | | 2026-09 | Adopt |
| X.509 | rcgen 0.14.10, x509-parser 0.18.1 | | 2026-08 / 2026-02 | Adopt. Remote-signing spike in Phase 1 (ADR-0007) |
| PEM | rustls-pemfile | 2.2.0 | 2024-09 | **Reject**: RUSTSEC-2025-0134 (unmaintained). Use `rustls-pki-types` PEM support. Banned in deny.toml |
| AWS | aws-config 1.12, aws-sdk-{kms,s3,secretsmanager,rds} | | 2026-10 | Adopt |
| Kubernetes | kube 4.2.0, k8s-openapi 0.28.0 | | 2026-07 / 2026-06 | Adopt in principle; **not used in Phase 8 (ADR-0033)**. The kube worker forwards the user's request to the API server and must pass `exec`/`port-forward` upgrades through byte for byte, which a typed client does not do. It uses hyper directly, the same as the rest of the HTTP code. Revisit for discovery of clusters (ADR-0027) |
| Kubernetes streams (WebSocket) | tokio-tungstenite, tungstenite | | | **Reject for Phase 8.** We never terminate a WebSocket: the worker copies the bytes and decodes a copy to record them. A frame reader is ~150 lines (`limen-kube::ws`), fuzzable and tested, and cannot alter what it reads |
| Kubernetes streams (SPDY/3.1) | none exists in Rust | | | **Write our own** (`limen-kube::spdy`), as ADR-0001 anticipated. Header blocks are zlib streams with a preset dictionary, inflated with `flate2` 1.1.10 (already in the tree for the audit pipeline) on its `zlib-rs` backend, which supports dictionaries. The 1423-byte dictionary is fixed by the SPDY/3 specification and copied from `moby/spdystream` (BSD-3-Clause, Copyright 2013 The Go Authors), noted in the source file |
| OIDC | openidconnect | 4.0.1 | 2025-07 (repo active 2025-11) | Adopt. Stable and widely used. Watch maintenance; a fallback is `openidconnect` minus discovery plus `jsonwebtoken` |
| SQL state | sqlx | 0.9.0 | 2026-05 | Adopt |
| CLI | clap | 4.6.7 | 2026-09 | Adopt |
| Telemetry | tracing 0.1.44, tracing-subscriber 0.3.23, opentelemetry(-otlp) 0.33.1, tracing-opentelemetry 0.34 | | 2025-12 → 2026-10 | Adopt |
| Metrics | metrics 0.24.6 + metrics-exporter-prometheus 0.18.3, cadence 1.8.0 | | 2026-04/05 | Adopt |
| SSH | russh 0.64.1 | | 2026-10-05 | Adopt, at ≥ 0.60.3 (RUSTSEC-2026-0154 fixed). Fuzz our usage |
| SSH certs | ssh-key 0.6.7 (RustCrypto) | | 2026-06 | Adopt |
| PG wire | pgwire 0.41.1 | | 2026-09-29 | Adopt. Very active (805★) |
| MySQL wire | opensrv-mysql 0.7.0 | | **2024-02** | **Reject**: no release in 2.5 years, low use |
| MySQL wire | mysql_common 0.38.2 | | 2026-07 | **Adopt for packet and type definitions.** We write our own server-side handshake and command loop on top (the protocol subset is small: HandshakeV10, AuthSwitch, COM_QUERY, COM_STMT_*, COM_QUIT, result passthrough) |
| Redis wire | redis-protocol 6.0.0 | | **2024-11** (repo pushed 2025-02) | **Reject as a core dependency.** RESP2/3 is small. We write our own codec, fuzzed and tested against redis-protocol and the `redis` crate (1.7.1, active) in dev-dependencies |
| SQL parsing | sqlparser 0.63.0 | | 2026-09 | Adopt, for statement type classification and literal normalization only. Never for allow/deny decisions |
| YAML | serde_yaml | 0.9.34+deprecated | 2024-03 | **Reject**: deprecated |
| YAML | serde_yml | 0.0.13 | | **Reject**: RUSTSEC-2025-0068 (unsound, unmaintained) |
| YAML | serde-saphyr | 2.0.0 | 2026-10-13 | **Adopt** (pure Rust, active) |
| Rate limiting | governor 0.10.4 | | 2025-12 | Adopt |
| HTML templates | askama 0.16.1 | | 2026-09 | **Adopt** (compile-time templates, escapes by default). maud 0.27.0 (last release 2025-02) passed over for that reason |
| Constant-time compare | subtle 2.6.1 | | 2025 | Adopt (already in the tree through rustls and RustCrypto). Used for CSRF and login-state comparisons |
| Fonts and icons (vendored) | Inter 5.3.0 and JetBrains Mono 5.3.0 (`@fontsource-variable`, OFL-1.1), Lucide 1.57.0 (ISC) | | 2026 | **Adopt, vendored** with licenses under `crates/limen-control-plane/assets/vendor/` |
| Recording player (JS, vendored) | asciinema-player 3.17.0 | | 2026-06-30 | **Adopt, vendored** into `crates/limen-control-plane/assets/vendor/` with hash and license. Apache-2.0, no advisories on 2026-10-14, plays asciicast v3. Needs `'wasm-unsafe-eval'` (WebAssembly terminal), see ADR-0017 |
| Spool storage | redb 4.4.0 | | 2026-10-13 | Fallback only (ADR-0009) |
| Recording | asciicast 0.2.2 | | **2018** | **Reject**. Write our own asciicast v3 writer (newline-delimited JSON, ~100 lines) |
| Crypto | sha2 0.11, p256 0.14, ed25519-dalek 3.0 | | 2026 | Adopt |
| IDs and time | uuid 1.28 (v7), time 0.3.55 | | 2026 | Adopt |

## Accepted advisories

| Advisory | Crate (path) | Why it's accepted |
|---|---|---|
| RUSTSEC-2023-0071 (Marvin attack) | `rsa` (via `openidconnect`) | The attack recovers keys through timing of **private-key** operations. Limen only verifies IdP RS256 ID token signatures with public keys from the IdP's JWKS, and never generates or holds an RSA private key. There is no fixed version. Re-evaluate when `openidconnect` drops `rsa` or a fix ships. |

## Consequences
- We own two small protocol codecs: MySQL server-side and RESP. Both are fuzzed with `cargo-fuzz` in their phases.
- To add a dependency, a PR adds a row here.
