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
| Kubernetes | kube 4.2.0, k8s-openapi 0.28.0 | | 2026-07 / 2026-06 | Adopt |
| OIDC | openidconnect | 4.0.1 | 2025-07 (repo active 2025-11) | Adopt. Stable and widely used. Watch maintenance; a fallback is `openidconnect` minus discovery plus `jsonwebtoken` |
| SQL state | sqlx | 0.9.0 | 2026-05 | Adopt |
| CLI | clap | 4.6.7 | 2026-09 | Adopt |
| Telemetry | tracing 0.1.44, tracing-subscriber 0.3.23, opentelemetry(-otlp) 0.33.1, tracing-opentelemetry 0.34 | | 2025-12 → 2026-10 | Adopt |
| Metrics | metrics 0.24.6 + metrics-exporter-prometheus 0.18.3, cadence 1.8.0 | | 2026-04/05 | Adopt |
| SSH | russh 0.64.1 | | 2026-10-05 | Adopt, at ≥ 0.60.3 (RUSTSEC-2026-0154 fixed). Fuzz our usage |
| SSH certs | ssh-key 0.6.7 (RustCrypto) | | 2026-06 | Adopt |
| PG wire | pgwire 0.41.1 | | 2026-09-29 | Assessed and **not used** (Phase 6): the relay only needs frame lengths and a few message bodies, so the frame layer is ~100 lines of our own (`db/pg.rs`). Still a sound choice if a full server-side implementation is ever needed |
| MySQL wire | opensrv-mysql 0.7.0 | | **2024-02** | **Reject**: no release in 2.5 years, low use |
| MySQL wire | mysql_common 0.38.2 | | 2026-07 | Assessed and **not used** (Phase 6): the packet layer, handshake, and command loop are our own (`db/mysql.rs`), because the subset is small (HandshakeV10, AuthSwitch, COM_QUERY, COM_STMT_*, COM_QUIT, result passthrough) and is covered by tests against a real MySQL. The bootstrap and the tests use a small client of our own on the same packet layer (`db/mysqlclient.rs`) instead of adding a MySQL driver dependency |
| Redis wire | redis-protocol 6.0.0 | | **2024-11** (repo pushed 2025-02) | **Reject as a core dependency.** RESP2/3 is small. We write our own codec (`limen-worker/src/redis/codec.rs`, Phase 7), unit-tested at every cut point and run against real Redis and Valkey in the demo. A fuzz target and the `redis` crate as a dev-dependency are not added yet |
| SQL parsing | sqlparser 0.63.0 | | 2026-09 | **Adopted (Phase 6)**, `default-features = false`, and only its **tokenizer**: statement splitting, the first keyword, literal normalization. Never for allow/deny decisions. No advisories on 2026-10-17 |
| MD5 | md-5 0.11.0 (RustCrypto) | | 2026 | **Adopt (Phase 6)**, for the legacy PostgreSQL MD5 password exchange Redshift uses. Used for nothing else |
| AWS credentials | aws-credential-types 1.2 (with aws-config 1.12) | | 2026-10 | **Adopt (Phase 6)**: the default credential chain for IAM database authentication (also the worker's ElastiCache IAM token for Redis, Phase 7). SigV4 itself is hand-written on aws-lc-rs and checked against AWS's published examples |
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
- We own two small protocol codecs: MySQL (server side toward clients, client side toward targets) and RESP, plus the PostgreSQL frame layer. All are to be fuzzed with `cargo-fuzz`; that is still open for the Phase 6 codecs (design §14).
- To add a dependency, a PR adds a row here.
