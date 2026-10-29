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
| gRPC | tonic, tonic-prost(-build) 0.14.6, prost 0.14.4 | | 2026-05 / 2026-06 | Adopt. `prost` is also used directly by the control plane for Phase 12 web-session handoff messages. Needs `protoc` at build time (pinned through mise) |
| TLS | rustls 0.23.46, tokio-rustls 0.26.6 | | 2026-10 / 2026-09 | Adopt. Locked `rustls-webpki` and root-store crates are at patched versions 0.103.16 / 1.0.10 after the 2026-10 RustSec advisories |
| X.509 | rcgen 0.14.10, x509-parser 0.18.1 | | 2026-08 / 2026-02 | Adopt. Remote-signing spike in Phase 1 (ADR-0007) |
| PEM | rustls-pemfile | 2.2.0 | 2024-09 | **Reject**: RUSTSEC-2025-0134 (unmaintained). Use `rustls-pki-types` PEM support. Banned in deny.toml |
| AWS | aws-config 1.12, aws-sdk-{kms,s3,secretsmanager,rds} | | 2026-10 | Adopt |
| Kubernetes | kube 4.2.0, k8s-openapi 0.28.0 | | 2026-07 / 2026-06 | Adopt in principle; **not used in Phase 8 (ADR-0038)**. The kube worker forwards the user's request to the API server and must pass `exec`/`port-forward` upgrades through byte for byte, which a typed client does not do. It uses hyper directly, the same as the rest of the HTTP code. Revisit for discovery of clusters (ADR-0027) |
| Kubernetes streams (WebSocket) | tokio-tungstenite, tungstenite | | | **Reject for Phase 8.** We never terminate a WebSocket: the worker copies the bytes and decodes a copy to record them. A frame reader is ~150 lines (`limen-kube::ws`), fuzzable and tested, and cannot alter what it reads |
| Kubernetes streams (SPDY/3.1) | none exists in Rust | | | **Write our own** (`limen-kube::spdy`), as ADR-0001 anticipated. Header blocks are zlib streams with a preset dictionary, inflated with `flate2` 1.1.10 (already in the tree for the audit pipeline) on its `zlib-rs` backend, which supports dictionaries. The 1423-byte dictionary is fixed by the SPDY/3 specification and copied from `moby/spdystream` (BSD-3-Clause, Copyright 2013 The Go Authors), noted in the source file |
| OIDC | openidconnect | 4.0.1 | 2025-07 (repo active 2025-11) | Adopt. Stable and widely used. Watch maintenance; a fallback is `openidconnect` minus discovery plus `jsonwebtoken` |
| SQL state | sqlx | 0.9.0 | 2026-05 | Adopt |
| CLI | clap | 4.6.7 | 2026-09 | Adopt |
| CLI completions | clap_complete 4.6.11 | | 2026-10 | Adopt. Same maintainers and release train as clap; generates `limen completions <shell>`. No advisories; MIT/Apache-2.0 |
| Telemetry | tracing 0.1.44, tracing-subscriber 0.3.23, opentelemetry(-otlp) 0.33.1, tracing-opentelemetry 0.34 | OTLP over HTTP/protobuf with the blocking reqwest client (shares reqwest and prost; no second tonic). ADR-0040 | 2025-12 → 2026-10 | Adopt |
| Metrics | metrics 0.24.6 + metrics-exporter-prometheus 0.18.3, cadence 1.8.0 | | 2026-04/05 | Adopt |
| SSH | russh 0.64.1 | | 2026-10-05 | Adopt, at ≥ 0.60.3 (RUSTSEC-2026-0154 fixed). Fuzz our usage |
| SSH certs | ssh-key 0.6.7 (RustCrypto) | | 2026-06 | Adopt |
| PG wire | pgwire 0.41.1 | | 2026-09-29 | Assessed and **not used** (Phase 6): the relay only needs frame lengths and a few message bodies, so the frame layer is ~100 lines of our own (`db/pg.rs`). Still a sound choice if a full server-side implementation is ever needed |
| MySQL wire | opensrv-mysql 0.7.0 | | **2024-02** | **Reject**: no release in 2.5 years, low use |
| MySQL wire | mysql_common 0.38.2 | | 2026-07 | Assessed and **not used** (Phase 6): the packet layer, handshake, and command loop are our own (`db/mysql.rs`), because the subset is small (HandshakeV10, AuthSwitch, COM_QUERY, COM_STMT_*, COM_QUIT, result passthrough) and is covered by tests against a real MySQL. The bootstrap and the tests use a small client of our own on the same packet layer (`db/mysqlclient.rs`) instead of adding a MySQL driver dependency |
| Redis wire | redis-protocol 6.0.0 | | **2024-11** (repo pushed 2025-02) | **Reject as a core dependency.** RESP2/3 is small. We write our own codec (`limen-worker/src/redis/codec.rs`, Phase 7), unit-tested at every cut point and run against real Redis and Valkey in the demo. A fuzz target and the `redis` crate as a dev-dependency are not added yet |
| AMQP 0-9-1 wire | lapin, amq-protocol | | not assessed | **Reject.** Our own frame codec (`limen-worker/src/amqp/codec.rs`, Phase 11): the worker is the server toward the client and reads about thirty method layouts; a client library would not serve it. Tested at every cut point, and against real RabbitMQ 4 with pika in the demo. No new crate |
| Kafka wire | kafka-protocol, rdkafka | | not assessed | **Reject.** Our own readers and builders for 17 API keys at pinned non-flexible versions (`limen-worker/src/kafka/`, Phase 11): policy needs the topics and groups, not full messages, and the worker rewrites responses. SCRAM and the MSK IAM payload use `aws-lc-rs` and the Phase 6 SigV4 code. Run against a real three-broker cluster with librdkafka in the demo. No new crate |
| SQL parsing | sqlparser 0.63.0 | | 2026-09 | **Adopted (Phase 6)**, `default-features = false`, and only its **tokenizer**: statement splitting, the first keyword, literal normalization. Never for allow/deny decisions. No advisories on 2026-10-17 |
| MD5 | md-5 0.11.0 (RustCrypto) | | 2026 | **Adopt (Phase 6)**, for the legacy PostgreSQL MD5 password exchange Redshift uses. Used for nothing else |
| AWS credentials | aws-credential-types 1.2 (with aws-config 1.12) | | 2026-10 | **Adopt (Phase 6)**: the default credential chain for IAM database authentication (also the worker's ElastiCache IAM token for Redis, Phase 7). SigV4 itself is hand-written on aws-lc-rs and checked against AWS's published examples |
| MongoDB wire and BSON | bson, mongodb (MongoDB, Rust driver) | | active | **Not used (Phase 9).** A relay walks and bounds documents rather than building typed values, and the driver brings a large tree. We write the BSON reader and `OP_MSG` framing ourselves (`limen-worker/src/mongo/bson.rs`, `wire.rs`; a few hundred lines), tested at the byte level and against a real MongoDB 8 and `mongosh` in the demo. SCRAM-SHA-1 and SHA-256 use `aws-lc-rs` and the `md-5` crate already adopted. A fuzz target is not added yet |
| Search wire | hyper 1.12, hyper-util 0.1, http-body-util 0.1, flate2 1.1 (already workspace dependencies) | | 2026-10 | **Adopted for the worker (Phase 10)**: no new crate. The search session is an HTTP/1.1 server and client built on `hyper` (`limen-worker/src/search/`); `http-body-util` bounds and collects bodies; `flate2` decodes a gzip body the worker has to read (decoded size capped). The `SigV4` signer is the Phase 6 one (`db/sigv4.rs`). `elasticsearch` and `opensearch` client crates were not assessed: the worker needs no client library, only HTTP |
| Regular expressions | regex-lite 0.1.9 | | 2026 | **Adopt (Phase 13)**, for the `ticket_pattern` of requestable roles and the secret-shape masker of the search index. A linear-time matcher with no backtracking, so a hostile reason or terminal output cannot make it spin; size and nesting limits on the policy-supplied pattern. Already in the tree through the AWS SDK; no advisories on 2026-10-25 |
| AWS describe calls and XML (discovery) | none | | | **Not adopted (Phase 13).** Discovery signs its calls with the worker's own SigV4 and reads answers with a small bounded XML reader (`limen-worker/src/discovery/xml.rs`), instead of adding `aws-sdk-ec2`, `-rds`, `-redshift`, `-elasticache` and `-eks`: the surface is five read calls, and the SDKs add large compile and review cost for it |
| YAML | serde_yaml | 0.9.34+deprecated | 2024-03 | **Reject**: deprecated |
| YAML | serde_yml | 0.0.13 | | **Reject**: RUSTSEC-2025-0068 (unsound, unmaintained) |
| YAML | serde-saphyr | 2.0.0 | 2026-10-13 | **Adopt** (pure Rust, active) |
| Rate limiting | governor 0.10.4 | | 2025-12 | Adopt |
| HTML templates | askama 0.16.1 | | 2026-09 | **Adopt** (compile-time templates, escapes by default). Enable only `derive` and `std`; no Askama config file is used, so its unused `config` feature and unmaintained `basic-toml` are excluded. maud 0.27.0 (last release 2025-02) passed over for that reason |
| URL parsing | url 2.5.8 | | 2026-01-05 | **Adopt** (WHATWG URL parser; already used by OIDC, now also parses Phase 12 app origins and upstream targets). No RustSec advisory in the 2026-10 audit |
| Base64 encoding | base64 0.23.1 | | 2026-08-04 | **Adopt** (URL-safe, unpadded encoding for signed Phase 12 assertions and app sessions). No RustSec advisory in the 2026-10 audit |
| Constant-time compare | subtle 2.6.1 | | 2025 | Adopt (already in the tree through rustls and RustCrypto). Used for CSRF and login-state comparisons |
| Fonts and icons (vendored) | Inter 5.3.0 and JetBrains Mono 5.3.0 (`@fontsource-variable`, OFL-1.1), Lucide 1.57.0 (ISC) | | 2026 | **Adopt, vendored** with licenses under `crates/limen-control-plane/assets/vendor/` |
| Recording player (JS, vendored) | asciinema-player 3.17.0 | | 2026-06-30 | **Adopt, vendored** into `crates/limen-control-plane/assets/vendor/` with hash and license. Apache-2.0, no advisories on 2026-10-14, plays asciicast v3. Needs `'wasm-unsafe-eval'` (WebAssembly terminal), see ADR-0017 |
| Spool storage | redb 4.4.0 | | 2026-10-13 | Fallback only (ADR-0009) |
| Recording | asciicast 0.2.2 | | **2018** | **Reject**. Write our own asciicast v3 writer (newline-delimited JSON, ~100 lines) |
| Crypto | sha2 0.11, p256 0.14, ed25519-dalek 3.0 | | 2026 | Adopt |
| IDs and time | uuid 1.28 (v7), time 0.3.55 | | 2026 | Adopt |
| Site (build time only, `website/`) | Node 24.22.1 LTS (pinned in `mise.toml`) | 24.22.1 | 2026-10 | Adopt. Astro 7 needs Node 22.23.4 or newer. Nothing from the site runs in a Limen component |
| Site | astro 7.4.2 (MIT), @astrojs/starlight 0.42.7 (MIT) | | 2026-10-21 / 2026-10-23 | Adopt. Static output, search without a server, 0 advisories under `npm audit`. Versions are exact in `website/package.json` and locked in `package-lock.json` |
| Site | @fontsource-variable/geist and geist-mono 5.3.0 (OFL-1.1) | | 2026-07-19 | Adopt. Fonts are served from the site itself, so a visitor makes no request to a font service |
| Site | @astrojs/markdown-satteri 0.4.5 (MIT) | | 2026-10-21 | Adopt. Astro's own Markdown engine, already in the tree through Starlight. Declared so `astro.config.mjs` can wrap every table in a scroll container. 0 advisories under `npm audit` |
| API contract (CI and dev only) | buf 1.74.0 (Apache-2.0, pinned in `mise.toml`) | 1.75.0 | 2026-10-14 | Adopt (ADR-0042). `buf lint` and `buf breaking` for `limen.manage.v1` only (`proto/buf.yaml`); not used to build, so `protoc` stays the code generator. Pinned one release behind the newest (1.75.0 is a week old). Actively maintained, no published security advisories (checked 2026-10-29) |

## Accepted advisories

| Advisory | Crate (path) | Why it's accepted |
|---|---|---|
| RUSTSEC-2023-0071 (Marvin attack) | `rsa` (via `openidconnect`) | The attack recovers keys through timing of **private-key** operations. Limen only verifies IdP RS256 ID token signatures with public keys from the IdP's JWKS, and never generates or holds an RSA private key. There is no fixed version. Re-evaluate when `openidconnect` drops `rsa` or a fix ships. |
| RUSTSEC-2026-0387 (`crypto-bigint` timing variability) | `crypto-bigint` 0.5.5 (via `openidconnect` 4.0.1, `p256`/`p384` 0.13, `elliptic-curve` 0.13) | The advisory covers operations on secret integers. Limen only verifies IdP ES256/ES384 ID token signatures with public keys, so none are processed. The other path, `aws-sigv4`, is cleared: 1.6.4 uses `crypto-bigint` 0.7. The fix is on `openidconnect` master (4.1.0, `p256`/`p384` 0.14) but not on crates.io yet; upstream tracks it in [openidconnect-rs#244](https://github.com/ramosbugs/openidconnect-rs/issues/244). Remove the `deny.toml` ignore and this row when 4.1.0 ships and we bump. |

## Consequences
- We own two small protocol codecs: MySQL (server side toward clients, client side toward targets) and RESP, plus the PostgreSQL frame layer. All are to be fuzzed with `cargo-fuzz`; that is still open for the Phase 6 codecs (design §14).
- To add a dependency, a PR adds a row here.
