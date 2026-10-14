# Limen threat model

Status: **Living document**. Last reviewed 2026-10-14 (Phase 1). Method: STRIDE per trust boundary, plus abuse cases. Review this document in every phase that adds an entry point, a credential type, or a data store. A PR that adds any of those must update it.

## 1. Assets

| # | Asset | Why it matters |
|---|---|---|
| A1 | CA private keys (internal, user X.509, user SSH) | Anyone who can sign can impersonate any user or component |
| A2 | User short-lived certs and private keys | Direct access to infrastructure until the TTL expires |
| A3 | Worker and proxy mTLS identities | Joining the fabric, getting session grants, reading session traffic |
| A4 | DB admin secrets (Secrets Manager) | Full control of databases |
| A5 | Worker IAM roles (`rds-db:connect`, `elasticache:Connect`) | DB and cache access as any `limen_*` role |
| A6 | Kube worker service account (impersonate) | Acting as any user or group in the cluster |
| A7 | Session content: SQL results, SSH terminal, kube exec | Customer data, secrets typed into terminals |
| A8 | Audit trail and recordings | Detection, forensics, compliance. A target for anyone covering their tracks |
| A9 | Policy (roles, mappings, resources) | Changing it grants access |
| A10 | Join tokens | Enrolling a rogue worker |
| A11 | Aurora state | Policy history, token hashes, tunnel registry |

## 2. Adversaries
- **External attacker** on the internet who can reach the public NLB.
- **Malicious or compromised insider** with valid IdP credentials and some roles.
- **Attacker with code execution on a user's laptop**, including another local user or a malicious local process.
- **Attacker who compromised one component**: a proxy task, a worker host or pod, or a target host.
- **Attacker in a target network**, for example on the same VPC as a worker.
- **Supply-chain attacker** through a dependency or CI.

Out of scope for v1: a compromised AWS account root or KMS itself; a compromised IdP (we inherit the IdP's guarantees); physical attacks.

## 3. Trust boundaries

```
[Laptop: CLI + local tools] ──TB1── [Proxy] ──TB2── [Worker] ──TB3── [Target]
                                      │                │
                                     TB4              TB2'
                                      │                │
                                 [Control plane] ──TB5── [Aurora / KMS / S3 / Secrets Manager]
                                      │
                                     TB6 ── [Datadog, Grafana]
[CLI] ──TB0── [IdP]
```

## 4. STRIDE by boundary

### TB0: CLI ↔ IdP (login)
| Threat | Mitigation |
|---|---|
| S: authorization-code interception on the loopback redirect | PKCE (S256). Random port. `state` checked. Loopback only, never `0.0.0.0` |
| S: a malicious proxy or MITM swaps the user's public key for its own during cert issuance | The nonce binds the hash of the CLI's public keys. The control plane rejects an ID token whose nonce doesn't match the presented keys (ADR-0006) |
| T: replayed ID token | `exp` and `iat` checked. The nonce is single-use (the control plane stores a nonce hash until the token expires) |
| S: no key binding in the device flow (RFC 8628 can't carry our nonce) | Replay is still blocked: the control plane records a hash of each device-flow ID token and accepts it once. PKCE stays the default. **Residual risk:** a compromised proxy relaying a device-flow login could swap in its own CSR (see §6) |
| I: tokens in logs | `Secret<T>` newtypes. The log scanner test |

### TB1: Laptop ↔ proxy (public)
| Threat | Mitigation |
|---|---|
| S: stolen user cert and key | 10-minute TTL. Keys stored with 0600. Optional OS keychain (Phase 7) |
| S: another local process or user connects to the CLI's loopback DB or Redis listener and rides the session | **Known risk.** Mitigations: bind to 127.0.0.1 only. `--socket` puts a unix socket in a 0700 directory. Each listener serves one target and closes after idle, by default 1 hour, configurable. Sessions are audited under the user. Documented in the user guide |
| T/I: downgrade or MITM | TLS 1.3 only (rustls). Public cert pinned through system roots plus an optional pin of the Limen CA |
| D: connection floods, handshake CPU exhaustion | NLB plus a per-IP pre-auth rate limit and a concurrent handshake cap. Max sessions per user |
| E: malformed `SessionRequest` | Strict schema, size limits, `deny_unknown_fields`. Fuzzed in Phase 7 |

### TB2/TB2′: Proxy ↔ worker (tunnel) and worker/proxy ↔ control plane
| Threat | Mitigation |
|---|---|
| S: rogue worker enrolls | Single-use join tokens with a 15-minute TTL, stored hashed and consumed atomically. Bound to allowed kinds and labels. `worker.enroll` audit plus an alert on enrollment |
| S: leaked static join token (ADR-0016) | Kind-scoped. Proxies enrolled with one may only request allow-listed DNS names, and workers get no DNS names, so a leaked worker token can't mint a server certificate. Audited with `token_type=static`. Stored in Secrets Manager and rotated. Replaced by IAM join in Phase 7 |
| S: client spoofs `x-limen-*` relay headers | The proxy strips every client-supplied `x-limen-*` header before relaying. The control plane accepts forwarding only from callers presenting a **proxy** certificate, and re-verifies the forwarded certificate against the user CA, or the internal CA for workers only. Integration-tested |
| E: worker forwards a user cert to act as that user | Only proxies may forward. A worker's direct calls resolve to the worker's identity, and user APIs reject it. Integration-tested |
| S: a compromised worker claims resources it doesn't serve | The worker's cert carries its pool and labels. The control plane only routes resources whose `worker_selector` matches the cert attributes |
| S: a compromised proxy forges identities toward the control plane | The control plane re-verifies the forwarded user cert against the user CA. The proxy can't mint certs (no `kms:Sign`) |
| T: a compromised proxy replays a user cert it observed, to open new sessions | **Residual risk**, bounded by the cert TTL (10 min). The proxy would also need the user's private key for the TLS handshake on TB1, which it never sees. Session grants are only produced by proxies. Workers check that `grant.user` equals the forwarded cert. Accepted |
| T: grant replay | Grant TTL ≤ 60 s to establish. Nonce LRU on the worker. The grant is bound to the session ID |
| R: proxy denies having routed a session | Both the proxy and the worker emit events that share the `session_id` |
| D: tunnel exhaustion | Max concurrent streams per tunnel. Per-user session caps |

### TB3: Worker ↔ target
| Threat | Mitigation |
|---|---|
| S: a target impersonated (DNS hijack in the VPC) | RDS: TLS `verify-full` against the RDS CA bundle. ElastiCache: TLS required. SSH: host CA or pinned host key, unknown fails closed. Kube: cluster CA from in-cluster config |
| E: a worker compromise exposes DB admin secrets (A4) | The secret is read only during reconcile and held in memory only. The IAM policy is scoped to that one secret ARN. The admin role should be a dedicated `limen_admin`, not the RDS master user (documented). Alternative: run bootstrap as a separate one-shot task with its own role (Phase 4 option) |
| E: a worker compromise lets it act as any `limen_*` DB role | `rds-db:connect` is limited to `dbuser:<id>/limen_*` per resource. Workers are deployed per VPC or account to limit blast radius |
| E: privilege escalation through kube impersonation (A6) | The worker strips client-supplied `Impersonate-*` headers and sets its own from the grant. The ClusterRole limits `groups` impersonation to `resourceNames` = the `limen:*` groups when the operator lists them, and must never include `system:masters`. Constrained impersonation (K8s ≥ 1.36) is planned hardening |
| E: SSH target cert too broad | Per-session cert: TTL 1 min to authenticate, one principal, key ID = session ID. Port forwarding and agent forwarding are off unless the role allows them |

### TB4/TB5: Control plane ↔ Aurora, KMS, S3, Secrets Manager
| Threat | Mitigation |
|---|---|
| E: CA key theft (A1) | Keys live in KMS. `kms:Sign` is granted only to the control plane task role, with a key-policy condition on the signing algorithm. CloudTrail on `Sign`. Separate keys per purpose |
| T: policy tampering in Aurora (A9) | Policy versions are immutable rows. Snapshots are signed. `policy.change` is audited. The DB user has no `DELETE` on the policy tables |
| I: Aurora data exposure | Encryption at rest (KMS), TLS, IAM auth for the control plane DB user (Phase 7), no secrets stored (join tokens are hashed) |

### TB6: Audit sinks and dashboards
| Threat | Mitigation |
|---|---|
| T: tampering with audit batches (A8) | Per-writer hash chain plus signed manifests. Optional S3 Object Lock in compliance mode. A separate KMS key. Bucket policy denies delete except to lifecycle. `limen admin audit verify` |
| R: an insider evades audit through protocol tricks | PG: extended protocol, `COPY`, multi-statement, and `DO` blocks are all logged at the wire level, not through SQL parsing. MySQL: `COM_STMT_PREPARE`/`EXECUTE`, multi-statements. Redis: `MULTI`/`EXEC`, `EVAL`/`EVALSHA` (the script body is logged, args redacted), pipelining. Kube: exec recorded, port-forward audited. Unparseable input is logged raw as `statement_type=unknown` |
| D: audit pipeline loss | Local fsynced spool, at-least-once delivery, fail-closed by default, producer `seq` gap detection |
| I: sensitive data in audit (PII in SQL literals, Redis values) | Redis values redacted by default. SQL full text by default (owner decision), with per-resource literal normalization. Bound parameters redacted by default. Access to the bucket and Grafana is limited to auditors |
| S: Grafana access | Okta OIDC, auditor and admin groups only. Read-only Athena role |

## 5. Cross-cutting

| Concern | Control |
|---|---|
| Secrets in logs | `Secret<T>` (no `Serialize`, redacted `Debug`). Log scanner test. Tokens never in URLs |
| Input validation | Strict serde (`deny_unknown_fields`), size caps on every frame and request, label and name validation (`limen-core::labels`) |
| Rate limiting | `governor`: per IP before auth, per user after, stricter for login and enrollment |
| Supply chain | `cargo-deny` (advisories, licenses, sources, bans), `cargo-audit`, pinned toolchain and tools (mise), GitHub Actions pinned to commit SHAs, minimal `permissions:` in workflows, distroless images, SBOM in release (Phase 7) |
| Memory safety | `unsafe_code = "forbid"` workspace-wide. Hand-written protocol codecs (MySQL, RESP) are fuzzed |
| Clock skew | Certs are back-dated 1 minute. TTL checks allow ±2 minutes |

## 6. Accepted residual risks (v1)
1. A compromised proxy can replay observed user certs toward the control plane for up to the cert TTL (it can't do TLS as the user without the key).
2. A local process on the user's machine can use an open loopback listener during its lifetime.
3. A compromised worker sees the plaintext of the sessions it serves, and can act as the `limen_*` DB roles of its resources.
4. Duplicates in Datadog under failure (at-least-once).
5. Revocation is TTL-based (no immediate lock in v1. `lock` is an extension point).
6. Device-flow logins aren't bound to the CLI's key (no nonce in RFC 8628). PKCE is the default and is bound.
7. Until IAM join exists (Phase 7), autoscaled proxies and workers enroll with a static, kind-scoped token.

## 7. Review log
| Date | Phase | Change |
|---|---|---|
| 2026-10-13 | 0 | Initial model |
| 2026-10-14 | 1 | Device-flow binding gap; static join tokens; relay header spoofing; worker forwarding. Identity moved to URI SANs |
