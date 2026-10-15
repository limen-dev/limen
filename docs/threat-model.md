# Limen threat model

Status: **Living document**. Last reviewed 2026-10-14 (Phase 2). Method: STRIDE per trust boundary, plus abuse cases. Review this document in every phase that adds an entry point, a credential type, or a data store. A PR that adds any of those must update it.

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
| S: stolen user cert and key | 10-minute TTL. Keys stored with 0600. Optional OS keychain (Phase 13) |
| S: another local process or user connects to the CLI's loopback DB or Redis listener and rides the session | **Known risk.** Mitigations: bind to 127.0.0.1 only. `--socket` puts a unix socket in a 0700 directory. Each listener serves one target and closes after idle, by default 1 hour, configurable. Sessions are audited under the user. Documented in the user guide |
| T/I: downgrade or MITM | TLS 1.3 only (rustls). Public cert pinned through system roots plus an optional pin of the Limen CA |
| D: connection floods, handshake CPU exhaustion | NLB plus a per-IP pre-auth rate limit and a concurrent handshake cap. Max sessions per user |
| E: malformed `SessionRequest` | Strict schema, size limits, `deny_unknown_fields`. Fuzzed in Phase 13 |

### TB2/TB2′: Proxy ↔ worker (tunnel) and worker/proxy ↔ control plane
| Threat | Mitigation |
|---|---|
| S: rogue worker enrolls | Single-use join tokens with a 15-minute TTL, stored hashed and consumed atomically. Bound to allowed kinds and labels. `worker.enroll` audit plus an alert on enrollment |
| S: leaked static join token (ADR-0016) | Kind-scoped. Proxies enrolled with one may only request allow-listed DNS names, and workers get no DNS names, so a leaked worker token can't mint a server certificate. Audited with `token_type=static`. Stored in Secrets Manager and rotated. Replaced by IAM join in Phase 13 |
| S: client spoofs `x-limen-*` relay headers | The proxy strips every client-supplied `x-limen-*` header before relaying. The control plane accepts forwarding only from callers presenting a **proxy** certificate, and re-verifies the forwarded certificate against the user CA, or the internal CA for workers only. Integration-tested |
| E: worker forwards a user cert to act as that user | Only proxies may forward. A worker's direct calls resolve to the worker's identity, and user APIs reject it. Integration-tested |
| S: a worker forges or replays a grant | Grants are signed by a proxy key (verified against the internal CA, proxy kind only, domain-separated from other signatures), expire 60 seconds after issue, name the worker, carry the user certificate (its identity and roles must match), and have a nonce the worker remembers. The control plane allows one SSH certificate issuance per grant across replicas |
| S: a worker claims labels to receive sessions for other resources | Labels are signed into its certificate at enrollment. Proxies and the control plane only use certified labels |
| S: something other than a proxy joins peering | `limen-peer/1` requires a proxy certificate. The calling proxy pins the expected peer ID from the registry |
| T: rolled-back or stale policy on proxies and workers | Snapshots are signed by a control plane and versioned. Rollbacks are refused. Age counts from issue time, including across restarts. Past the grace period, decisions fail closed |
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
| E: a worker compromise exposes DB admin secrets (A4) | The secret is read only during reconcile and held in memory only. The IAM policy is scoped to that one secret ARN. The admin role should be a dedicated `limen_admin`, not the RDS master user (documented). Alternative: run bootstrap as a separate one-shot task with its own role (Phase 6 option) |
| E: a worker compromise lets it act as any `limen_*` DB role | `rds-db:connect` is limited to `dbuser:<id>/limen_*` per resource. Workers are deployed per VPC or account to limit blast radius |
| E: privilege escalation through kube impersonation (A6) | The worker strips client-supplied `Impersonate-*` headers and sets its own from the grant. The ClusterRole limits `groups` impersonation to `resourceNames` = the `limen:*` groups when the operator lists them, and must never include `system:masters`. Constrained impersonation (K8s ≥ 1.36) is planned hardening |
| E: SSH target cert too broad | Per-session cert: TTL 1 min to authenticate, one principal, key ID `limen:<session>:<user>`, only `permit-pty`. Issued once per proxy grant, after the control plane re-checks the grant, its own current policy, and the worker's labels. Port, agent, and X11 forwarding and environment variables are refused by the worker |
| S: a target impersonated toward the worker | Every SSH resource pins `host_key`. The worker refuses resources without one, and refuses any other key |
| S: the proxy (or anyone in the path) impersonates the worker toward the user's SSH client | The worker presents a per-session host certificate from the SSH host CA. The CLI's known_hosts trusts only that CA (`@cert-authority`, `StrictHostKeyChecking=yes`). Tested: a client trusting another CA refuses the worker |
| E: the user's SSH client authenticates to the worker with `none` | Only for the granted login, on a stream the worker received from a proxy with a signed grant it verified. A direct connection to a worker isn't possible (it listens nowhere) |
| E: a login SSH certificate used to bypass Limen | None exist. Targets only trust the SSH user CA, which signs per-session certificates on a grant (ADR-0007 amendment) |
| T: a compromised worker alters or drops recordings | **Residual until Phase 3.** The SHA-256 the worker reports is recorded by the proxy in `session.end`. Phase 3 ships recordings off the worker with signed manifests |

### TB4/TB5: Control plane ↔ Aurora, KMS, S3, Secrets Manager
| Threat | Mitigation |
|---|---|
| E: CA key theft (A1) | Keys live in KMS. `kms:Sign` is granted only to the control plane task role, with a key-policy condition on the signing algorithm. CloudTrail on `Sign`. Separate keys per purpose |
| T: policy tampering in Aurora (A9) | Policy versions are immutable rows. Snapshots are signed. `policy.change` is audited. The DB user has no `DELETE` on the policy tables |
| I: Aurora data exposure | Encryption at rest (KMS), TLS, IAM auth for the control plane DB user (Phase 13), no secrets stored (join tokens are hashed) |

### TB7: Browser ↔ proxy ↔ web console (ADR-0017)
| Threat | Mitigation |
|---|---|
| S: login CSRF / session fixation (an attacker's callback URL opened by a victim) | A login cookie must match the OIDC `state`; each state is single use; the session token is minted only after the callback, never accepted from the request |
| S: stolen console cookie | `__Host-` cookie, `HttpOnly`, `Secure`, `SameSite=Lax`, random 256-bit token (only its hash is stored), expires with the user's certificate lifetime, ended by a lock or sign-out. Limit: a stolen live cookie works until then; there is no device binding |
| T: CSRF on state-changing requests | POST only; per-session token compared in constant time; `Origin`/`Referer` must equal the public origin |
| T: XSS, clickjacking | Server-side templates escape by default; recording text only reaches the browser as data for the player; CSP forbids inline script and third-party origins; `frame-ancestors 'none'`. `'wasm-unsafe-eval'` is the one relaxation (vendored player). Limit: the player is third-party code running in the page |
| I: one user reads another's sessions or recordings | Non-admins are limited to their own rows in the query itself (not by hiding links); other users' sessions answer 404; recordings follow the same check |
| I: a tampered recording is played | Its hash is compared with the one recorded at session end; mismatch is refused |
| E: a non-admin reaches admin pages | Every admin page and action checks the role server-side; tests cover each |
| E: a worker or other component calls the console directly | Only a proxy certificate with the forwarded marker is accepted |
| D: sign-in flooding | Separate per-IP limiter for console login; login state rows expire in 10 minutes and are cleaned up |
| R: unattributed console changes | Every change is audited as the signed-in admin with `via=console` |
| I: sensitive data in the console's audit trail | The `audit_events` table stores only a fixed list of summary fields (never statements, claims, or payloads), is readable by admins only, and is trimmed after 30 days. The sinks remain the record |
| S: a stolen cookie lives longer now that sign-ins last 8 hours (A-console) | Lock, kill and every-request lock checks still end it at once; the lifetime is configurable (`LIMEN_CONSOLE_SESSION_TTL`) and capped by the maximum certificate lifetime. Limit: no device binding |

### TB8: CI platform ↔ control plane (bot login, ADR-0019)
| Threat | Mitigation |
|---|---|
| S: someone else's token (another repository, a fork's pull request, another branch) logs in as a bot | Exact claim matching with no wildcards; the validator refuses a repository alone, pull request refs and events, an unprotected GitLab ref, and `oidc` rules without an exact `sub`; a token matching two bots logs nobody in; GitHub tokens from pull request runs never match, whatever the rule says |
| S: a forged token, or one for another audience | Signature checked against the issuer's published keys (RS256, ES256, EdDSA only); `aud` must be the control plane's bot audience; `exp` honoured; `iat` required and no older than 15 minutes |
| S: the control plane is tricked into fetching keys from an attacker's issuer (SSRF) | Only issuers that a `bot` document names are contacted, chosen from the token's *unverified* `iss` against that allow-list; the signing keys must be on the issuer's own origin (a discovery document that points them elsewhere is refused, so a compromised issuer can't aim the control plane at an internal address); redirects are off; plain `http` issuers are refused unless the development flag is set |
| S/R: a leaked or intercepted token is reused | One login per token (its `jti`, or the hash of its signed part `header.payload`, is recorded until the later of its expiry and the end of its `iat` window, and only a login that issues credentials spends it; the signature is never part of it, because it can be altered without invalidating a token, and a token without a `jti` could otherwise be replayed under a different signature); a stolen, still-unused token works until it expires. Limit: a token minted for a job can be used by whoever holds it first; the short lifetime and the exact match narrow that |
| E: a person impersonates a bot (or the reverse) | `bot:` names are reserved: a person whose IdP name starts with it is refused; the certificate marker and the prefix must agree at issuance and at every verification; bot certificates can't carry built-in roles (the validator refuses them) |
| T: a bot keeps working after the repository is compromised | Lock works by name (login refused, open sessions end); credentials last at most an hour and never refresh; sessions are recorded |
| R: bot actions can't be tied to a run | `auth.login` and `session.start` carry the CI run (repository, workflow, run id, commit, ref, who triggered it); denied logins carry the refused run; every session and command event carries `actor_type` |
| I: tokens in logs or the audit trail | Tokens are never logged, audited, or placed in certificates; only a fixed list of claims (the "CI facts") is kept, clipped and stripped of control characters; the Phase 4 demo checks the audit file and the service logs for the token and its signature |
| D: login flooding | The same per-IP limit as people's logins (30 a minute, bursts of 10) |
| Limit | The CI platform is trusted for what its tokens claim. Everything here is verified against a stand-in issuer, not real GitHub or GitLab tokens |

### TB6: Audit sinks and dashboards
| Threat | Mitigation |
|---|---|
| R: a compromised user keeps working after the admin notices | `limen admin lock` and `kill-session`: signed snapshot carries them, enforced at login, certificate issuance, proxy, and worker; open sessions end within about 11 s. Limit: credentials the user already used on a target (a background process) aren't recalled |
| T: tampering with audit batches (A8) | Per-writer hash chain plus signed manifests. Optional S3 Object Lock in compliance mode. A separate KMS key. Bucket policy denies delete except to lifecycle. `limen-audit-verify` (a CLI subcommand comes later). Limit: a signed chain proves a batch was altered or removed, not that the control plane never wrote a false event; and the tail after the last manifest isn't covered until the next batch lands |
| R: an insider evades audit through protocol tricks | PG: extended protocol, `COPY`, multi-statement, and `DO` blocks are all logged at the wire level, not through SQL parsing. MySQL: `COM_STMT_PREPARE`/`EXECUTE`, multi-statements. Redis: `MULTI`/`EXEC`, `EVAL`/`EVALSHA` (the script body is logged, args redacted), pipelining. Kube: exec recorded, port-forward audited. Unparseable input is logged raw as `statement_type=unknown` |
| D: audit pipeline loss | Local fsynced spool, at-least-once delivery, fail-closed by default, producer `seq` gap detection |
| I: sensitive data in audit (PII in SQL literals, Redis values) | Redis values redacted by default. SQL full text by default (owner decision), with per-resource literal normalization. Bound parameters redacted by default. Access to the bucket and Grafana is limited to auditors |
| S: Grafana access | Okta OIDC, auditor and admin groups only. Read-only Athena role (`reader_policy_json` in the audit module). The dev stack's Grafana allows anonymous viewers and an open Trino: development only |

## 5. Cross-cutting

| Concern | Control |
|---|---|
| Secrets in logs | `Secret<T>` (no `Serialize`, redacted `Debug`). Log scanner test. Tokens never in URLs |
| Input validation | Strict serde (`deny_unknown_fields`), size caps on every frame and request, label and name validation (`limen-core::labels`) |
| Rate limiting | `governor`: per IP before auth, per user after, stricter for login and enrollment |
| Supply chain | `cargo-deny` (advisories, licenses, sources, bans), `cargo-audit`, pinned toolchain and tools (mise), GitHub Actions pinned to commit SHAs, minimal `permissions:` in workflows, distroless images, SBOM in release (Phase 13) |
| Memory safety | `unsafe_code = "forbid"` workspace-wide. Hand-written protocol codecs (MySQL, RESP) are fuzzed |
| Dev CA persistence | Dev compose only: the file-backend CA key and certificate live in the external Docker volume `limen-dev-ca`, so `down -v` and worktrees keep one CA. Same exposure as the old `cp-ca` volume (readable by anyone with Docker access); nothing is trusted automatically and no key is on the host filesystem. The certificate is also kept next to the key as a seed only: the database stays the source of truth, a file that doesn't match the key is ignored. Production uses KMS (ADR-0007) |
| Clock skew | Certs are back-dated 1 minute. TTL checks allow ±2 minutes |

## 6. Accepted residual risks (v1)
1. A compromised proxy can replay observed user certs toward the control plane for up to the cert TTL (it can't do TLS as the user without the key).
2. A local process on the user's machine can use an open loopback listener during its lifetime.
3. A compromised worker sees the plaintext of the sessions it serves, and can act as the `limen_*` DB roles of its resources.
4. Duplicates in Datadog under failure (at-least-once).
5. Revocation is TTL-based (no immediate lock in v1. `lock` is an extension point).
6. Device-flow logins aren't bound to the CLI's key (no nonce in RFC 8628). PKCE is the default and is bound.
7. Until IAM join exists (Phase 13), autoscaled proxies and workers enroll with a static, kind-scoped token.
8. Until Phase 3, recordings sit on the worker's disk, protected only by file permissions and the hash in `session.end`.

## 7. Review log
| Date | Phase | Change |
|---|---|---|
| 2026-10-13 | 0 | Initial model |
| 2026-10-14 | 1 | Device-flow binding gap; static join tokens; relay header spoofing; worker forwarding. Identity moved to URI SANs |
| 2026-10-14 | 2 | SSH: per-session certificates, host CA for workers, `none` auth on authorized streams, pinned target host keys, grant forgery and replay, certified labels, peering identity, snapshot rollback; recording tampering is a residual until Phase 3 |
| 2026-10-15 | dev | Dev CA key and certificate kept in an external Docker volume so resets and worktrees share one CA; dev only, trust never automatic |
