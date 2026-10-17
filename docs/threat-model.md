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
| S: another local process or user connects to the CLI's loopback DB or Redis listener and rides the session | **Known risk.** Mitigations: bind to 127.0.0.1 only. `--socket` puts a unix socket in a 0700 directory. Each listener serves one target and closes after an hour with no connection. A unix socket (`--socket`) has mode 0600. A non-loopback `--listen` prints a warning. Sessions are audited under the user. Documented in the user guide |
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
| E: a worker compromise exposes DB admin secrets (A4) | **Built (Phase 6):** the admin password is a file the bootstrap reads only while reconciling, held as `Secret<String>` and never logged or put in an event. Bootstrap is a separate one-shot task (`--db-bootstrap-once`) with its own admin secret by default; the in-process loop is opt-in (`--db-bootstrap-interval`), so the data-path worker normally never holds it. The admin should be a dedicated `limen_admin`, not the RDS master user (documented). Secrets Manager (`admin_secret_arn`) is not supported yet; the IAM policy for it is future work |
| E: a worker compromise lets it act as any `limen_*` DB role | `rds-db:connect` is limited to `dbuser:<id>/limen_*` per resource. Workers are deployed per VPC or account to limit blast radius. In secret mode the worker holds each role's password file (mode 0600, directory 0700) and can use them: scope `password_dir` to the resources a worker serves |
| S: a database target impersonated toward the worker (Phase 6) | TLS is mandatory with `verify-full` against the resource's `tls_ca_file` (and `tls_server_name`). `insecure_dev` is refused unless the worker was started with `--allow-insecure-db-targets`. MySQL logins that would send a clear-text password refuse to without TLS. Tested with a wrong certificate name |
| I: statement text in the audit trail holds secrets a user typed (Phase 6, A8) | Full text is the default (owner decision), so the audit store and its readers are as sensitive as the databases. `normalize_literals` per resource replaces literals; parameters and result data are never logged; text over 256 KiB is truncated with a hash. Reading audit data is not yet role-gated: the auditor role and search (ADR-0026, Phase 6.5) are where that lands. The console also keeps each database session's statements (text cut at 16 KiB) in the control plane's database for its session page: only admins and the session's own user can open it, and the same `normalize_literals` text is what is stored. `audit_events` summaries still carry no statement text |
| E: a user escapes the granted role or database inside a session (Phase 6) | The worker accepts only the granted role and database at startup, refuses `COM_CHANGE_USER`, `USE`, replication, and startup `options`, and does not offer `LOCAL INFILE`. `SET ROLE` is not blocked; bootstrap keeps `limen_*` roles members of nothing and reports drift, so there is no role to switch to. Statement-level restrictions are the database's grants, not Limen's: a role that can drop a table lets its users drop it, audited |
| T/D: users on the same database role cancel or kill each other's queries (Phase 6) | **Residual risk.** The database lets a role manage its own sessions (`pg_cancel_backend`, `KILL`). Limen translates and checks only the cancel messages and the exact `KILL <id>` form; a prepared `KILL` or function call isn't caught. Use separate roles where that matters |
| D: a client sends unbounded frames to the worker's database relay (Phase 6) | Frames Limen reads in full are capped at 64 MiB (startup packets at 10 KB); everything else is streamed. Idle sessions end after an hour; sessions end at `max_session_ttl`. Fuzzing the protocol framing is deferred (listed in the design doc) |
| E: SQL injection into the bootstrap (Phase 6) | Role names are validated (`limen_` plus `[a-z0-9_]`) in policy and again in the worker; other identifiers are quoted (`"` doubled, backticks doubled) and literals escaped, with `standard_conforming_strings` checked. Unit-tested with hostile strings; the integration tests use fixed names |
| I: AWS credentials on the worker for IAM auth (Phase 6, A5) | The default credential chain, never stored by Limen. Tokens live for the connect only and are `Secret`-wrapped. Redshift credential calls go to AWS (or `AWS_ENDPOINT_URL_REDSHIFT*`, set by the operator, never by policy, so policy can't redirect signed requests). **Unverified against real AWS** |
| S: weak MD5 password exchange (Phase 6) | Used only when the database asks for it (Redshift, or PostgreSQL configured with `md5`), and always inside TLS. Limen prefers SCRAM |
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

### TB9: Control plane replicas (scale-out, ADR-0020)
| Threat | Mitigation |
|---|---|
| S: something other than a live control plane calls `AuditHandoff/Handoff` and plants audit events | The caller must present a control plane certificate directly (not forwarded by a proxy) **and** have a row in `control_plane_replicas` with a fresh heartbeat; proxies, workers, users, and unregistered certificates get `permission_denied`. The sender, in turn, checks the receiver's certificate is a control plane with the id the registry lists. Integration-tested |
| T: a registered replica injects events for any producer | **Accepted.** A holder of a CA-issued control plane certificate and a registry row already holds the CA key and the database, which are higher trust than the audit trail's writers. Handed-off events keep their original producer and `seq`, so the verifier shows any conflict (one `seq` used by two events) |
| D: a peer fills another replica's spool through handoff | The spool has a size limit and refuses when full (fail closed); the call is bounded by the sender's deadline. No per-stream size cap or idle timeout (the caller is trusted). Known |
| T: tampering with `control_plane_replicas` (a new table in the A11 store) | Rows hold ids, advertised URLs, and heartbeats only, no secrets. Whoever can write the table can already change policy. Heartbeats carry an ownership token, so a stalled replica cannot refresh or delete the row of the replica that took its id |
| S: a second replica reuses an id and corrupts a replica's audit chain | Registration refuses an id with a fresh heartbeat; a replica that loses its id shuts down; a replica that cannot reach the database for 8 seconds stops writing to S3 until it can (the row only goes stale at 15 seconds), so two processes never write one manifest chain. Residual: an S3 write already in flight when the fence goes up |
| S/E: the spool-adopt tool as a way to read or inject audit events | `limen-spool-adopt` needs the control plane's environment (database URL, CA access), registers a short-lived `spool-adopt-<random>` row (live for as long as the tool runs, and up to 15 seconds after a crash), and sends only through the same handoff call. It opens the spool under a file lock |
| R/D: audit events lost when a replica dies | `durable` mode (volume per replica): none. `ephemeral` mode killed without warning: events acknowledged and not yet shipped are lost, up to the sink flush interval; **residual risk**, visible as sequence gaps in the verifier. Graceful stops lose nothing (drain, then handoff) |
| T: a proxy retries a call that was already processed | A relayed call is resent only when the request provably was not processed: a request with a body whose body was never read, or a GET or HEAD whose error shows the connection went away before the control plane could act (GOAWAY, refused stream). Never for an empty-body POST or any other error, so the console's sign-in callback is not replayed. A worker's refusal for capacity or drain is returned before the session's first byte, so another worker can be tried |
| S: a token holder names a component to confuse operators or audit (impersonation by name) | Names are display only: certificates, policy, revocation, and audit attribution use the id. A name must be approved by the join token (exact or a pattern), is unique among live proxies and workers, and is certified as a label so it cannot change; policy refuses a `worker_selector` on it and the matcher ignores it. A refused enrollment (not approved, or already in use) is audited as `auth.denied` |
| D: a token holder squats names (takes `prod-a-1` first) | Limited to the token's approved pattern; an admin revokes the squatter and the name is free again. A component whose enrollment reply was lost cannot re-enroll under its name until the orphan is revoked |
| D: login and connection limits multiplied by replicas, or too low behind one egress IP | The control plane's login limit and the proxy's pre-authentication accept limit are per client IP and per replica (abuse guards, not authorization); rates and bursts are settings (defaults 30 a minute, burst 10; 50 a second, burst 200). A site behind one address should raise them |
| T: test-only settings reach a release build | The long report interval and similar overrides sit behind the `test-hooks` Cargo feature, enabled only by `limen-e2e`; release images are built with `--bin` for named binaries that do not depend on it |

### TB6: Audit sinks and dashboards
| Threat | Mitigation |
|---|---|
| R: a compromised user keeps working after the admin notices | `limen admin lock` and `kill-session`: signed snapshot carries them, enforced at login, certificate issuance, proxy, and worker; open sessions end within about 11 s. Limit: credentials the user already used on a target (a background process) aren't recalled |
| T: tampering with audit batches (A8) | Per-writer hash chain plus signed manifests. Optional S3 Object Lock in compliance mode. A separate KMS key. Bucket policy denies delete except to lifecycle. `limen-audit-verify` (a CLI subcommand comes later). Limit: a signed chain proves a batch was altered or removed, not that the control plane never wrote a false event; and the tail after the last manifest isn't covered until the next batch lands |
| R: an insider evades audit through protocol tricks | PG: extended protocol, `COPY`, multi-statement, and `DO` blocks are all logged at the wire level, not through SQL parsing. MySQL: `COM_STMT_PREPARE`/`EXECUTE`, multi-statements. Redis: `MULTI`/`EXEC`, `EVAL`/`EVALSHA` (the script body is logged, args redacted), pipelining. Kube: exec recorded, port-forward audited. Unparseable input is logged raw as `statement_type=unknown` |
| D: audit pipeline loss | Local fsynced spool, at-least-once delivery, fail-closed by default, producer `seq` gap detection |
| I: sensitive data in audit (PII in SQL literals, Redis values) | Redis values redacted by default. SQL full text by default (owner decision), with per-resource literal normalization. Bound parameters redacted by default. Access to the bucket and Grafana is limited to auditors |
| S: Grafana access | Okta OIDC, auditor and admin groups only. Read-only Athena role (`reader_policy_json` in the audit module). The dev stack's Grafana allows anonymous viewers and an open Trino: development only |

### TB9: GitHub Actions ↔ self-hosted runners (CI)
Pull request code runs on the owner's machines: a macOS runner and two OrbStack VMs on it, under the owner's user account. See [the CI runbook](runbooks/ci-runners.md).

| Threat | Mitigation |
|---|---|
| E: a pull request runs commands on the owner's machines (a PR's workflow is code) | The repository is private, so only collaborators can open pull requests. Keep it private, and never point the runners at forks or public repositories. Limit: anyone who can push a branch can run code on the runners |
| E: a workflow reads the owner's files or secrets | The Linux VMs are separate from the Mac. Workflows use `permissions: contents: read`. Publishing secrets are used only by `release.yml`, which runs on hosted runners. Limit: the macOS runner runs as the owner's user, so a workflow there can read the laptop's files |
| T: one job leaves state for the next | Each VM runs one job at a time. The checkout cleans the workspace (`git clean -ffdx`). The macOS runner is not isolated per job |
| I: the checkout token leaks into logs or onto disk | The fetch step passes the token through the environment (`GIT_CONFIG_*`) and writes no credentials into `.git/config`. Nothing echoes it |
| S: a workflow change that weakens CI | `.github/` changes run the full suite and `actionlint`. Only repository admins can set the `CI_RUNNERS` variable |
| D: a runner stops or runs out of memory mid-job | Every job has a timeout. Integration tests compile two crates at a time on the 8 GiB VM. A lost runner fails its job, which is then rerun by hand |

Residual: the macOS runner has the owner's user access, which the owner accepts for a private repository. Forks and public repositories would change that, so they're out of scope.

## 5. Cross-cutting

| Concern | Control |
|---|---|
| Secrets in logs | `Secret<T>` (no `Serialize`, redacted `Debug`). Log scanner test. Tokens never in URLs |
| Input validation | Strict serde (`deny_unknown_fields`), size caps on every frame and request, label and name validation (`limen-core::labels`) |
| Rate limiting | `governor`: per IP before auth, per user after, stricter for login and enrollment |
| Supply chain | `cargo-deny` (advisories, licenses, sources, bans), `cargo-audit`, pinned toolchain and tools (mise), GitHub Actions pinned to commit SHAs, minimal `permissions:` in workflows, distroless images, SBOM in release (Phase 13) |
| Memory safety | `unsafe_code = "forbid"` workspace-wide. Hand-written protocol codecs (MySQL, RESP) are fuzzed |
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
| 2026-10-15 | CI | Self-hosted runners run pull request code on the owner's machines (TB9). Private repository only |
| 2026-10-17 | 6 | SQL databases: verified TLS to targets, secret files and the bootstrap admin, statement text in audit, role and database guards, shared-role cancel and kill (residual), SigV4 and Redshift credential calls (unverified), injection into bootstrap SQL, frame limits |
