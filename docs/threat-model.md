# Limen threat model

Status: **Living document**. Last reviewed for Phase 12. Method: STRIDE per trust boundary, plus abuse cases. Review this document in every phase that adds an entry point, a credential type, or a data store. A PR that adds any of those must update it.

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
| A12 | Web app handoffs, signed browser sessions, and identity assertions | Replaying a handoff or forging identity to an upstream app |
| A13 | Web request audit projection | Request metadata supports investigations; accidental payload or query capture would expose user data |

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
[Browser] ──TB10── [Proxy] ──TB2── [Worker] ──TB10── [Web app]
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
| S: stolen user cert and key | 10-minute TTL. Keys stored with 0600. Optional OS keychain (Phase 14) |
| S: another local process or user connects to the CLI's loopback DB, Redis, MongoDB, search, RabbitMQ, or Kafka listener and rides the session | **Known risk.** Mitigations: bind to 127.0.0.1 only. `--socket` puts a unix socket in a 0700 directory. Each listener serves one target and closes after an hour with no connection. A unix socket (`--socket`) has mode 0600. A non-loopback `--listen` prints a warning. Sessions are audited under the user. Documented in the user guide |
| T/I: downgrade or MITM | TLS 1.3 only (rustls). Public cert pinned through system roots plus an optional pin of the Limen CA |
| D: connection floods, handshake CPU exhaustion | NLB plus a per-IP pre-auth rate limit and a concurrent handshake cap. Max sessions per user |
| E: malformed `SessionRequest` | Strict schema, size limits, `deny_unknown_fields`. Fuzzed in Phase 14 |
| I/E: detached connections (`--detach`, ADR-0039) keep a listener open after the terminal closes, and leave a state file and log on disk | They hold no credential (the process reads the 0600 profile like any command). State and log files are mode 0600 under `$LIMEN_HOME/conns/`. The process ends at certificate expiry, on `limen logout`, on `limen conns stop`, or after the idle timeout (default 1 h). The listener risk is the one in the row above; a detached listener lasts longer, so `limen conns ls` shows every one |
| S/E: a client sends its own identity to the Kubernetes route (`Authorization`, `Impersonate-*`, `X-Remote-*`, `X-Limen-*`) to act as someone else (ADR-0038) | `/k8s/<cluster>/` takes the user from the mTLS certificate only, verified against the user CA. The proxy and then the worker both strip those headers; the worker sets the impersonation from the signed grant. Paths with dot segments, empty segments, or encoded slashes and dots are refused, so audit and API server read a path alike. Tested end to end (stand-in) and on kind (`kubectl --as=system:admin` is ignored) |
| E: the `/k8s/` route is a new HTTP entry point that upgrades connections (exec, attach, port-forward) | It answers only for a verified user certificate and a cluster policy grants. Only `exec`, `attach`, and `portforward` on pods may upgrade, anything else that asks is a 403. Connections with no ALPN are served as HTTP/1.1 and reach only `/console/` and `/k8s/`. Locks, kills, grant expiry, and worker revocation end an open stream, and cut a streaming response (`watch`, `logs -f`), within a second (proxy and worker both check; tested) |
### TB10: Browser ↔ proxy ↔ worker ↔ internal web app (ADR-0022)
| Threat | Mitigation |
|---|---|
| S/E: a browser replays a handoff or app session at another app | OIDC state and handoffs are one-use, short-lived, and bound to resource and exact host; the signed app session also carries and verifies the user certificate, login, resource, host, and expiry. The `__Host-` cookie is Secure, HttpOnly, SameSite=Lax, host-only, and removed before forwarding |
| E: a browser app session outlives authorization | Every request checks the current proxy policy snapshot, deny rules, user lock/restrictions, and session expiry. Bots are refused browser sessions; session lifetime is capped by the user certificate |
| S/E: a client spoofs an upstream identity or routing header | The proxy rejects host/SNI/authority mismatch, routes only to an exact policy host and fixed worker target, strips inbound Limen/forwarding headers, and adds signed identity headers only when the resource explicitly enables them. Apps must verify ES256 JWT issuer, audience, key ID, and expiry |
| E: a sibling internal app or a long-lived WebSocket rides a user's session | App cookies are host-only and `SameSite=Lax`, but sibling hosts are same-site, so a WebSocket handshake must carry an `Origin` that names the app (else `auth.denied`, `websocket_origin_denied`). An upgraded stream is no longer re-authorized per request, so it is closed at app-session expiry (`session_expired`). Plain cross-app `fetch`/form requests are the app's own CSRF concern (residual risk) |
| I: web queries, cookies, bodies, or credentials enter audit | `web.request`, `web.response`, and WebSocket-end events contain bounded path and request/outcome metadata only; query, payload, cookie, authorization values, and upstream error text are excluded. Unauthenticated requests and denials emit `auth.denied`; audit failure blocks forwarding and successful handoff |
| E: an upstream target is impersonated or a worker is used as an open proxy | The worker connects only to the resource's fixed `address`; HTTPS certificate verification is required unless an explicit development-only target opt-in is enabled at both policy and worker. No `CONNECT`, client-selected destination, or unsupported upgrade is forwarded |

### TB2/TB2′: Proxy ↔ worker (tunnel) and worker/proxy ↔ control plane
| Threat | Mitigation |
|---|---|
| S: rogue worker enrolls | Single-use join tokens with a 15-minute TTL, stored hashed and consumed atomically. Bound to allowed kinds and labels. `worker.enroll` audit plus an alert on enrollment |
| S: leaked static join token (ADR-0016) | Kind-scoped. Proxies enrolled with one may only request allow-listed DNS names, and workers get no DNS names, so a leaked worker token can't mint a server certificate. Audited with `token_type=static`. Stored in Secrets Manager and rotated. Replaced by IAM join in Phase 14 |
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
| I: statement text in the audit trail holds secrets a user typed (Phase 6, A8) | Full text is the default (owner decision), so the audit store and its readers are as sensitive as the databases. `normalize_literals` per resource replaces literals; parameters and result data are never logged; text over 256 KiB is truncated with a hash. Reading audit data is not yet role-gated: the auditor role and search (ADR-0026, Phase 13) are where that lands. The console also keeps each database session's statements (text cut at 16 KiB) in the control plane's database for its session page: only admins and the session's own user can open it, and the same `normalize_literals` text is what is stored. `audit_events` summaries still carry no statement text |
| E: a user escapes the granted role or database inside a session (Phase 6) | The worker accepts only the granted role and database at startup, refuses `COM_CHANGE_USER`, `USE`, replication, and startup `options`, and does not offer `LOCAL INFILE`. `SET ROLE` is not blocked; bootstrap keeps `limen_*` roles members of nothing and reports drift, so there is no role to switch to. Statement-level restrictions are the database's grants, not Limen's: a role that can drop a table lets its users drop it, audited |
| T/D: users on the same database role cancel or kill each other's queries (Phase 6) | **Residual risk.** The database lets a role manage its own sessions (`pg_cancel_backend`, `KILL`). Limen translates and checks only the cancel messages and the exact `KILL <id>` form; a prepared `KILL` or function call isn't caught. Use separate roles where that matters |
| D: a client sends unbounded frames to the worker's database relay (Phase 6) | Frames Limen reads in full are capped at 64 MiB (startup packets at 10 KB); everything else is streamed. Idle sessions end after an hour; sessions end at `max_session_ttl`. Fuzzing the protocol framing is deferred (listed in the design doc) |
| E: SQL injection into the bootstrap (Phase 6) | Role names are validated (`limen_` plus `[a-z0-9_]`) in policy and again in the worker; other identifiers are quoted (`"` doubled, backticks doubled) and literals escaped, with `standard_conforming_strings` checked. Unit-tested with hostile strings; the integration tests use fixed names |
| I: AWS credentials on the worker for IAM auth (Phase 6, A5) | The default credential chain, never stored by Limen. Tokens live for the connect only and are `Secret`-wrapped. Redshift credential calls go to AWS (or `AWS_ENDPOINT_URL_REDSHIFT*`, set by the operator, never by policy, so policy can't redirect signed requests). **Unverified against real AWS** |
| S: weak MD5 password exchange (Phase 6) | Used only when the database asks for it (Redshift, or PostgreSQL configured with `md5`), and always inside TLS. Limen prefers SCRAM |
| E: privilege escalation through kube impersonation (A6) | Paths containing an encoded letter, digit, or `-._~` (`%73ecrets`) are refused, and the audit classification decodes the path and the query as the API server does, so a request cannot be logged as something else. The worker strips client-supplied `Impersonate-*` headers and sets its own from the grant. The ClusterRole limits `groups` impersonation to `resourceNames` = the `limen:*` groups when the operator lists them, and must never include `system:masters`. The worker also refuses grants for a user named `system:*` (it would inherit that built-in identity's RBAC) and for `system:*` groups, whatever policy or a proxy says. Constrained impersonation (K8s ≥ 1.36) is planned hardening |
| E: a Kubernetes stream is not recorded because the worker cannot read it (ADR-0038) | The worker offers the API server only the binary channel protocols (never `base64.*`), removes `Sec-WebSocket-Extensions` so frames are never compressed, and after the upgrade checks what the server agreed to. A protocol it cannot decode, a malformed frame, or a recording write failure ends the stream (audit fails closed). Output is on tape before it reaches the user |
| I: a recording of `kubectl exec` leaks secrets typed at a prompt | stdin is never recorded (as with SSH). Output is, and can contain secrets a command prints. Recordings are as sensitive as the session (A7) |
| E: the kube worker's token (A6) is used from somewhere else | It can only impersonate, never act as itself (no other verbs in the ClusterRole). The token is read from the pod's projected file (rotated, short-lived) and never logged (`Secret`). Anyone holding it can act as any user and, unless `resourceNames` limits it, any group, so treat it like a signing key |
| E: SSH target cert too broad | Per-session cert: TTL 1 min to authenticate, one principal, key ID `limen:<session>:<user>`, only `permit-pty`. Issued once per proxy grant, after the control plane re-checks the grant, its own current policy, and the worker's labels. Port, agent, and X11 forwarding and environment variables are refused by the worker |
| S: a target impersonated toward the worker | Every SSH resource pins `host_key`. The worker refuses resources without one, and refuses any other key |
| S: the proxy (or anyone in the path) impersonates the worker toward the user's SSH client | The worker presents a per-session host certificate from the SSH host CA. The CLI's known_hosts trusts only that CA (`@cert-authority`, `StrictHostKeyChecking=yes`). Tested: a client trusting another CA refuses the worker |
| E: the user's SSH client authenticates to the worker with `none` | Only for the granted login, on a stream the worker received from a proxy with a signed grant it verified. A direct connection to a worker isn't possible (it listens nowhere) |
| E: a login SSH certificate used to bypass Limen | None exist. Targets only trust the SSH user CA, which signs per-session certificates on a grant (ADR-0007 amendment) |
| T: a compromised worker alters or drops recordings | **Residual until Phase 3.** The SHA-256 the worker reports is recorded by the proxy in `session.end`. Phase 3 ships recordings off the worker with signed manifests |
| E: a RabbitMQ or Kafka session does something its role doesn't allow (publish, declare, produce, create topics, read another topic or group) | The worker decodes every client method (AMQP) or request (Kafka) and checks the role's grant before forwarding; unknown methods, API keys, and versions are refused. A refused AMQP method closes its channel (403); a refused Kafka topic is cut out of the request and answered `TOPIC_AUTHORIZATION_FAILED`. `*` never opens `amq.rabbitmq.*` or internal topics. The broker's own ACLs are the second layer. A declare that names a dead-letter or alternate exchange needs `write` on it, as RabbitMQ requires, so queue arguments can't route around a publish restriction |
| I/R: a message body, record value, or broker credential reaches the audit trail | Bodies, properties, record keys and values are never read into an event (only a publish's size, and a produce's byte count). Credentials are `Secret`s in the worker; the client's own login is discarded. Tested by searching the trail for planted values |
| S: Kafka clients are sent to broker addresses the user could not otherwise reach, or to another user's listener | The worker rewrites advertised addresses only to the loopback ports the user's own CLI declared (validated 1 to 65535, at most 64). Each broker slot is a separate audited session through the same grant; the CLI binds loopback only |
| D: a client floods the audit trail or the worker's memory with names | One event lists at most 32 names of at most 256 characters (with the total beside them), so a request naming thousands of topics is not an event that size; the per-topic audit window state is capped at 4096 entries per session |
| D: oversize or malformed frames exhaust the worker | AMQP frames over the negotiated 131072 bytes end the session (501); Kafka messages over 128 MiB (responses 256 MiB) are refused and array lengths are bounded by the bytes left. The audit backlog for a client that isn't reading is capped |
| E: a Redis session runs a command its role doesn't allow, or reaches keys it shouldn't | The worker checks every command against the role's grant (deny list, `allow_commands`, key patterns) before forwarding it, and the target's own ACL for the Redis user is the second layer. Key positions come from the target's `COMMAND INFO`; a command whose keys can't be located is refused for key-restricted grants. Scripts are refused for them, and so are `CLIENT TRACKING`, `PUBSUB CHANNELS`, and subscriptions that could deliver keyspace or key-event notifications. Commands with subcommands (`OBJECT`, `XINFO`, `XGROUP`, `MEMORY`) are checked by subcommand; a command the target's table doesn't list is refused. A grant covers only the databases it names, tracked per `SELECT`. *Limit:* the worker's check is only as good as that table, and ordinary Pub/Sub channels are not key-limited |
| I/R: a Redis value or credential reaches the audit trail | Values are not in `redis.command` unless the target opts in; `AUTH`, `HELLO`, `ACL`, `MIGRATE`, `CONFIG` arguments never are. The client's `AUTH` is dropped, and the target password is a `Secret` read from the worker's credentials file or signed per login. *Limit:* key names are logged in the clear unless `audit.redact_keys` is set, and a plain hash of a guessable key can be guessed |
| T: pipelined or `MULTI` commands slip past the check | Every command is parsed from the wire and checked and audited individually, in order; `MULTI`/`EXEC` queue commands that were each checked. Replies are matched to commands by a queue, so a refused command cannot shift a later reply onto the wrong command. Pub/Sub switches to pass-through for replies only; commands are still checked |
| D: a client floods the worker with large frames | One request or reply is capped at 256 MiB; line, nesting, and element counts are capped; the session ends on a violation. *Residual:* many sessions each holding large frames use memory; a worker's `--max-sessions` cap (default 200) bounds the number of sessions, but not their frames; a memory budget per worker is Phase 14 |
| E: a MongoDB session reaches a database or runs a command its role doesn't allow | Every command's `$db` is checked at the worker against policy (grants, wildcards, deny rules) and refused as `Unauthorized`; `deny_commands` refuses named commands; `admin` is closed except read-only metadata; `$external` is refused. The server's own grants for the MongoDB user are the real boundary and the second layer: a command Limen lets through that the server refuses is in the trail with the server's error code. `$out`, `$merge`, `$lookup`, `$graphLookup`, and `mapReduce` targets that name another database are walked out of the command (at any depth) and checked the same way. *Limit:* policy is by database and command name, not by collection or operation, and a namespace given in some form the worker doesn't recognize is left to the server's grants |
| S/E: a MongoDB client logs in as someone else, or swaps the identity | `authenticate`, `saslStart`, `saslContinue`, and `logout` are refused; the worker's login is made before the client's first byte is read, and the client never sees a credential. A connection string with credentials fails with a clear message |
| E: one session reads another's cursor | Sessions of the same role share a server login, and cursors belong to the login. The worker records the cursor ids each session was given and refuses `getMore` and `killCursors` for any other (`CursorNotFound`); ids are 63-bit random, so guessing isn't practical either. Up to 10,000 cursors per session are tracked. *Limit:* server sessions (`lsid`) are likewise shared by login; their ids are random UUIDs |
| I/R: a MongoDB value or credential reaches the audit trail | `mongo.command` keeps the command, collection, and the shape of the command with every value replaced by `?` (inserted documents are only counted); `full_commands` is an explicit opt-in per resource and still redacts fields named like secrets. Server error text, which can quote data, is kept only with `full_commands`. The target credential is a `Secret` read from a file per role (or a certificate, or the IAM chain) and never logged. *Limit:* collection and field names are kept, so a collection that stores data in its keys shows it; the audit text follows the same retention and access rules as other audit |
| T: framing tricks slip a command past the check or desynchronize the relay | Commands are parsed from the wire, checked, and audited one at a time, in order; `OP_COMPRESSED` is never offered; `exhaustAllowed` and the checksum are removed before forwarding, so the server never streams replies the worker isn't waiting for; a reply that doesn't answer the command (wrong `responseTo`, `moreToCome`) ends the session. `moreToCome` writes are audited as `unacknowledged`. A command cut off by a lock, kill, drain, TTL, or panic is recorded as `not_completed`, so no forwarded command lacks an outcome (*residual:* an instant-wide window between the start event and the guard that owes the end event). Unknown required flag bits, bad section kinds, lengths that lie, and BSON nested past 100 levels are rejected |
| D: a client floods the worker with large MongoDB messages | Commands are paced per session (`max_commands_per_second`, default 500 after a burst of 100), so a client in a loop can't flood the audit spool; they wait, they are not refused. One message is capped at 64 MiB (the server's own limit is 48 MB) and memory grows with the bytes received, not the length announced; one command runs at a time per session; idle sessions end after an hour; `--max-sessions` bounds the sessions per worker. *Residual:* many sessions each holding large messages use memory; a memory budget per worker is Phase 14. A command running when the client leaves keeps running on the server until it finishes (clients should set `maxTimeMS`) |
| T: a client sets another user's session `group` to merge their commands into its console page (MongoDB) | The group only labels rows. The console merges only sessions of the same user and resource, and the proxy keeps just a well-formed id (64 characters of `[A-Za-z0-9-]`). The audit trail never depends on it |
| S: the worker is tricked into signing for a hostile STS endpoint (`MONGODB-AWS`) | The worker signs only for hosts named `sts.*` made of letters, digits, `.` and `-`, with the server's nonce, and checks the nonce extends its own. *Unverified against Atlas and DocumentDB* |
| E: a search session reads or changes an index its role doesn't allow, or does more than its role's class | The worker classifies every request (`read`, `write`, `admin`; an unrecognised API is `admin` on every index) and checks each index it names, from the path and from the bodies of `_bulk`, `_msearch`, `_mget`, `_reindex`, `_aliases` and the references inside a search body (terms lookups, `_index`, indexed shapes, percolate), against the patterns of a single grant before forwarding. Hidden (`.`) indices need a pattern that starts with a dot. Gzip bodies are decoded to be read, with a size bound. The engine's own role for the login is the second layer. *Limits:* policy sees names, not what an alias or data stream points to; scroll and PIT ids name no index; responses are not filtered; SQL and PPL name tables in text and so need an unrestricted grant |
| T: a request is read one way by the worker and another by the engine | Paths with `.` or `..`, empty segments, encoded `/` or `\`, control characters, date math, cross-cluster names, and unusual index characters are refused before classification. What is classified is what is forwarded (path and query as sent, headers from an allowlist). Only `GET`, `HEAD`, `POST`, `PUT`, `DELETE` pass; the `source` query parameter is refused under an index restriction |
| E: a client smuggles its own credential or an impersonation header to the engine | Only an allowlist of headers is forwarded; `Authorization`, API keys, `es-security-runas-user`, `opensearch_security_impersonate_as`, `x-forwarded-*`, and the like are dropped, and the worker's credential and `X-Opaque-Id` are added. The demo checks that a superuser login sent by the client is not used |
| I: a search document, query, or credential reaches the audit trail | `search.request` has no body or query values unless the resource opts in (`audit.log_bodies`, `log_query`); security APIs are never body-logged; the engine's error text is not logged, only its type. Credentials are `Secret`s read from the worker's credentials file or signed per request. *Limit:* document ids are in the path in the clear unless `audit.redact_ids` is set |
| D: a client floods the worker with large bodies | Bodies the worker must read are capped (32 MiB by default, `--search-max-body-bytes`; the decoded size for gzip) and answered `413` beyond that; other bodies and all responses stream; connections idle for an hour end; the header section is bounded. *Residual:* many sessions each holding a large body use memory; `--max-sessions` bounds the number of sessions, not their bodies |

### TB4/TB5: Control plane ↔ Aurora, KMS, S3, Secrets Manager
| Threat | Mitigation |
|---|---|
| E: CA key theft (A1) | Keys live in KMS. `kms:Sign` is granted only to the control plane task role, with a key-policy condition on the signing algorithm. CloudTrail on `Sign`. Separate keys per purpose |
| T: policy tampering in Aurora (A9) | Policy versions are immutable rows. Snapshots are signed. `policy.change` is audited. The DB user has no `DELETE` on the policy tables |
| I: Aurora data exposure | Encryption at rest (KMS), TLS, IAM auth for the control plane DB user (Phase 14). Web state and handoff bearer tokens are hashes; login rows retain a PKCE verifier and nonce until expiry, and handoff rows retain a signed short-lived session. `web_requests` stores only user, resource, host, method, bounded path, status, byte counts, and duration—never query, headers, cookies, or bodies. Protect the database as credential-bearing control-plane state |

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
| I: Kubernetes request details in the console's Kubernetes tab (ADR-0038) | The `kube_requests` table keeps only the request's shape: user, cluster, verb, resource, namespace, name, status, latency. Never a body, query string, header, or the exec command. Each request is also grouped into a per-login console session (a row in `sessions`, derived from the login and cluster), readable by admins and by that user. Trimmed after 30 days, and a convenience copy: the signed events are in the sinks |
| E: a copy of a logged-out certificate keeps working (ADR-0038) | `limen logout` calls `Auth.Logout` (user certificate required; it ends only the caller's own login). The login id goes into `login_revocations` (kept until the certificate expires, however long it is configured to live) and the signed snapshot's `revoked_logins`; proxies, workers (every Kubernetes request, every new session) and SSH certificate issuance refuse it, and open sessions end within about 10 seconds. Audited (`auth.logout`, fail closed). Residual: the control plane's own API does not check revoked logins (same as locks), so a stolen certificate that is also an admin's can still call it until it expires |
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

### TB11: Access workflows (ADR-0025 to ADR-0030)
| Threat | Mitigation |
|---|---|
| E: approving your own request, through a second account or a shared group | The code refuses an approver equal to the requester (case-insensitive) and so does a database trigger; two approvals need two different people (one row per approver); the validator warns when `who` and `approvers` overlap. *Limit:* one human with two IdP accounts cannot be told apart from two people |
| E: a stale approver (left the group mid-flight) or a requester no longer eligible | Both are checked at approval time against today's policy and the groups the IdP reported at each person's latest login; the grant is clamped to today's `max_duration`. *Limit:* groups update when the person logs in |
| E: a grant outlives its purpose | The signed snapshot carries only unexpired grants; the proxy and worker compare the deadline with the clock on every decision; a session started under a grant is capped to its remaining time and ended when it leaves the snapshot; revoke also writes session kills; the per-session SSH certificate is capped to the grant. A lock and a deny override beat a grant |
| E: a grant opens more than was approved | A grant is scoped to the requested resource and role; the effective role is added only for that resource |
| T: a requestable role opens resources it shouldn't | `RequiresApproval` is a denial at every enforcement point (tests); only `evaluate_eligible`, used for telling people what to do, returns it |
| I: resource names leak in a notification | Default message: request id and console link only; details are opt-in; URLs must be https (or loopback); no redirects; webhook signed over timestamp and body; the URL is a secret and never logged |
| I: a notification carries the approval | It cannot: approval is only a signed-in console or API call |
| S/E: injection through the reason text | Plain text, length-limited, control characters refused, escaped when shown, never used in a shell or query; Slack markup is escaped; the ticket pattern is a linear-time regex with size limits |
| D: request flooding | One open request per person/role/resource; 20 open and 100 a day per person; pending requests lapse after 24 hours |
| I: search is a way to read everything | Only `limen:admin` and `limen:auditor`; every search is audited (`audit.search`, with the query, before it runs) and rate limited (30/min); statement text is masked for common secret shapes (best effort); recording text is off unless `--search-recordings` and is output only; retention 30 days |
| T/D: query injection or an expensive query | The query is parsed into typed filters, every value bound; at most 20 terms, 512 bytes, 200 hits; 10 s statement timeout |
| I: secrets reach the search index | Masked before indexing (passwords, tokens, keys, URLs with credentials); the index is a copy, the originals stay under the sinks' controls. *Residual:* masking is best effort |
| E: a tag steers a discovered resource into a role (ADR-0027) | Only `labels_from_tags` become labels; a new resource and any change to name, labels, or target wait for an admin (`auto_accept` only for named label keys, never name or target); `limen.io/*` labels are set from checked facts and win; the validator warns on roles selecting tag-derived labels |
| S/T: a compromised worker reports fake resources | The control plane makes names and labels; a report outside the document's accounts, regions, tag filter, and matchers is dropped; only workers named by `worker_selector` may report; everything lands pending |
| E: over-broad discovery IAM | The role (permissions listed in the discovery guide) grants only `Describe*`/`List*` for chosen sources and `ec2:GetConsoleOutput`; no `iam:PassRole`, no data plane |
| T: a hostile AWS answer exhausts the worker | The XML reader is bounded in size, depth, and nodes; paging is bounded |
| D/E: stale or vanished targets | Not seen for several *complete* scans, a resource is stale and refused; removed later, never from under an open session |
| E: an owner certifies their own access (ADR-0029) | Self-review is refused and routed to the admin pool; an admin cannot decide an item about themselves; overdue items escalate |
| T: evidence edited after export | The manifest of section hashes is signed by the control plane; the export is an audit event carrying the manifest hash; `limen-audit-verify --evidence` checks both offline; spreadsheet cells that would run as formulas are defused |
| I/E: silent surveillance of a live session (ADR-0030) | Every watch is audited and fails closed; the session page lists watchers; `notify_observed` tells the user; watching is a separate power from reading the record (`--auditors-may-watch`); you cannot watch yourself; output only |
| D: a watcher slows the user's session | Bounded rings and buffers that drop; nothing is sent unless watched; five watchers per session; the stream re-checks authorization every few seconds |

### TB6: Audit sinks and dashboards
| Threat | Mitigation |
|---|---|
| R: a compromised user keeps working after the admin notices | `limen admin lock` and `kill-session`: signed snapshot carries them, enforced at login, certificate issuance, proxy, and worker; open sessions end within about 11 s. Limit: credentials the user already used on a target (a background process) aren't recalled |
| T: tampering with audit batches (A8) | Per-writer hash chain plus signed manifests. Optional S3 Object Lock in compliance mode. A separate KMS key. Bucket policy denies delete except to lifecycle. `limen-audit-verify` (a CLI subcommand comes later). Limit: a signed chain proves a batch was altered or removed, not that the control plane never wrote a false event; and the tail after the last manifest isn't covered until the next batch lands |
| R: an insider evades audit through protocol tricks | PG: extended protocol, `COPY`, multi-statement, and `DO` blocks are all logged at the wire level, not through SQL parsing. MySQL: `COM_STMT_PREPARE`/`EXECUTE`, multi-statements. MongoDB: every `OP_MSG` is parsed and audited in order, `moreToCome` and exhaust are handled so no command goes unaudited. Redis: `MULTI`/`EXEC`, `EVAL`/`EVALSHA` (the script body is logged, args redacted), pipelining. Kube: exec recorded, port-forward audited. Unparseable input is logged raw as `statement_type=unknown` |
| D: audit pipeline loss | Local fsynced spool, at-least-once delivery, fail-closed by default, producer `seq` gap detection |
| I: sensitive data in audit (PII in SQL literals, Redis and MongoDB values) | Redis values and MongoDB command values redacted by default. SQL full text by default (owner decision), with per-resource literal normalization. Bound parameters redacted by default. Access to the bucket and Grafana is limited to auditors |
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

### TB12: Public website (ADR-0021)
A static site on GitHub Pages. It holds no Limen data and talks to no Limen component, so it is not an entry point to a deployment. Its risks are to its visitors and to the build.
| Threat | Mitigation |
|---|---|
| T: a compromised npm package changes the site, or runs in CI | Exact versions and a lockfile, `npm ci`, `npm audit` in CI, Dependabot, actions pinned by SHA. The deploy job has only `pages: write` and `id-token: write`, and runs only from `main` |
| I: the site tracks or leaks visitors to a third party | Fonts and scripts are self-hosted and `check-site.mjs` fails the build on any request to another origin. No analytics or cookies |
| S: marketing says more than is true (a claim that misleads operators) | ADR-0031's "will not claim" list is enforced by `check-site.mjs`; the homepage and the status page say what is unverified |
| T: a documentation page drifts from the repository | Pages are generated from `docs/` at build time, not copied |

## 5. Cross-cutting

| Threat | Mitigation |
|---|---|
| E: a TCP client turns Limen into an open proxy or reaches an unapproved target | `limen tcp` sends only the resource name. The proxy authorizes `TcpAccess`; the worker connects only to the `address` in that resource's signed policy snapshot. No destination is accepted from the client. Restrict worker egress at the network layer. |
| I: raw TCP payloads are captured in audit | The relay never parses or logs stream bytes. Proxy session start/end events record actor, resource, duration, byte counts, and reason; no payload or recording is produced. |

| Concern | Control |
|---|---|
| Secrets in logs | `Secret<T>` (no `Serialize`, redacted `Debug`). Log scanner test. Tokens never in URLs |
| Input validation | Strict serde (`deny_unknown_fields`), size caps on every frame and request, label and name validation (`limen-core::labels`) |
| Rate limiting | `governor`: per IP before auth, per user after, stricter for login and enrollment |
| Supply chain | `cargo-deny` (advisories, licenses, sources, bans), `cargo-audit`, pinned toolchain and tools (mise), GitHub Actions pinned to commit SHAs, minimal `permissions:` in workflows, distroless images, SBOM in release (Phase 14) |
| Memory safety | `unsafe_code = "forbid"` workspace-wide. Hand-written protocol codecs (MySQL, RESP) are fuzzed |
| I/D: the `/metrics` endpoint on each component's admin port (issue #59) | Plain HTTP, no authentication, like `/healthz`: expose the admin port only to the monitoring network, never publicly. Metrics carry counts, latencies and a few fixed labels (`kind`, `consumer`, `reason`, `outcome`, `status`); never user names, resource names, statements or tokens. Adding a label with a free-form value needs review. See `docs/guides/metrics.md` |
| I: traces exported over OTLP (`--otlp-endpoint`, ADR-0040) leak identities or data to the trace backend | Off unless an endpoint is set. Only spans made with `trace_span!` are exported; log events and other spans never are. Fields are limited to ids and outcomes (session id, kind, service, status), never user names, resource names, claims, tokens or statements. The proxy sends only a `traceparent` to the worker in the open frame; the worker ignores a malformed one, and a compromised proxy gains nothing from it beyond choosing the trace its worker span is filed under. The collector link is plain HTTP unless the endpoint is `https://` (`--otlp-ca-file` trusts a private CA; client certificates are not supported): keep plain HTTP on a trusted network. The control plane honours an incoming `traceparent` on gRPC requests only, so an unauthenticated caller can choose the trace an `api.request` span is filed under, nothing more |
| Clock skew | Certs are back-dated 1 minute. TTL checks allow ±2 minutes |

## 6. Accepted residual risks (v1)
1. A compromised proxy can replay observed user certs toward the control plane for up to the cert TTL (it can't do TLS as the user without the key).
2. A local process on the user's machine can use an open loopback listener during its lifetime.
3. A compromised worker sees the plaintext of the sessions it serves, and can act as the `limen_*` DB roles of its resources.
4. Duplicates in Datadog under failure (at-least-once).
5. Revocation is TTL-based (no immediate lock in v1. `lock` is an extension point).
6. Device-flow logins aren't bound to the CLI's key (no nonce in RFC 8628). PKCE is the default and is bound.
7. Until IAM join exists (Phase 14), autoscaled proxies and workers enroll with a static, kind-scoped token.
8. Until Phase 3, recordings sit on the worker's disk, protected only by file permissions and the hash in `session.end`.

## 7. Review log
| Date | Phase | Change |
|---|---|---|
| 2026-10-26 | Docs | Public website (TB12): a static site with no Limen data; supply chain and third-party requests |
| 2026-10-25 | 13 | Access requests and break-glass, audit search, discovery, policy tooling, reviews and evidence, live watch (TB11): new entry points `Access`, `AuditSearch`, `Reviews`, `Discovery`, `Watch` and the console pages; new data stores `access_*`, `audit_search`, `recording_text`, `discovered_resources`, `access_reviews`, `review_items`, `access_denies`, `session_watches`, `watch_chunks` |
| 2026-10-13 | 0 | Initial model |
| 2026-10-14 | 1 | Device-flow binding gap; static join tokens; relay header spoofing; worker forwarding. Identity moved to URI SANs |
| 2026-10-14 | 2 | SSH: per-session certificates, host CA for workers, `none` auth on authorized streams, pinned target host keys, grant forgery and replay, certified labels, peering identity, snapshot rollback; recording tampering is a residual until Phase 3 |
| 2026-10-15 | CI | Self-hosted runners run pull request code on the owner's machines (TB9). Private repository only |
| 2026-10-17 | 6 | SQL databases: verified TLS to targets, secret files and the bootstrap admin, statement text in audit, role and database guards, shared-role cancel and kill (residual), SigV4 and Redshift credential calls (unverified), injection into bootstrap SQL, frame limits |
| 2026-10-17 | 8 (final review) | Kubernetes: built-in user names, audit of requests that fail upstream, upstream 401 as a service error, token refresh during rotation |
| Phase 12 | Web OIDC handoff and app-session replay, fixed-host routing, identity-header spoofing, web request audit projection, and fixed-target TCP forwarding |
| 2026-10-25 | 14 | OTLP trace export: opt-in outbound flow to a collector; allow-listed spans (ADR-0040) |
| 2026-10-24 | 14 | Observability: `/metrics` on the admin port is unauthenticated and label-restricted; CA signing metrics |
| 2026-10-17 | 8 | Kubernetes: the `/k8s/` entry point and upgrade proxy, identity-header stripping at two hops, recordability of streams, the worker's impersonation token, ALPN-less HTTP/1.1 |
