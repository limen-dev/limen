# ADR-0035: MongoDB, Atlas, and DocumentDB access

- Status: Accepted (2026-10-19). Built and merged in PR #34; the owner asked for Phase 9 on 2026-10-18 and accepted the decisions below.
- Date: 2026-10-18

## Context
Phase 9 delivers `limen mongo connect`: a developer runs `mongosh` (or any MongoDB driver) against a loopback port and reaches a database they are allowed to use, with no password and every command audited. ADR-0018 fixed the shape for the family (the worker terminates the protocol next to the target and holds the credential; the proxy authorizes and routes; the CLI exposes a local listener) and sketched MongoDB as "medium" difficulty: the worker must not let a client switch databases or users, Atlas is reached over the internet, and DocumentDB implements a subset. ADR-0033 (SQL) and ADR-0034 (Redis) set the pattern this ADR follows: a message-aware relay in the worker, audit written before a command is forwarded, no replayable recording but an audited command timeline in the console.

On `main` the policy side already existed as data-only stubs (`mongodb` kind, `mongo` grant, `flavor`); `limen mongo connect` answered "planned for Phase 9". No MongoDB wire code existed.

## Decision

### 1. Data path
- The CLI opens `127.0.0.1:<port>` (or a 0600 unix socket) and turns each accepted connection into one Limen session of kind `mongodb` over a new proxy ALPN, `limen-mongo/1`. The proxy authorizes (resource, role, default database) and routes to a worker exactly as for SSH and SQL; it never parses MongoDB.
- The worker plays the **server** toward the driver and the **client** toward MongoDB. It answers the handshake itself, logs in to the server itself, and relays `OP_MSG` commands one at a time. It reads each command in full (to audit it first, check its database, and apply the few guards below) and reads each reply only as far as the outcome and any cursor it opened. Result documents are never inspected or kept.
- Wire support: `OP_MSG` (all commands), and `OP_QUERY`/`OP_REPLY` for the first handshake only (drivers still send it in the old format). `OP_COMPRESSED` is never offered, so it never arrives. The worker clears `exhaustAllowed` and drops the optional checksum when forwarding, so the server never streams replies the relay isn't waiting for. `moreToCome` (unacknowledged writes, `w: 0`) is honored: no reply is awaited.
- **The worker presents itself as a standalone, writable server**, whatever the real one is. Drivers then talk to it as a single node: no host lists to rewrite, no discovery, and `directConnection=true` is printed for good measure. The cost is that what needs a replica set does not work through Limen in Phase 9: multi-document transactions and retryable writes (see Decisions).
- Toward the server: TLS is mandatory with `verify-full` against the resource's `tls_ca_file` (the system bundle for Atlas, the AWS global bundle for DocumentDB). `insecure_dev` plus `--allow-insecure-db-targets` is the local-only escape, refused for Atlas and DocumentDB.
- **Replica sets**: the resource names one member. If it reports it isn't the primary and names one, the worker connects to that primary once (one hop). `mongodb+srv://` (DNS SRV and TXT) is not resolved: write the host, or any member of the set. A failover ends in an error to the client, who reconnects.

### 2. Authentication to the server
The role in policy names the identity; the credential lives on the worker (`credentials_dir`) and never reaches a person.

| `auth` | Mechanism | Credential on the worker | Where it fits |
|---|---|---|---|
| `scram` (default) | SCRAM-SHA-256 | `<dir>/<role>`: the password | any server, Atlas, DocumentDB 5.0 |
| `scram_sha1` | SCRAM-SHA-1 | `<dir>/<role>`: the password | servers without SHA-256, DocumentDB 4.0 |
| `x509` | MONGODB-X509 | `<dir>/<role>.pem`: client certificate and key | any server with X.509 enabled, Atlas |
| `aws` | MONGODB-AWS | the worker's IAM identity (default credential chain) | Atlas, DocumentDB 5.0 instance clusters |

SCRAM is checked against the RFC 5802 and RFC 7677 vectors. `MONGODB-AWS` signs the STS `GetCallerIdentity` request the server forwards, with the existing SigV4 code, and refuses any STS host that isn't `sts.*.amazonaws.com`. The worker sets `appName` to `limen:<session>` in its handshake, so the server's log and `currentOp` carry the Limen session.

### 3. What the worker enforces
Every command names its database in `$db`, so unlike SQL the wire says where a command goes. The worker checks it against policy (`Policy::evaluate` for `MongoRole { role, database }`, so grants, wildcards, and deny rules all apply) and refuses with a server-shaped error (`Unauthorized`, code 13) that `mongosh` shows as is. Beyond that:
- `authenticate`, `saslStart`, `saslContinue`, and `logout` are refused: the worker logged in already, and a client must not swap the identity (a connection string with credentials fails with a clear message).
- `$external` and malformed database names are refused. `admin` is refused unless granted, except read-only metadata that every driver and `mongosh` send (`ping`, `buildInfo`, `endSessions`, `listDatabases`, `connectionStatus`, `getParameter`, `whatsmyuri`); the server's own grants still apply to those.
- `deny_commands` on a grant refuses named commands (case-insensitive). With several covering grants, a session may do what any one permits, as for Redis.
- **Cursor ownership.** Cursors belong to the server login, which sessions share, so the worker records the cursor ids each session was given and refuses `getMore` and `killCursors` for any other id (`CursorNotFound`). Up to 10,000 open cursors are tracked per session.
- **Cross-database references.** `aggregate`, `explain`, and `mapReduce` are walked for `{db, coll}` targets under `$out`, `$merge`, `$lookup`, `$graphLookup`, and `out`, at any depth (`$facet` nests pipelines), and each database must pass the same policy check. A filter that merely looks the same is refused too (the safe side).
- What a role may do *inside* a database stays the server's job: the server's grants for the role are the boundary and this module a second lock.

### 4. Audit and "recording"
- One `mongo.command` event per command, **written before it is forwarded**; if it can't be written the command is not run and the session ends (fail closed, like `ssh.exec`). A second event, `mongo.command.end`, keyed to the first, carries status (`ok`, `error`, `unacknowledged`, `not_completed`), duration, documents returned or written, and the server's error code and name. Refused commands are `mongo.command` with `phase: refused` and a `reason`. The `hello` heartbeat is answered locally and not audited. **Every forwarded command has exactly one end event**, whatever ends the session: a guard owned by the command records `not_completed` if the session is cancelled from outside (a lock, a kill, a drain, the TTL) or a task panics, and tests check the pairing on a real server. *Residual:* a cancellation in the instant between the `mongo.command` write and the guard's creation leaves a start event with no end; the shipped trail still has the start. The server may keep running a cancelled command (clients should set `maxTimeMS`).
- **Redacted by default.** The event keeps the command name, database, collection, and the *shape* of the command: every value in a filter, update, or pipeline becomes `?`, while field names, operators (`$gt`, `$match`), sort directions, `limit`, and the collection names in `$out`, `$merge`, and `$lookup` stay. Inserted documents are only counted. Arrays of values collapse to a count (`"?[3]"`). `full_commands: true` on the resource keeps values, except fields named like secrets (`pwd`, `password`, `token`, ...). Server error text can quote data (`dup key: { email: ... }`), so it is kept only with `full_commands`; the code and code name always are. Field names are structure and are kept: a collection that stores data in keys will show it.
- **Session recording is the same as for databases and Redis**: no replayable terminal recording; the audited command timeline is the record. It lands in S3 and Datadog with the hash chain like every event, and the console projects it into the session page (`db_statements`), including refused commands and each command's outcome. Result data is never stored. Statement text can still be sensitive (collection and field names), so it follows the same retention and access rules as other audit.

### 5. Policy and CLI
- `MongoTarget` gains `auth`, `default_database`, `auth_source`, `credentials_dir`, `tls_ca_file`, `tls_server_name`, `insecure_dev`, and `full_commands`, and `max_commands_per_second`; `MongoGrant` gains `deny_commands`. The field names were provisional in ADR-0018; the existing ones are unchanged. Validation rejects names that could reach outside `credentials_dir`, X.509 on DocumentDB, `aws` on a plain server, and `insecure_dev` on Atlas or DocumentDB.
- `limen mongo connect <resource> [--role R] [--database D] [--listen ADDR | --socket PATH] [--idle-timeout 1h]`. A refusal reaches the driver as a MongoDB error, so `mongosh` prints why instead of "connection closed".
- A driver opens a few connections (monitoring and a pool), so one `mongosh` shows as a few short sessions in the console.

### 6. Tests and demo
- Unit tests: BSON (every type, lying lengths, nesting), wire framing, redaction, the rules, SCRAM vectors, the `MONGODB-AWS` signature fixture, reply parsing.
- Integration tests against a real MongoDB 8 with TLS, SCRAM-SHA-256, SCRAM-SHA-1, and X.509 (`crates/limen-worker/tests/mongo.rs`): audit before forwarding and failing closed, redaction (including a duplicate-key error that quotes a value), database and command refusal, the server's own grants, cursor ownership, unacknowledged writes, the legacy handshake, a wrong password. A full-stack test (`limen-e2e/tests/phase9.rs`) runs CLI-side listener, proxy, worker, and the server together, including a lock ending the session.
- `demos/demo-phase9.sh`: `mongosh` through `limen mongo connect` against a compose MongoDB, SCRAM and X.509, command audit with redacted filters, the console list of commands, a refused database, a refused login, a denied `dropDatabase`, and a lock.
- CI starts the MongoDB target next to PostgreSQL and MySQL (`scripts/ci-db-targets.sh`); Linux jobs fail on any SKIPPED.

### 7. Dependencies
None. BSON and the wire format are small enough to write by hand (a few hundred lines, bounded, fuzz-friendly): the `bson` and `mongodb` crates (MongoDB, active) were assessed and not adopted, for the same reason as the SQL and RESP codecs (ADR-0012): a relay needs to walk and bound documents, not build typed values, and the full driver brings a large tree. SCRAM-SHA-1 uses `aws-lc-rs` (legacy SHA-1 and HMAC-SHA1) and the `md-5` crate already adopted in Phase 6.

## Not verified against the real services
Atlas (SCRAM, X.509, `MONGODB-AWS`, TLS with the public CA), DocumentDB (`MONGODB-AWS`, SCRAM-SHA-1, its command subset, the AWS bundle), the replica-set primary hop on a multi-node set, and sharded clusters (`mongos`). Everything else runs against a real MongoDB 8 in compose.

## Decisions on the questions
Accepted by the owner on 2026-10-19, as built:
1. **Standalone presentation** (section 1): no transactions or retryable writes through Limen in Phase 9. Presenting the real replica set is a later change if it is needed.
2. **Redaction default** (section 4): command shapes with every value as `?` by default, `full_commands` per resource to keep values. This differs from SQL because filters carry user data far more often than SQL text does.
3. **Fail closed for every command** (section 4): one spool write before each command, no batching of reads.
4. **Admin metadata allowance** (section 3): the list as built (`ping`, `buildInfo`, `endSessions`, `listDatabases`, `connectionStatus`, `getParameter`, `whatsmyuri`).
5. **SRV** (section 1): `mongodb+srv://` resolution (a DNS SRV client dependency) follows once Atlas can be tested.

## Consequences
- \+ Users keep `mongosh` and their drivers; one relay covers self-hosted, Atlas, and DocumentDB.
- \+ Most of the phase is tested against a real server; only the managed-service paths are unverified, and they're labelled.
- \+ No new dependency and no new long-lived credential: the worker's secrets are a file per role, a certificate, or the IAM chain.
- − Our own BSON and wire code is a fuzzing target (a `cargo-fuzz` harness is deferred, as for the SQL codecs).
- − Presenting as standalone means no transactions or retryable writes, and a failover ends the session.
- − Command shapes in audit still show field and collection names.
- − The statement-level policy is by command name only; there is no per-collection or per-operation allow list.
- Amends ADR-0018: the MongoDB row's field names are now confirmed, and SRV resolution is deferred.

## Amendment: concise role selectors (2026-10-23)

`mongo.roles` selects a target MongoDB user whose credential the worker has; it does not require a Limen prefix. The guides and examples use `read` and `write` for these users.
