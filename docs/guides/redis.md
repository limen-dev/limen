# Redis and Valkey

Connect with `redis-cli` (or any Redis or Valkey client) through Limen. "Redis" below means both: they speak the same protocol, and the resource kind, command, and policy are all named `redis`. You never see a password: the worker logs in to the server as the Redis user (the ACL user, the same on Valkey) your role names, checks every command against your role, and audits it. Design: [ADR-0034](../adr/0034-redis-and-valkey-access.md).

## Connect

```sh
limen ls                                   # cache-staging   ● redis   limen-ro
limen redis connect cache-staging          # the user is picked from policy when there's only one
# Listening for cache-staging as limen-ro.
# Run: redis-cli -h 127.0.0.1 -p 51234
redis-cli -h 127.0.0.1 -p 51234 GET app:greeting
```

- Each connection to the listener is its own audited session. Leave `limen redis connect` running while you work; press Ctrl-C, or wait for it to stop after an hour with no connection (`--idle-timeout 30m`, `0` for never).
- `--user limen-rw` picks the Redis user when policy allows several. `--listen 127.0.0.1:6380` fixes the port (loopback only). `--socket ~/.limen/run/cache.sock` uses a unix socket (mode 0600, in a directory only you can enter) instead of TCP.
- Anyone who can reach the listener acts as you. That is why it binds loopback only and the socket is private. Don't forward the port.
- A refusal reaches your client as a Redis error: `-NOPERM Limen: ...` for a command, or `-ERR Limen: access denied ...` if you can't use the resource at all.
- Your client's own `AUTH` is accepted and ignored. The worker's login stays.

## What a role can run

A role grants Redis users with optional limits (`docs/policy.md` has the full syntax):

```yaml
- resources: { kind: [redis], labels: { env: [staging] } }
  redis:
    users: [limen-ro]
    keys: ["app:*", "session:*"]      # only these keys (empty: any)
    deny_commands: [KEYS]             # refuse more
    allow_commands: ["CONFIG GET"]    # open one of the default-denied commands
    databases: [0]                    # SELECT these (empty: only 0)
```

- **Refused unless the role opens them:** `FLUSHALL`, `FLUSHDB`, `CONFIG`, `DEBUG`, `SHUTDOWN`, `REPLICAOF`, `MODULE`, `ACL`, `CLIENT KILL`, `MIGRATE`, `SWAPDB`, `MOVE`, `SAVE`, `BGSAVE`, `BGREWRITEAOF`, `SLOWLOG` (it holds other sessions' commands), `FAILOVER`, `CLUSTER`, and scripting (`EVAL`, `EVALSHA`, `FCALL`, `SCRIPT`, `FUNCTION`).
- **Never allowed:** `MONITOR`, `SYNC`, `PSYNC`, `REPLCONF`, `RESET`, `CLIENT REPLY`, `CLIENT PAUSE`.
- **With `keys`:** every key a command touches must match a pattern (`*` and `?`). `KEYS`, `SCAN`, `RANDOMKEY`, `FLUSHALL`, `FLUSHDB`, `SWAPDB` and scripts are refused (even if `allow_commands` lists them), `SORT` with `BY` or `GET` is refused (those patterns read other keys), and so is any command whose keys the server's own `COMMAND INFO` table can't locate.
- The server's ACL for that user is the second layer. If the worker were ever wrong, the server still refuses what its ACL forbids.

## What is audited

One `redis.command` event per command, **before** it is forwarded (if it can't be written, the command is refused): the user, session, command, subcommand, key names, argument count, resource, and Redis user. **Values are not logged.** A target can opt in with `audit.log_values: true`, and can hash key names with `audit.redact_keys: true`. `AUTH`, `HELLO`, `ACL`, `MIGRATE`, and `CONFIG` arguments are never logged. A refused command is an `auth.denied` event with `action: redis`. `session.start` and `session.end` carry `kind: redis`. Locking a user or killing a session ends the Redis session like any other.

**In the console**, a Redis session's page lists its commands (time, command, outcome), up to 500, newest last, including the ones policy refused. Redis sessions have no terminal recording; this list is the record. It shows the command and the key names (hashed if the resource sets `audit.redact_keys`), and the arguments only if the resource sets `audit.log_values`; values are never kept otherwise. The console keeps this text in the control plane's database for 30 days (table `db_statements`, shared with SQL sessions), visible only to admins and to the session's own user. The complete trail stays in S3 and Datadog. A command's outcome is "allowed" (policy let it through; it was audited and forwarded) or "refused" (with the reason); the server's reply is not recorded, so a command the server's own ACL rejects still shows as allowed.

## Operating it

**Resource**

```yaml
kind: resource
version: v1
metadata: { name: cache-prod, labels: { env: prod } }
spec:
  redis:
    endpoint: "master.cache-prod.abc123.euw1.cache.amazonaws.com:6379"
    region: eu-west-1
    cache_name: cache-prod          # the replication group ID (names the IAM token's host)
    iam_auth: true                  # default
    tls: true                       # default
    audit: { redact_keys: true }
  worker_selector: { pool: prod-vpc }
```

**Worker**

| Flag / variable | Purpose |
|---|---|
| `--redis-ca-file` / `LIMEN_REDIS_CA_FILE` | PEM bundle to verify the server (ElastiCache: the [Amazon RDS/ElastiCache bundle](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/in-transit-encryption.html)). Required for any `tls: true` target |
| `--redis-credentials-file` / `LIMEN_REDIS_CREDENTIALS_FILE` | JSON `{"<resource>": {"<user>": "<password>"}}` for targets with `iam_auth: false`. Mount it as a secret, mode 0400. Never put these in policy |

**IAM (ElastiCache)** needs Redis OSS 7.0+ or Valkey 7.2+ with in-transit encryption, a user created with `authentication-mode Type=iam` whose name equals its ID and which belongs to the replication group's user group, and an IAM policy on the worker's role allowing `elasticache:Connect` on the replication group and the user. The worker signs a 15-minute token with its AWS credentials (the SDK's usual chain) and logs in again at 11 hours, because ElastiCache drops IAM connections after 12. Limen does not create ElastiCache users: create them in Terraform. The ACL on those users is your first control.

**Self-hosted** Redis or Valkey: create one ACL user per Redis user your roles name (`user limen-ro on >... ~* +@read +@connection +command`), and list their passwords in the credentials file. `+command` is needed (the worker reads `COMMAND INFO` once per session) and so is `+@connection` (`HELLO`, `CLIENT SETNAME`). The dev stack's ACL is in `deploy/compose/targets/redis/users.acl` (the default user is off; ACL files take no comments). `limen-ro` is read-only, and `limen-rw` has everything except the admin and dangerous categories.

The server sees `limen-ro`, not the person. The worker names each connection `limen:<session id>` (`CLIENT LIST` and the slow log show it), so server-side logs join to Limen's audit.

## Limits

- Standalone and replication-group endpoints only. **Cluster mode** (`MOVED`/`ASK`) is not supported yet; ElastiCache Serverless is untested.
- A request or reply over 256 MiB ends the session.
- **Audit comes first, so each command waits for it.** The event is on disk (one fsync, shared by whatever is waiting) before the command is forwarded. In the dev stack a client that sends one command at a time measured about 9 ms per command end to end, of which the fsync is about 3 ms (this depends on the disk); a pipeline pays it once per batch (60,000 pipelined commands took about 1.6 seconds). This is the price of failing closed.
- **Pub/Sub.** After a `SUBSCRIBE`-family command the connection is a stream: the worker passes the server's frames through, answers refusals at once, and no longer matches replies to commands, so use a separate connection for commands. Channels are not key-limited, except that a role with `keys` can't subscribe to keyspace or key-event channels (`__keyspace@*`, `__keyevent@*`, or a pattern that could match them), and can't use `CLIENT TRACKING` or `PUBSUB CHANNELS`, because those show other roles' key names.
- **Databases.** A role covers only the databases it names (`databases`, default `[0]`); a connection starts in database 0, so a role that names only `[3]` must `SELECT 3` first and can't run anything before that. `MOVE` and `COPY ... DB` need the target database to be one the role names.
- **Large commands.** Each audit event lists at most 100 keys (with `keys_total`) and, with `log_values`, 100 arguments, so a large `DEL` or `MSET` is audited rather than refused.
- A refused command inside `MULTI` makes the server answer `EXECABORT` to the `EXEC`, so the rest of the transaction does not run.
- `limen redis connect` opens and closes one empty session first, to fail early on a bad login or an unreachable server. It shows up as a session with no commands.
- **Unverified against real ElastiCache:** IAM token acceptance, the 12-hour re-login, TLS with the AWS bundle. Everything else was run against Redis 7.4 and Valkey 8.0 in `deploy/compose/demo-phase7.sh`.
