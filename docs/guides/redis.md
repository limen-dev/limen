# Redis and Valkey

Connect with `redis-cli` or any Redis or Valkey client. "Redis" below covers both: same protocol, and the resource kind, command and policy are all named `redis`. You never see a password: the worker logs in as the Redis ACL user your role names (same on Valkey), checks every command against your role, and audits it. Design: [ADR-0034](../adr/0034-redis-and-valkey-access.md).

## Connect

```sh
limen ls                                   # cache-staging   ● redis   read
limen redis connect cache-staging          # user picked from policy when there's only one
# Listening for cache-staging as read.
# Run: redis-cli -h 127.0.0.1 -p 51234
redis-cli -h 127.0.0.1 -p 51234 GET app:greeting
```

- Listener behaviour (loopback, one audited session per connection, idle timeout, `--listen`, `--socket`): [Using the CLI](cli.md#local-listeners). `--user write` picks the Redis user when policy allows several.
- A refusal reaches your client as a Redis error: `-NOPERM Limen: ...` for a command, `-ERR Limen: access denied ...` if you can't use the resource at all.
- Your client's own `AUTH` is accepted and ignored; the worker's login stays.

## What a role can run

Full syntax: [policy reference](../policy.md).

```yaml
- resources: { kind: [redis], labels: { env: [staging] } }
  redis:
    users: [read]
    keys: ["app:*", "session:*"]      # only these keys (empty: any)
    deny_commands: [KEYS]             # refuse more
    allow_commands: ["CONFIG GET"]    # open one of the default-denied commands
    databases: [0]                    # SELECT these (empty: only 0)
```

- **Refused unless the role opens them:** `FLUSHALL`, `FLUSHDB`, `CONFIG`, `DEBUG`, `SHUTDOWN`, `REPLICAOF`, `MODULE`, `ACL`, `CLIENT KILL`, `MIGRATE`, `SWAPDB`, `MOVE`, `SAVE`, `BGSAVE`, `BGREWRITEAOF`, `SLOWLOG` (it holds other sessions' commands), `FAILOVER`, `CLUSTER`, and scripting (`EVAL`, `EVALSHA`, `FCALL`, `SCRIPT`, `FUNCTION`).
- **Never allowed:** `MONITOR`, `SYNC`, `PSYNC`, `REPLCONF`, `RESET`, `CLIENT REPLY`, `CLIENT PAUSE`.
- **With `keys`:** every key a command touches must match a pattern (`*`, `?`). `KEYS`, `SCAN`, `RANDOMKEY`, `FLUSHALL`, `FLUSHDB`, `SWAPDB` and scripts are refused even if `allow_commands` lists them. So are `SORT` with `BY` or `GET` (those patterns read other keys) and any command whose keys the server's `COMMAND INFO` table can't locate.
- The server's ACL for that user is the second layer: if the worker were ever wrong, the server still refuses what its ACL forbids.

## What is audited

One `redis.command` event per command, written *before* forwarding (if it can't be written, the command is refused): user, session, command, subcommand, key names, argument count, resource, Redis user. **Values are not logged**; `audit.log_values: true` opts in (a short list of keyless control commands, such as `SELECT 3` and `INFO keyspace`, always logs its arguments, and the console shows `(N args not logged)` for other commands that show no keys), and `audit.redact_keys: true` hashes key names. `AUTH`, `HELLO`, `ACL`, `MIGRATE` and `CONFIG` arguments are never logged. A refusal is `auth.denied` with `action: redis`. `session.start` and `session.end` carry `kind: redis`. Locking a user or killing a session ends the session as usual.

The console session page lists commands ([command lists](console.md)) with key names (hashed under `redact_keys`) and arguments only under `log_values`. A command is "allowed" (policy passed it on) or "refused" (with the reason). The server's reply isn't recorded, so a command the server's ACL rejects still shows as allowed.

## Operating it

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

| Worker flag / variable | Purpose |
|---|---|
| `--redis-ca-file` / `LIMEN_REDIS_CA_FILE` | PEM bundle to verify the server (ElastiCache: the [Amazon bundle](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/in-transit-encryption.html)). Required for any `tls: true` target |
| `--redis-credentials-file` / `LIMEN_REDIS_CREDENTIALS_FILE` | JSON `{"<resource>": {"<user>": "<password>"}}` for targets with `iam_auth: false`. Mount as a secret, mode 0400. Never put these in policy |

**IAM (ElastiCache)** needs Redis OSS 7.0+ or Valkey 7.2+ with in-transit encryption; a user created with `authentication-mode Type=iam` whose name equals its ID, in the replication group's user group; and an IAM policy on the worker's role allowing `elasticache:Connect` on the replication group and the user. The worker signs a 15-minute token with its AWS credentials (the SDK's usual chain) and logs in again at 11 hours, because ElastiCache drops IAM connections after 12. Limen doesn't create ElastiCache users; create them in Terraform, since their ACL is your first control.

**Self-hosted.** Create one ACL user per Redis user your roles name (`user read on >... ~* +@read +@connection +command`) and list their passwords in the credentials file. `+command` is needed (the worker reads `COMMAND INFO` once per session), as is `+@connection` (`HELLO`, `CLIENT SETNAME`). The dev stack's ACL is `deploy/compose/config/targets/redis/users.acl` (default user off; ACL files take no comments): `read` is read-only, `write` has everything except the admin and dangerous categories.

The server sees the Redis user, not the person. The worker names each connection `limen:<session id>`, so `CLIENT LIST` and the slow log join to Limen's audit.

## Limits

- Standalone and replication-group endpoints only. **Cluster mode** (`MOVED`/`ASK`) isn't supported; ElastiCache Serverless is untested.
- A request or reply over 256 MiB ends the session.
- **Audit comes first**: the event is on disk (one fsync, shared by whatever is waiting) before the command is forwarded. In the dev stack, one command at a time measured about 9 ms end to end, about 3 ms of it fsync (disk-dependent); a pipeline pays once per batch (60,000 pipelined commands took about 1.6 s). That is the price of failing closed.
- **Pub/Sub.** After a `SUBSCRIBE`-family command the connection is a stream: the worker passes frames through, answers refusals at once, and no longer matches replies to commands, so use a separate connection for commands. Channels aren't key-limited, except that a role with `keys` can't subscribe to keyspace or key-event channels (`__keyspace@*`, `__keyevent@*`, or a pattern that could match them) or use `CLIENT TRACKING` or `PUBSUB CHANNELS`, which reveal other roles' key names.
- **Databases.** A role covers only the databases it names (default `[0]`). Connections start in database 0, so a role naming only `[3]` must `SELECT 3` first and can run nothing before. `MOVE` and `COPY ... DB` need a target database the role names.
- **Large commands.** An audit event lists at most 100 keys (with `keys_total`) and, under `log_values`, 100 arguments, so a large `DEL` or `MSET` is audited, not refused.
- A refused command inside `MULTI` makes the server answer `EXECABORT` to `EXEC`, so the rest of the transaction doesn't run.
- `limen redis connect` opens and closes one empty session first, to fail early on a bad login or unreachable server. It shows as a session with no commands.
- **Unverified against real ElastiCache:** IAM token acceptance, the 12-hour re-login, TLS with the AWS bundle. The rest ran against Redis 7.4 and Valkey 8.0 (`demos/demo-phase7.sh`).
