# MongoDB, Atlas, and DocumentDB

Connect with `mongosh` or any MongoDB driver. You never see a password: the worker logs in as the role your policy names, checks every command against your role, and audits it. Design: [ADR-0035](../adr/0035-mongodb-access.md).

## Connect

```sh
limen ls                                   # catalog-staging   ● mongodb   read
limen mongo connect catalog-staging        # role and database picked from policy when there's only one
# Listening for catalog-staging as read in orders.
# Run: mongosh "mongodb://127.0.0.1:51234/orders?directConnection=true"
mongosh "mongodb://127.0.0.1:51234/orders?directConnection=true"
```

- Each connection to the listener is its own audited session. A driver opens a few (monitoring and a pool), so the console groups them into one row ("4 connections") that lists all their commands; each keeps its own session id and events. Leave the command running; Ctrl-C stops it, or it stops after an hour with no connection (`--idle-timeout 30m`, `0` for never).
- `--role write` picks the role when policy allows several. `--database orders` opens another database (otherwise the resource's `default_database`). `--listen 127.0.0.1:27018` fixes the port (loopback only). `--socket ~/.limen/run/catalog.sock` uses a unix socket (mode 0600).
- Connect **without credentials**. A connection string with a user and password is refused (`Limen has already authenticated this session`).
- A refusal reaches your client as a MongoDB error: `not authorized on billing` for a database policy doesn't grant, `Limen policy does not allow the dropDatabase command`, or `Limen: access denied ...` if you can't use the resource at all.

## What a role can do

Full syntax: [policy reference](../policy.md).

```yaml
- resources: { kind: [mongodb], labels: { env: [staging] } }
  mongo:
    roles: [read]                       # names the worker has a credential for
    databases: [orders]                 # "*" for all; deny rules apply
    deny_commands: [dropDatabase, drop, createIndexes]
```

- Every command names its database. The worker refuses one on a database the role isn't granted (`Unauthorized`, code 13) before the server sees it. So are pipelines naming another database: `$out`, `$merge`, `$lookup` and `$graphLookup` with a `{db, coll}` target, and `mapReduce` with `out.db`.
- `authenticate`, `saslStart`, `saslContinue` and `logout` are refused. `admin` is refused except the read-only metadata drivers send on connect (`ping`, `buildInfo`, `listDatabases`, `connectionStatus`, `getParameter`, `endSessions`, `whatsmyuri`).
- Cursors stay with the session that opened them: `getMore` or `killCursors` on another session's cursor fails with `CursorNotFound`.
- With several grants covering one database, the session may do whatever any one permits.
- **The server's own grants are the real boundary.** Create the MongoDB user with the least privilege that works (for example `read` on `orders`); Limen's checks are a second lock. A command Limen allows and the server refuses appears in the audit trail with the server's error code.

## What is audited

One **`mongo.command`** event per command, written *before* forwarding (if it can't be written, the command doesn't run and the session ends). Each forwarded command then gets exactly one **`mongo.command.end`**: status (`ok`, `error`, `unacknowledged` for `w: 0` writes, `not_completed` when a lock, kill, drain or TTL cut the session off), duration, documents returned or written, and the server's error code and name.

**Values are redacted by default.** The event keeps the command, database, collection and the *shape*:

```
find orders.customers   {"filter":{"email":"?","age":{"$gt":"?"}},"sort":{"createdAt":-1},"limit":10}
update orders.customers {"updates":[{"q":{"email":"?"},"u":{"$set":{"tier":"?"}},"multi":false,"upsert":true}]}
insert orders.invoices  {"documents":{"count":2}}
aggregate orders.invoices {"pipeline":[{"$match":{"status":"?"}},{"$lookup":{"from":"customers","as":"?"}},{"$out":"copy"}]}
```

Field names, operators, sort directions, `limit` and the collection names in `$out`, `$merge` and `$lookup` stay. Every other value is `?`, arrays become a count (`"?[3]"`), and inserted documents are only counted. Result data is never kept. Only the server's error *code* is kept, since its text can quote data. Field names are structure, so a collection that stores data in its keys will show it.

Set `full_commands: true` on the resource to keep values. Fields named like secrets (`pwd`, `password`, `token`, …) stay redacted even then.

A refused command is a `mongo.command` event with `phase: refused` and a `reason` (`database_not_granted`, `command_denied`, `auth_command`, `unknown_cursor`). `session.start` and `session.end` carry `kind: mongodb`. Locking a user or killing a session ends the session as usual. The console session page lists commands with shape, outcome, result and error code ([command lists](console.md)).

## Operating it

```yaml
kind: resource
version: v1
metadata: { name: catalog-prod, labels: { env: prod } }
spec:
  mongodb:
    endpoint: "mongo-0.internal:27017"      # any replica set member; the worker follows the primary
    # hosts: ["*.db.example.com"]            # where it may follow it (see below)
    default_database: shop
    auth: scram                              # scram (SHA-256) | scram_sha1 | x509 | aws
    credentials_dir: /etc/limen/mongo/catalog-prod
    tls_ca_file: /etc/limen/mongo/ca.pem
    # tls_server_name: mongo.internal        # if the certificate carries another name
    # full_commands: true                    # keep values in the audit trail
    # max_commands_per_second: 500           # pacing per session; 0 for no limit
  worker_selector: { pool: prod }
```

**Credentials.** `credentials_dir` holds one file per role: `<role>` is the password (`scram`, `scram_sha1`; ASCII only, SASLprep isn't implemented), `<role>.pem` the client certificate and key (`x509`). Role names are `[A-Za-z0-9_.-]`, so they can't climb out of the directory. Create the MongoDB users yourself, least privilege (there is no bootstrap for MongoDB yet). The worker reads the file per session and holds it only to log in.

**X.509.** The MongoDB user is the certificate subject (`$external`), such as `CN=limen-x509,O=Limen`. The role name only selects which `.pem` the worker presents.

**Atlas.** Use a replica set member's `host:27017` (`mongodb+srv://` isn't resolved yet), `flavor: atlas`, the system bundle as `tls_ca_file` (`/etc/ssl/certs/ca-certificates.crt`), and `auth: scram`, `x509` or `aws`. Allow the worker's egress IP (or use PrivateLink) in Atlas. *Unverified against a real Atlas cluster.*

**Where the worker follows.** A member names the primary and the worker goes there with the login, so it only follows a host in the same domain as `endpoint` (an address stays in its /16) unless the resource lists `hosts` (exact names, `*.suffix` patterns, IP literals). A primary outside that is refused with a message naming `mongodb.hosts`. An `endpoint` of two labels, such as `kafka.corp`, shares no domain below the top level, so the worker follows only to names under it (`b-2.kafka.corp`) unless `hosts` says more. The field is part of the resource, not of a delegated writer's reach (ADR-0042).

**DocumentDB.** `flavor: documentdb`, the AWS global bundle as `tls_ca_file`, and `auth: scram` (5.0), `scram_sha1` (4.0) or `aws` (the worker's IAM identity, `$external`, instance clusters on 5.0, not the primary user). X.509 isn't supported by DocumentDB. Use the cluster endpoint. DocumentDB implements a subset of commands, so some `mongosh` helpers fail server-side. *Unverified against a real cluster.*

**IAM (`auth: aws`).** The worker signs an STS `GetCallerIdentity` request with its IAM identity (default AWS credential chain). Map the MongoDB user to that IAM role ARN (`$external` user in Atlas, an IAM user in DocumentDB). *Unverified against the real services.*

**Pacing.** Each command is a durable audit write, so a session may send at most `max_commands_per_second` (default 500; 0 for no limit) after a burst of 100. A client in a tight loop is slowed, never refused, and adds no extra events.

**Limits**

- No transactions or retryable writes: the worker presents itself as a standalone server, so drivers don't start them.
- A failover ends the session with an error; reconnect and the worker finds the new primary. Sharded clusters (`mongos`) and `mongodb+srv://` aren't supported.
- A session ends at the role's `max_session_ttl` or after an hour of client silence. A command still running when the client leaves keeps running on the server (set `maxTimeMS`); the worker closes its own connection.
- Messages up to the server's 48 MB limit pass; the worker holds one per session at a time. `OP_COMPRESSED` isn't offered, so drivers use no compression.

**Metrics** (worker): `limen_mongo_commands_total{status}`, `limen_mongo_command_seconds`, `limen_mongo_refused_total{reason}`, `limen_mongo_connect_failures_total`, `limen_mongo_paced_total` (commands that had to wait). Rising `connect_failures` means a credential, TLS, network or primary problem; rising `not_completed` means sessions cut off mid-command.

**Observing.** The server log and `db.currentOp()` show `appName: limen:<session id>` for each connection, tying it to the console session. In the audit trail, group `mongo.command.end` by `error_code_name` to see what the server refuses, and by `status: not_completed` to see commands cut short.
