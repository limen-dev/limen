# MongoDB, Atlas, and DocumentDB

Connect with `mongosh` (or any MongoDB driver) through Limen. You never see a password: the worker logs in to the server as the role your policy names, checks every command against your role, and audits it. Design: [ADR-0035](../adr/0035-mongodb-access.md).

## Connect

```sh
limen ls                                   # catalog-staging   ● mongodb   limen-read
limen mongo connect catalog-staging        # the role and database are picked from policy when there's only one
# Listening for catalog-staging as limen-read in orders.
# Run: mongosh "mongodb://127.0.0.1:51234/orders?directConnection=true"
mongosh "mongodb://127.0.0.1:51234/orders?directConnection=true"
```

- Each connection to the listener is its own audited session. A driver opens a few (monitoring and a pool), so one `mongosh` shows up as a few short sessions. Leave `limen mongo connect` running while you work; press Ctrl-C, or wait for it to stop after an hour with no connection (`--idle-timeout 30m`, `0` for never).
- `--role limen-rw` picks the role when policy allows several. `--database orders` opens another database (the resource's `default_database` otherwise). `--listen 127.0.0.1:27018` fixes the port (loopback only). `--socket ~/.limen/run/catalog.sock` uses a unix socket (mode 0600, in a directory only you can enter) instead of TCP.
- Anyone who can reach the listener acts as you. That is why it binds loopback only and the socket is private. Don't forward the port.
- **Connect without credentials.** A connection string with a user and password is refused (`Limen has already authenticated this session`); the worker's login stays.
- A refusal reaches your client as a MongoDB error: `not authorized on billing` for a database policy doesn't grant, `Limen policy does not allow the dropDatabase command`, or `Limen: access denied ...` if you can't use the resource at all.

## What a role can do

A role grants MongoDB roles and the databases they may use (`docs/policy.md` has the full syntax):

```yaml
- resources: { kind: [mongodb], labels: { env: [staging] } }
  mongo:
    roles: [limen-read]              # names the worker has a credential for
    databases: [orders]              # "*" for all; deny rules apply
    deny_commands: [dropDatabase, drop, createIndexes]
```

- Every command names its database. The worker refuses one on a database the role isn't granted, as `Unauthorized` (code 13), before the server sees it. So are pipelines that name another database: `$out`, `$merge`, `$lookup`, `$graphLookup` with a `{db, coll}` target, and `mapReduce` with `out.db`.
- `authenticate`, `saslStart`, `saslContinue`, and `logout` are refused. `admin` is refused too, except the read-only metadata that `mongosh` and drivers send when they connect (`ping`, `buildInfo`, `listDatabases`, `connectionStatus`, `getParameter`, `endSessions`, `whatsmyuri`).
- Cursors stay with the session that opened them: a `getMore` or `killCursors` for another session's cursor id fails with `CursorNotFound`.
- **The server's own grants are the real boundary.** Create the MongoDB user with the least privilege that works (for example the `read` role on `orders`); Limen's checks are a second lock. A command Limen lets through that the server refuses shows up in the audit trail with the server's error code.
- With several grants covering the same database, the session may do whatever any one of them permits.

## What is audited

One `mongo.command` event per command, **before** it is forwarded (if it can't be written, the command is not run and the session ends). A second event, `mongo.command.end`, says how it ended: status (`ok`, `error`, `unacknowledged` for `w: 0` writes, `not_completed`), duration, documents returned or written, and the server's error code and name.

**Values are redacted by default.** The event keeps the command, database, collection, and the *shape* of the command:

```
find orders.customers   {"filter":{"email":"?","age":{"$gt":"?"}},"sort":{"createdAt":-1},"limit":10}
update orders.customers {"updates":[{"q":{"email":"?"},"u":{"$set":{"tier":"?"}},"multi":false,"upsert":true}]}
insert orders.invoices  {"documents":{"count":2}}
aggregate orders.invoices {"pipeline":[{"$match":{"status":"?"}},{"$lookup":{"from":"customers","as":"?"}},{"$out":"copy"}]}
```

Field names, operators, sort directions, `limit`, and the collection names in `$out`, `$merge`, and `$lookup` stay; every other value is `?`, arrays of values become a count (`"?[3]"`), and inserted documents are only counted. Result data is never kept. Server error text can quote data (`dup key: { email: ... }`), so only the error code is kept. Field names are structure and are kept, so a collection that stores data in its keys will show it.

To keep values, set `full_commands: true` on the resource. Fields named like secrets (`pwd`, `password`, `token`, ...) stay redacted even then.

A refused command is a `mongo.command` event with `phase: refused` and a `reason` (`database_not_granted`, `command_denied`, `auth_command`, `unknown_cursor`). `session.start` and `session.end` carry `kind: mongodb`. Locking a user or killing a session ends the MongoDB session like any other.

**In the console**, a session's page lists its commands (time, command, shape, outcome), up to 500, including refused ones and each command's result and error code. MongoDB sessions have no terminal recording; this list is the record, the same as for SQL and Redis sessions. The console keeps this text in the control plane's database for 30 days (table `db_statements`), visible only to admins and to the session's own user. The complete trail stays in S3 and Datadog with the hash chain.

## Operating it

**Resource**

```yaml
kind: resource
version: v1
metadata: { name: catalog-prod, labels: { env: prod } }
spec:
  mongodb:
    endpoint: "mongo-0.internal:27017"      # any replica set member; the worker follows the primary
    default_database: shop
    auth: scram                              # scram (SHA-256) | scram_sha1 | x509 | aws
    credentials_dir: /etc/limen/mongo/catalog-prod
    tls_ca_file: /etc/limen/mongo/ca.pem
    # tls_server_name: mongo.internal        # if the certificate carries another name
    # full_commands: true                    # keep values in the audit trail
  worker_selector: { pool: prod }
```

**Credentials on the worker.** `credentials_dir` holds one file per role: `<role>` is the password (`scram`, `scram_sha1`; ASCII only, because SASLprep isn't implemented), `<role>.pem` is the client certificate and key (`x509`). Role names are `[A-Za-z0-9_.-]`, so they can't climb out of the directory. Create the MongoDB users yourself with the least privilege that works (there is no bootstrap for MongoDB yet). The worker reads the file for each session and holds it only to log in.

**X.509.** The MongoDB user is the certificate's subject (`$external`), for example `CN=limen-x509,O=Limen`. The role name only selects which `.pem` the worker presents.

**Atlas.** Use a replica set member's `host:27017` (the SRV form `mongodb+srv://` isn't resolved yet), `flavor: atlas`, TLS with the system bundle (`tls_ca_file: /etc/ssl/certs/ca-certificates.crt`), and `auth: scram`, `x509`, or `aws`. Allow the worker's egress IP (or use PrivateLink) in Atlas. *Unverified against a real Atlas cluster.*

**DocumentDB.** `flavor: documentdb` with the AWS global bundle as `tls_ca_file`, and `auth: scram` (5.0), `scram_sha1` (4.0), or `aws` (the worker's IAM identity, `$external`, instance clusters on 5.0, not the primary user). X.509 isn't supported by DocumentDB. Use the cluster endpoint. DocumentDB implements a subset of the commands, so some `mongosh` helpers fail on the server's side. *Unverified against a real cluster.*

**IAM (`auth: aws`).** The worker signs an STS `GetCallerIdentity` request with its IAM identity (the default AWS credential chain: task role, instance profile, environment). The MongoDB user must be mapped to that IAM role ARN (`$external` user in Atlas, an IAM user in DocumentDB). *Unverified against the real services.*

**Limits and behavior to know**
- **No transactions or retryable writes.** The worker presents itself as a standalone server, so drivers don't start transactions or retry writes through Limen.
- A failover ends the session with an error; reconnect and the worker finds the new primary. Sharded clusters (`mongos`) and `mongodb+srv://` are not supported yet.
- A session ends at the role's `max_session_ttl`, or after an hour with no client activity. A command that is running when the client leaves keeps running on the server until it finishes (set `maxTimeMS`); the worker closes its own connection.
- Messages up to the server's 48 MB limit pass; the worker holds one message in memory at a time per session.
- The client's `OP_COMPRESSED` compression is not offered, so drivers use none.

**Observing it.** The server's log and `db.currentOp()` show `appName: limen:<session id>` for each Limen connection, which ties them to the session in the console. In the audit trail, group `mongo.command.end` by `error_code_name` to see what the server refuses, and by `status: not_completed` to see commands cut short.
