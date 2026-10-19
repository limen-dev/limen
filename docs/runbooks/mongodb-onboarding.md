# Runbook: onboarding a MongoDB deployment

How to put a self-hosted MongoDB, an Atlas cluster, or a DocumentDB cluster behind `limen mongo connect`, and what to check when it doesn't work. The model is in [ADR-0035](../adr/0035-mongodb-access.md); the user side is in [the MongoDB guide](../guides/mongodb.md).

Limen logs in to MongoDB as one **user per policy role** (`limen-read`, `limen-rw`, ...), with a credential only the worker holds. People never get one. There is no bootstrap for MongoDB users yet: you create them, with the least privilege that works. The server's own grants are the real boundary; Limen's checks (database, command name, cursors) are a second lock.

## 1. Reach the server from a worker

- Run a worker in the network that can reach every member you list, labelled to match the resource's `worker_selector` (see [worker enrollment](worker-enrollment.md)).
- Put the CA that signs the server's certificate on the worker: your own CA, the system bundle (`/etc/ssl/certs/ca-certificates.crt`) for Atlas, or the AWS global bundle (`https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem`) for DocumentDB. Limen refuses to connect without verifying it. If the certificate carries another name than the host you connect to, set `tls_server_name`.
- **Atlas**: add the worker's egress IP to the project's access list, or use PrivateLink/peering. Atlas gives hostnames per member (`...-shard-00-00.xxxx.mongodb.net:27017`); write one, because `mongodb+srv://` isn't resolved. The worker follows the primary that member names.
- **DocumentDB**: use the cluster endpoint (it always reaches the primary), from inside the VPC.

## 2. Create the users

**SCRAM (any server, Atlas, DocumentDB)**

```js
// mongosh, as an admin
db.getSiblingDB("admin").createUser({
  user: "limen-read", pwd: passwordPrompt(),
  roles: [{ role: "read", db: "orders" }],
});
```

Write the password to the worker as a file named for the role, mode `0400`, in the resource's `credentials_dir` (`/etc/limen/mongo/catalog-prod/limen-read`). Use ASCII passwords only. For servers without SCRAM-SHA-256 (DocumentDB 4.0) set `auth: scram_sha1`.

**X.509**: issue a client certificate from a CA the server trusts (`--tlsCAFile`, or the Atlas X.509 CA) with `extendedKeyUsage=clientAuth`, create the user in `$external` named for the subject in RFC 2253 order, and put the certificate followed by its key in `<credentials_dir>/<role>.pem`:

```js
db.getSiblingDB("$external").runCommand({
  createUser: "CN=limen-x509,O=Limen",
  roles: [{ role: "read", db: "orders" }],
});
```

**IAM (`auth: aws`, Atlas and DocumentDB 5.0)**: map the worker's IAM role ARN to a MongoDB user in `$external`. The worker uses the default AWS credential chain, so give its task role or instance profile that identity. *Unverified against the real services.*

## 3. Describe the deployment in policy

```yaml
kind: resource
version: v1
metadata: { name: catalog-prod, labels: { env: prod, team: catalog } }
spec:
  mongodb:
    endpoint: "mongo-0.internal:27017"
    default_database: shop
    credentials_dir: /etc/limen/mongo/catalog-prod
    tls_ca_file: /etc/limen/mongo/ca.pem
  worker_selector: { pool: prod }
---
kind: role
version: v1
metadata: { name: catalog-readers }
spec:
  allow:
    - resources: { kind: [mongodb], labels: { env: [prod] } }
      mongo: { roles: [limen-read], databases: [shop], deny_commands: [dropDatabase] }
```

Check it before applying: `limen admin apply <dir> --dry-run`. Then `limen ls` as a member of the role shows the resource.

## 4. Verify

```sh
limen mongo connect catalog-prod
mongosh "mongodb://127.0.0.1:<port>/shop?directConnection=true" --eval 'db.runCommand({connectionStatus: 1}).authInfo'
```

`authenticatedUsers` should name the MongoDB user, not a person. In the server's log or `db.currentOp()`, the connection's `appName` is `limen:<session id>`, the id shown on the session's page in the console.

## When it doesn't work

| Symptom | Likely cause |
|---|---|
| `limen mongo connect` says `couldn't connect to the MongoDB server; ask an admin to check the worker's log` | The worker's log has the reason: DNS or firewall, TLS name mismatch (`tls_server_name`), a missing CA, a wrong or missing credential file, an Atlas access list, or an election in progress (`no primary is known`) |
| `Authentication failed` in the worker's log | The password file is wrong, the user lives in another `auth_source` (Atlas and `x509`/`aws` use `$external`; SCRAM users use `admin` unless you set `auth_source`), or the mechanism isn't enabled for the user (`scram` needs SHA-256 credentials) |
| `the password for ... isn't ASCII` | SCRAM-SHA-256 needs SASLprep, which Limen doesn't implement; use an ASCII password |
| `not authorized on <db>` in `mongosh` | Policy doesn't grant that database to the role (the audit event has `reason: database_not_granted`), or the server's own role doesn't (the end event has `error_code_name: Unauthorized`) |
| Writes work in `mongosh` but a transaction or retryable write fails | The worker presents a standalone server: no transactions or retryable writes through Limen |
| Sessions end during a failover | Expected: the worker's connection was to the old primary. Reconnect; the worker finds the new one |
| `CursorNotFound` after a long pause | The cursor timed out on the server (default 10 minutes), or it belonged to another session |
| Several sessions for one `mongosh` | Normal: a driver opens monitoring and pool connections, each its own audited session (own `session_id`). The console shows one row per `limen mongo connect` run ("N connections"); in the audit trail the `session.start` events share a `group` |

## Watching it

- Group `mongo.command.end` events by `error_code_name` to see what the server refuses, and by `status: not_completed` for commands cut short (a worker restart, a lock, a dying server).
- `mongo.command` events with `phase: refused` are Limen's own refusals; the `reason` says which rule.
- A burst of `database_not_granted` or `auth_command` refusals from one user is worth a look: someone is probing, or a tool is configured with credentials of its own.
- A worker's `--max-sessions` bounds its sessions. A busy `mongosh` user costs a few.
