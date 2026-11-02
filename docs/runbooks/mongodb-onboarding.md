# Runbook: onboarding a MongoDB deployment

Put a self-hosted MongoDB, an Atlas cluster or a DocumentDB cluster behind `limen mongo connect`, and diagnose it when it doesn't work. Model: [ADR-0035](../adr/0035-mongodb-access.md). User side: [MongoDB guide](../guides/mongodb.md).

Limen logs in as one **MongoDB user per policy role** (`read`, `write`, …) with a credential only the worker holds. There is no user bootstrap yet: you create the users, least privilege. The server's grants are the real boundary; Limen's checks (database, command name, cursors) are a second lock.

## 1. Reach the server from a worker

- Run a worker in a network that reaches every member you list, labelled to match the resource's `worker_selector` ([worker enrollment](worker-enrollment.md)).
- Put the CA that signs the server certificate on the worker: your own CA, the system bundle (`/etc/ssl/certs/ca-certificates.crt`) for Atlas, or the AWS global bundle (`https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem`) for DocumentDB. Limen won't connect unverified. If the certificate names a different host, set `tls_server_name`.
- **Atlas:** allow the worker's egress IP in the project access list, or use PrivateLink/peering. Write one member hostname (`...-shard-00-00.xxxx.mongodb.net:27017`); `mongodb+srv://` isn't resolved. The worker follows the primary that member names.
- **DocumentDB:** use the cluster endpoint (always the primary), from inside the VPC.

## 2. Create the users

**SCRAM** (any server, Atlas, DocumentDB):

```js
// mongosh, as an admin
db.getSiblingDB("admin").createUser({
  user: "read", pwd: passwordPrompt(),
  roles: [{ role: "read", db: "orders" }],
});
```

Give the worker the password as a file named for the role, mode `0400`, in the resource's `credentials_dir` (`/etc/limen/mongo/catalog-prod/read`). ASCII only. For servers without SCRAM-SHA-256 (DocumentDB 4.0) set `auth: scram_sha1`.

**X.509:** issue a client certificate (`extendedKeyUsage=clientAuth`) from a CA the server trusts (`--tlsCAFile`, or the Atlas X.509 CA), create a `$external` user named for the subject in RFC 2253 order, and put the certificate then its key in `<credentials_dir>/<role>.pem`:

```js
db.getSiblingDB("$external").runCommand({
  createUser: "CN=limen-x509,O=Limen",
  roles: [{ role: "read", db: "orders" }],
});
```

**IAM** (`auth: aws`; Atlas and DocumentDB 5.0): map the worker's IAM role ARN to a `$external` MongoDB user. The worker uses the default AWS credential chain, so give its task role or instance profile that identity. *Unverified against the real services.*

## 3. Describe it in policy

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
      mongo: { roles: [read], databases: [shop], deny_commands: [dropDatabase] }
```

Check with `limen admin apply <dir> --dry-run`; then `limen ls` as a member of the role shows the resource.

## 4. Verify

```sh
limen mongo connect catalog-prod
mongosh "mongodb://127.0.0.1:<port>/shop?directConnection=true" --eval 'db.runCommand({connectionStatus: 1}).authInfo'
```

`authenticatedUsers` should name the MongoDB user, not a person. In the server log or `db.currentOp()`, the connection's `appName` is `limen:<session id>`, the id on the console session page.

## When it doesn't work

| Symptom | Likely cause |
|---|---|
| `couldn't connect to the MongoDB server; ask an admin to check the worker's log` | The worker log has the reason: DNS or firewall, TLS name mismatch (`tls_server_name`), missing CA, wrong or missing credential file, Atlas access list, or an election (`no primary is known`) |
| `Authentication failed` in the worker log | Wrong password file; the user lives in another `auth_source` (`x509`/`aws` use `$external`; SCRAM defaults to `admin`); or the mechanism isn't enabled for the user (`scram` needs SHA-256 credentials) |
| `the password for ... isn't ASCII` | SCRAM-SHA-256 needs SASLprep, which Limen doesn't implement. Use ASCII |
| `not authorized on <db>` | Policy doesn't grant the database (audit `reason: database_not_granted`), or the server role doesn't (end event `error_code_name: Unauthorized`) |
| A transaction or retryable write fails | The worker presents a standalone server: neither is supported |
| Sessions end during a failover | Expected; reconnect and the worker finds the new primary |
| `CursorNotFound` after a pause | The cursor timed out (server default 10 minutes) or belonged to another session |
| Several sessions per `mongosh` | Normal: monitoring and pool connections, each its own session. The console shows one row per run; their `session.start` events share a `group` |

## Watching it

- Group `mongo.command.end` by `error_code_name` for what the server refuses, and by `status: not_completed` for commands cut short (worker restart, lock, dying server).
- `mongo.command` with `phase: refused` is Limen's own refusal; `reason` names the rule.
- A burst of `database_not_granted` or `auth_command` from one user means probing, or a tool configured with its own credentials.
- A worker's `--max-sessions` bounds its sessions; a busy `mongosh` user costs a few.
