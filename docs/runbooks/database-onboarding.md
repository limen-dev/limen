# Runbook: onboarding a database

How to put a PostgreSQL, MySQL, Aurora, or Redshift database behind `limen db connect`, keep its `limen_*` roles in line with policy, and fix drift. The model is in [ADR-0015](../adr/0015-database-credentials.md) and [ADR-0033](../adr/0033-sql-database-access.md); the user side is in [the databases guide](../guides/databases.md).

Limen logs in to the database as one **`limen_*` role per policy role** (`limen_read`, `limen_write`, ...). People never get a credential. A dedicated **admin login** (`limen_admin`) creates those roles. Never give Limen the master user.

## 1. Reach the database from a worker

- Run a worker in the network that can reach the database, labelled to match the resource's `worker_selector` (see [worker enrollment](worker-enrollment.md)).
- Put the CA that signs the database's certificate on the worker (the RDS bundle for AWS, `https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem`). Limen refuses to connect without verifying it.

## 2. Create the admin login

**PostgreSQL / Aurora PostgreSQL**

```sql
CREATE ROLE limen_admin LOGIN CREATEROLE PASSWORD '<generated>';
-- It must be able to grant on your objects: make it the owner, or give it
-- the grants it will pass on. For a database it will manage:
ALTER DATABASE orders OWNER TO limen_admin;           -- simplest, or
GRANT ALL ON ALL TABLES IN SCHEMA public TO limen_admin WITH GRANT OPTION;
-- RDS, for IAM mode only:
GRANT rds_iam TO limen_admin WITH ADMIN OPTION;       -- run as the master user
```

**MySQL / Aurora MySQL**

```sql
CREATE USER 'limen_admin'@'%' IDENTIFIED BY '<generated>' REQUIRE SSL;
GRANT CREATE USER ON *.* TO 'limen_admin'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON orders.* TO 'limen_admin'@'%' WITH GRANT OPTION;
-- IAM mode reads other users' grants with SHOW GRANTS FOR, which needs:
GRANT SELECT ON mysql.* TO 'limen_admin'@'%';
```

**Redshift**: a user with `CREATEUSER`, and the privileges it will grant `WITH GRANT OPTION`.

The admin password goes to the worker as a file (Kubernetes secret, ECS secret, or a mounted volume), mode `0400`.

## 3. Describe the database in policy

```yaml
kind: resource
version: v1
metadata: { name: orders-prod, labels: { env: prod, team: payments } }
spec:
  postgres:
    endpoint: "orders.cluster-xyz.eu-west-1.rds.amazonaws.com:5432"
    region: eu-west-1
    iam_auth: true                       # or false with password_dir
    default_database: orders
    tls_ca_file: /etc/limen/rds-global-bundle.pem
    admin_user: limen_admin
    admin_password_file: /run/limen/admin-password
    bootstrap:
      - role: limen_read
        grants: [{ database: orders, access: read }]
      - role: limen_write
        grants: [{ database: orders, access: write }]
  worker_selector: { pool: prod-vpc }
```

Then a role that lets people use them (`db: { roles: [limen_read], databases: [orders] }`). Apply with `limen admin apply`. Role names must start with `limen_`.

`access: read` is `SELECT`; `write` is `SELECT, INSERT, UPDATE, DELETE` (and sequence use) on every table in the listed `schemas` (default `public`; for MySQL the database). Tables created later get the same grants (PostgreSQL default privileges; MySQL schema-level grants).

## 4. Bootstrap the roles <a id="bootstrap"></a>

```sh
# Show what would change; exit status 0 = nothing, 2 = differences, 1 = a failure.
limen-worker --db-bootstrap-once --db-bootstrap-check <the worker's usual flags>
# Make the changes:
limen-worker --db-bootstrap-once <the worker's usual flags>
```

The one-shot mode enrolls, fetches policy, reconciles every database resource its labels may serve, ships its audit events to the control plane (it exits with status 1 if they can't be delivered), and exits. Run it as a **separate task** with its own admin secret and IAM role, so the admin credential never sits in the long-running data path. If you prefer one process, `--db-bootstrap-interval 10m` (or `LIMEN_DB_BOOTSTRAP_INTERVAL`) reconciles inside the running worker; it is **off by default**.

What it does, per role, and only for names starting with `limen_`:

- creates the role or user with login, and with no superuser, create-database, create-role, replication, or row-security bypass;
- sets its password from `password_dir/<role>`, or generates one (hex, 256 bits) and writes the file with mode `0600`, **before** it creates the role, so a crash loses nothing;
- in IAM mode, grants `rds_iam` (PostgreSQL) or creates the user `IDENTIFIED WITH AWSAuthenticationPlugin AS 'RDS'` (MySQL), and requires TLS;
- grants exactly the declared access, revokes the rest (extra privileges, table or column grants, grants on other databases), and removes membership in other roles, which is how `SET ROLE` could escalate;
- sets default privileges for tables the admin creates later (PostgreSQL).

It is **idempotent**: it compares first and changes only the difference, so a second run does nothing. Every change is written as a `db.bootstrap` audit event **before** it is made; if the event can't be written, nothing changes. The events name the role and the action, never a password.

## 5. Check

```sh
limen ls                                   # the resource and its roles
limen db connect orders-prod --db-role limen_read
psql "host=127.0.0.1 port=… user=limen_read dbname=orders sslmode=disable" -c 'select 1'
```

In the audit trail: `session.start`, `db.query`, `db.query.end`, `session.end` with the same session id.

## IAM mode

Give the worker's IAM role (task role, instance profile, or IRSA) only what it needs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": "rds-db:connect",
      "Resource": "arn:aws:rds-db:eu-west-1:111122223333:dbuser:cluster-ABCDEFGHIJKL/limen_*" }
  ]
}
```

For Redshift provisioned, `redshift:GetClusterCredentials` on `arn:aws:redshift:<region>:<account>:dbuser:<cluster>/IAM:limen_*` (and `dbname:<cluster>/<database>`), with the resource's `cluster_identifier`; for Serverless, `redshift-serverless:GetCredentials` on the workgroup, with `workgroup`.

IAM database authentication needs the engine and instance class to support it, and tokens expire in 15 minutes (only the connect needs one). **This path is unverified against the real services.**

## Rotating a role's password

Delete `password_dir/limen_read` and run the bootstrap. It generates a new password, writes the file, and sets it on the database. Open sessions keep working; new ones use the new password. To make the database match a file you changed by hand, just run the bootstrap: it finds the mismatch and aligns the database to the file.

## Drift

The bootstrap reports (check mode) or repairs these:

| Difference | Action |
|---|---|
| role or user missing | `create_role` / `ensure_user` |
| login off, or superuser, createdb, createrole, replication, or bypassrls on | `alter_role` |
| member of another role | `revoke_membership` |
| password differs from the file | `reset_password` / `ensure_user` |
| privileges missing or extra, on tables, schemas, or databases | `grant` |
| default privileges missing or wrong | `default_privileges` |

## When something is wrong

| Message | Cause |
|---|---|
| `Limen couldn't connect to the database (is it reachable, and does its certificate match?)` | The worker can't reach `endpoint`, or the certificate isn't signed by `tls_ca_file` or doesn't carry the host (set `tls_server_name`). The worker log has the TLS error. |
| `could not authenticate to the database as limen_x` | The password file doesn't match the database. Run the bootstrap. |
| `the worker has no credential for this database role` | No `password_dir/<role>` file on the worker. Run the bootstrap, or mount the secrets. |
| `this session is for the database role …, not …` | The client asked for another user. Use the command `limen db connect` printed. |
| `Limen can't record this session right now, so it is closed` | The audit spool is full or the sink is failing; see [audit spool full](audit-spool-full.md). |
| `tls_ca_file is required …` | The resource has no `tls_ca_file`. For local development only: `insecure_dev: true` and `--allow-insecure-db-targets`. |
| `permission denied` inside a session | The database role lacks the grant. That is the database's decision; fix `bootstrap` and rerun. |
