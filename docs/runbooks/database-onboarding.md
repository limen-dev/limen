# Runbook: onboarding a database

Put a PostgreSQL, MySQL, Aurora or Redshift database behind `limen db connect`, keep its `limen_*` roles in line with policy, and fix drift. Model: [ADR-0015](../adr/0015-database-credentials.md), [ADR-0033](../adr/0033-sql-database-access.md). User side: [databases guide](../guides/databases.md).

Limen logs in as one **`limen_*` role per policy role** (`limen_read`, `limen_write`, …). People never get a credential. A dedicated **admin login** (`limen_admin`) creates those roles. Never give Limen the master user.

## 1. Reach the database from a worker

- Run a worker in a network that reaches it, labelled to match the resource's `worker_selector` ([worker enrollment](worker-enrollment.md)).
- Put the CA that signs the database certificate on the worker (for AWS, the RDS bundle: `https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem`). Limen won't connect unverified.

## 2. Create the admin login

**PostgreSQL / Aurora PostgreSQL**

```sql
CREATE ROLE limen_admin LOGIN CREATEROLE PASSWORD '<generated>';
-- It must be able to grant on your objects: make it the owner, or give it
-- the grants it will pass on. For a database it will manage:
ALTER DATABASE orders OWNER TO limen_admin;           -- simplest, or
GRANT ALL ON ALL TABLES IN SCHEMA public TO limen_admin WITH GRANT OPTION;
-- RDS, IAM mode only (run as the master user):
GRANT rds_iam TO limen_admin WITH ADMIN OPTION;
```

**MySQL / Aurora MySQL**

```sql
CREATE USER 'limen_admin'@'%' IDENTIFIED BY '<generated>' REQUIRE SSL;
GRANT CREATE USER ON *.* TO 'limen_admin'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON orders.* TO 'limen_admin'@'%' WITH GRANT OPTION;
-- IAM mode reads other users' grants with SHOW GRANTS FOR, which needs:
GRANT SELECT ON mysql.* TO 'limen_admin'@'%';
```

**Redshift:** a user with `CREATEUSER`, plus the privileges it will grant `WITH GRANT OPTION`.

Give the admin password to the worker as a file (Kubernetes or ECS secret, or a mounted volume), mode `0400`.

## 3. Describe it in policy

Write the resource as in the [databases guide](../guides/databases.md#resources). For RDS or Aurora IAM, set `iam_auth: true` and `region` (endpoint such as `orders.cluster-xyz.eu-west-1.rds.amazonaws.com:5432`, CA `rds-global-bundle.pem`); for passwords set `iam_auth: false` and `password_dir`. Keep `admin_user`, `admin_password_file` and the `bootstrap` roles. Add a role letting people use them (`db: { roles: [limen_read], databases: [orders] }`) and `limen admin apply`. Role names must start with `limen_`.

`access: read` is `SELECT`; `write` is `SELECT, INSERT, UPDATE, DELETE` (and sequence use) on every table in the listed `schemas` (default `public`; for MySQL, the database). Later tables get the same grants (PostgreSQL default privileges; MySQL schema-level grants).

## 4. Bootstrap the roles <a id="bootstrap"></a>

```sh
# Show what would change. Exit status: 0 nothing, 2 differences, 1 failure.
limen-worker --db-bootstrap-once --db-bootstrap-check <the worker's usual flags>
# Make the changes:
limen-worker --db-bootstrap-once <the worker's usual flags>
```

One-shot mode enrolls, fetches policy, reconciles every database resource its labels may serve, ships its audit events to the control plane (exit 1 if they can't be delivered), and exits. Run it as a **separate task** with its own admin secret and IAM role, so the admin credential never sits in the long-running data path. For one process instead, `--db-bootstrap-interval 10m` (`LIMEN_DB_BOOTSTRAP_INTERVAL`) reconciles inside the worker; it's **off by default**.

Per role, and only for names starting with `limen_`, it:

- creates the role or user with login and no superuser, create-database, create-role, replication or row-security bypass;
- sets the password from `password_dir/<role>`, or generates one (256-bit hex) and writes the file with mode `0600` **before** creating the role, so a crash loses nothing;
- in IAM mode, grants `rds_iam` (PostgreSQL) or creates the user `IDENTIFIED WITH AWSAuthenticationPlugin AS 'RDS'` (MySQL) and requires TLS;
- grants exactly the declared access and revokes the rest (extra privileges, table or column grants, grants on other databases), and removes membership in other roles, which `SET ROLE` could abuse to escalate;
- sets default privileges for tables the admin creates later (PostgreSQL).

It's **idempotent**: it compares first and changes only the difference. Every change is a `db.bootstrap` audit event written **before** it's made; if the event can't be written, nothing changes. Events name the role and action, never a password.

## 5. Check

```sh
limen ls                                   # the resource and its roles
limen db connect orders-prod --db-role limen_read
psql "host=127.0.0.1 port=… user=limen_read dbname=orders sslmode=disable" -c 'select 1'
```

The audit trail should show `session.start`, `db.query`, `db.query.end`, `session.end` with one session id.

## IAM mode

Give the worker's IAM role (task role, instance profile or IRSA) only:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": "rds-db:connect",
      "Resource": "arn:aws:rds-db:eu-west-1:111122223333:dbuser:cluster-ABCDEFGHIJKL/limen_*" }
  ]
}
```

Redshift provisioned: `redshift:GetClusterCredentials` on `arn:aws:redshift:<region>:<account>:dbuser:<cluster>/IAM:limen_*` (and `dbname:<cluster>/<database>`), with the resource's `cluster_identifier`. Serverless: `redshift-serverless:GetCredentials` on the workgroup, with `workgroup`.

The engine and instance class must support IAM authentication; tokens last 15 minutes (only the connect needs one). **Unverified against the real services.**

## Rotating a password

Delete `password_dir/limen_read` and run the bootstrap: it generates a new password, writes the file, and sets it on the database. Open sessions continue; new ones use the new password. To align the database with a file you edited by hand, just run the bootstrap.

## Drift

The bootstrap reports (check mode) or repairs:

| Difference | Action |
|---|---|
| role or user missing | `create_role` / `ensure_user` |
| login off, or superuser, createdb, createrole, replication or bypassrls on | `alter_role` |
| member of another role | `revoke_membership` |
| password differs from the file | `reset_password` / `ensure_user` |
| privileges missing or extra, on tables, schemas or databases | `grant` |
| default privileges missing or wrong | `default_privileges` |

## When something is wrong

| Message | Cause |
|---|---|
| `Limen couldn't connect to the database (is it reachable, and does its certificate match?)` | The worker can't reach `endpoint`, or the certificate isn't signed by `tls_ca_file` or lacks the host (set `tls_server_name`). The worker log has the TLS error |
| `could not authenticate to the database as limen_x` | The password file doesn't match the database. Run the bootstrap |
| `the worker has no credential for this database role` | No `password_dir/<role>` on the worker. Run the bootstrap or mount the secrets |
| `this session is for the database role …, not …` | The client asked for another user. Use the command `limen db connect` printed |
| `Limen can't record this session right now, so it is closed` | Audit spool full or sink failing: [audit spool full](audit-spool-full.md) |
| `tls_ca_file is required …` | Set `tls_ca_file`. Local development only: `insecure_dev: true` plus `--allow-insecure-db-targets` |
| `permission denied` inside a session | The database role lacks the grant, which is the database's decision. Fix `bootstrap` and rerun |
