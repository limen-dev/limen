# Databases: PostgreSQL, MySQL, Aurora, and Redshift

`limen db connect` gives `psql`, `mysql` and any driver a local address that needs no password. Limen checks your identity and policy, logs in as a `limen_*` role it manages, and audits every statement. You never see a database credential. Design: [ADR-0033](../adr/0033-sql-database-access.md), [ADR-0015](../adr/0015-database-credentials.md).

> **Verification.** PostgreSQL 18 and MySQL 8.4 are tested end to end. RDS and Aurora IAM authentication and everything Redshift-specific (credential APIs, a real cluster) are **unverified** against the real services. The Status page lists every gap.

## Connect

```sh
limen ls                                   # orders-staging (postgres) with your DB roles
limen db connect orders-staging            # picks your role if policy allows only one
# Limen is ready for orders-staging as limen_read. In another terminal:
#   psql "host=127.0.0.1 port=54623 user=limen_read dbname=orders sslmode=disable"
```

| Option | Meaning |
|---|---|
| `--db-role ROLE` | Database role to use. Required when policy allows several. |
| `--database NAME` | Database. Defaults to the resource's `default_database`. |
| `--listen ADDR` | Listen address (default `127.0.0.1`, free port). A non-loopback address prints a warning: anyone who can reach it rides your session. |
| `--socket PATH` | Unix socket (mode `0600`) instead of TCP. Prefer it on shared machines. |

Each connection to the listener is one Limen session, authorized, audited and capped by your certificate's lifetime. The listener stops after an hour with no connections. Your tool talks to it in plain text on your own machine (`sslmode=disable` for PostgreSQL, `--ssl-mode=DISABLED` for MySQL); the hop to the proxy is mutual TLS and the hop to the database is verified TLS.

## What gets audited

Each statement produces two events, written by the worker next to the database:

- **`db.query`**, written *before* the statement is forwarded. If it can't be written (sink down, spool full), the statement is refused and the session ends. Fields: statement text, `statement_type` (`select`, `insert`, … or `other`/`unknown`), `phase` (`simple`, `parse`, `execute`, `function_call`, `cancel`, `refused`), user, `db_role`, `database`, resource.
- **`db.query.end`**, with `query_id` (the first event's id), `status` (`ok`, `error`, `not_completed`), `duration_ms`, `rows` (returned for `SELECT`, affected otherwise), and the database's error code and message. On MySQL the error number is `error_number` and the SQLSTATE is `error_code`.

The proxy adds `session.start` and `session.end` (with `database`). Refused logins are `auth.denied` with `action: db`; role changes are `db.bootstrap`.

- Text is logged as written, one event per statement in a multi-statement message. Statements over 256 KiB are truncated; `statement_sha256` hashes the whole.
- Prepared statements: the text is logged at `Parse`/`COM_STMT_PREPARE`; each `Execute` logs the statement name and `parse_query_id`. **Parameter values are never logged.**
- Never logged: result rows, `COPY` data, passwords.
- Literals are replaced with `?` in logged statement text by default (`email = 'a@b.c'` becomes `email = ?`), so the trail shows what was run but not the values in it. Text that can't be tokenized is withheld. Set `normalize_literals: false` on a resource to log the full text; do that only where the audit sinks are as tightly held as the database.
- The console session page lists the statements ([command lists](console.md)); text is kept up to 16 KiB.
- Statement text can still contain secrets a user typed. Treat the audit store accordingly ([threat model](../threat-model.md)).

To join the database's own logs to Limen, use `application_name` (PostgreSQL, Redshift) or the `limen_session` connection attribute (MySQL): both carry the session id (`limen:<session id>` for `application_name`).

## What Limen enforces

Limen decides **who may use which role on which database**. Policy grants (`db: { roles, databases }`) are checked at the proxy and again at the worker. Everything inside the session is limited by **the database's own grants for that role**. Limen doesn't parse statements to allow or deny them (ADR-0012), so a role that can `DROP TABLE` lets its users do it, audited. Keep roles narrow and let [bootstrap](../runbooks/database-onboarding.md#bootstrap) manage the grants.

The worker adds guards the wire protocol makes cheap:

| Guard | PostgreSQL / Redshift | MySQL |
|---|---|---|
| One user, one database | Startup `user` must be the granted role; `database` the granted one (or absent). | Same, from the handshake. `USE` and `COM_INIT_DB` to another database are refused. |
| No identity switch | | `COM_CHANGE_USER` refused. |
| No replication | `replication=...` startup refused. | `COM_BINLOG_DUMP` and other replication commands refused. |
| No startup options | `options=...` refused (use `SET` after connecting). | |
| No file access | | `LOCAL INFILE` not offered. |
| Role escalation | `SET ROLE` isn't blocked, but bootstrap keeps the role a member of nothing and reports drift. | Bootstrap revokes role grants the same way. |
| Cancel / kill | `CancelRequest` works through a per-session key only that user can use. | `KILL [QUERY\|CONNECTION] <id>` works with the id the client was shown; other `KILL`s are refused. |

**Known limit:** sessions sharing a database role share its powers. A role can cancel or terminate its own other sessions (`pg_cancel_backend`, `pg_terminate_backend`, `KILL` via prepared statement), so two people on one role can disturb each other. Use separate roles where that matters.

## Resources

```yaml
kind: resource
version: v1
metadata: { name: orders-staging, labels: { env: staging, team: payments } }
spec:
  postgres:                        # or mysql, or redshift
    endpoint: "orders.internal:5432"
    default_database: orders
    tls_ca_file: /etc/limen/rds-ca-bundle.pem   # required; certificate is verified
    iam_auth: false                # secret mode: one password file per role
    password_dir: /run/limen/db-secrets
    admin_user: limen_admin        # role bootstrap: see the runbook
    admin_password_file: /run/limen/db-secrets/.admin
    bootstrap:
      - role: limen_read
        grants: [{ database: orders, access: read }]
      - role: limen_write
        grants: [{ database: orders, access: write }]
  worker_selector: { pool: staging-vpc }
```

| Field | Meaning |
|---|---|
| `endpoint` | `host:port` the **worker** can reach. |
| `default_database` | Used when the user names none. |
| `iam_auth` | `true` (default) for IAM on RDS, Aurora, Redshift; `false` for secret mode. |
| `region` | AWS region (IAM only). |
| `password_dir` | Secret mode: a worker directory with one file per role, named for the role. |
| `tls_ca_file` | PEM bundle that signs the database's certificate. **Required**: certificate and name are verified. |
| `tls_server_name` | Certificate name, when it differs from the host in `endpoint`. |
| `insecure_dev` | Plain text to the database. Refused unless the worker runs with `--allow-insecure-db-targets` (local compose only). |
| `normalize_literals` | Replace literals in logged text with `?`. On by default; `false` logs the full text. |
| `cluster_identifier` / `workgroup` | Redshift IAM: provisioned cluster or serverless workgroup. |
| `admin_user`, `admin_password_file`, `bootstrap` | Role bootstrap. `admin_secret_arn` (Secrets Manager) is not supported yet; use the password file. |

Grant it in a role:

```yaml
allow:
  - resources: { kind: [postgres, mysql], labels: { env: [staging] } }
    db: { roles: [limen_read], databases: [orders] }   # "*" for any database
```

Role names must be `limen_` plus lowercase letters, digits or underscores. The prefix is reserved: Limen never creates or changes any other role.

## Aurora

Same code. The cluster **writer** and **reader** endpoints are separate `postgres` or `mysql` resources, each with its own `endpoint`. With IAM, set `region` and use the cluster endpoint.

## Redshift

`redshift` resources use the PostgreSQL relay, with these differences:

- **Login.** Password mode works as for PostgreSQL, with SCRAM or the legacy MD5 exchange. With IAM, the worker calls `GetClusterCredentials` (set `cluster_identifier`) or Serverless `GetCredentials` (set `workgroup`) and logs in as the user the API returns (`IAM:<role>`, `IAMR:<role>`). Policy and audit still show `<role>`.
- **Compatibility.** Only the startup, simple query, extended query, `COPY` and cancel messages are relayed. Features Redshift lacks (`LISTEN`/`NOTIFY`, large objects, many catalog functions) fail on the cluster, not in Limen.
- **Bootstrap** works in password mode. Redshift has no `rds_iam`, so IAM mode creates the user and relies on the credential API.
- **Unverified.** There is no Redshift emulator. The credential APIs and MD5 against a real cluster are untested; the shared PostgreSQL suite runs against vanilla PostgreSQL with the Redshift profile.

## Limits

- No Secrets Manager for the bootstrap admin (`admin_secret_arn`); use `admin_password_file`.
- No parameter logging (`audit.log_parameters`); values are always omitted.
- No statement-level policy (such as "deny `DROP`"); use the database's grants.
- Not supported: MySQL cursors (`COM_STMT_FETCH`), compression and `LOCAL INFILE`; PostgreSQL GSSAPI encryption and protocol versions other than 3.0.
- Athena/Trino tables and Grafana panels don't list the `db.*` fields yet. The events are complete in S3 and Datadog.
- No per-resource idle timeout: sessions end after an hour of silence and at `max_session_ttl`.
