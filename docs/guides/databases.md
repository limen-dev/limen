# Databases: PostgreSQL, MySQL, Aurora, and Redshift

`limen db connect` gives `psql`, `mysql`, and any driver a local address to connect to **without a password**. Limen checks who you are and what policy allows, logs in to the database as a `limen_*` role it manages, and writes every statement to the audit trail. You never see a database credential. Design: [ADR-0033](../adr/0033-sql-database-access.md), [ADR-0015](../adr/0015-database-credentials.md).

> **What is verified.** PostgreSQL 18 and MySQL 8.4 are tested end to end (TLS to the database, password logins, bootstrap, audit, cancel and kill). **IAM database authentication for RDS and Aurora, and everything Redshift-specific (its credential APIs and a real cluster), are unverified against the real services**: no AWS account has been available. The request signing matches AWS's published examples, and the Redshift calls are exercised against a local stand-in. See [what is and isn't tested](#what-is-tested).

## Connect

```sh
limen ls                                   # shows orders-staging (postgres) with your DB roles
limen db connect orders-staging            # picks your role if policy allows only one
# Limen is ready for orders-staging as limen_readonly. In another terminal:
#   psql "host=127.0.0.1 port=54623 user=limen_readonly dbname=orders sslmode=disable"
```

| Option | Meaning |
|---|---|
| `--db-role ROLE` | The database role to use. Needed when policy allows you several. |
| `--database NAME` | The database. Defaults to the resource's `default_database`. |
| `--listen ADDR` | Where to listen (default `127.0.0.1` and a free port). A non-loopback address prints a warning: anyone who can reach it rides your session. |
| `--socket PATH` | A Unix socket (mode `0600`) instead of TCP. |

Every connection to the listener is **one Limen session**, authorized, audited, and limited by your certificate's lifetime. The listener stops after an hour with no connections. The connection from your tool to the listener is plain text on your own machine, so use `sslmode=disable` (PostgreSQL) or `--ssl-mode=DISABLED` (MySQL). The hop to the proxy is mutual TLS, and the hop to the database is verified TLS.

Other local processes and users can connect to the listener while it runs. Bind to a socket with `--socket` on shared machines.

## What gets audited

Each statement produces two events in the audit trail, both from the worker next to the database:

- **`db.query`**, written **before** the statement is forwarded. If it can't be written (the sink is down and the spool is full), the statement is refused and the session ends. It has the statement text, `statement_type` (`select`, `insert`, ... from the tokenizer; `other` or `unknown` otherwise), the `phase` (`simple`, `parse`, `execute`, `function_call`, `cancel`, `refused`), the user, the `db_role`, the `database`, and the resource.
- **`db.query.end`**, with `query_id` (the first event's id), `status` (`ok`, `error`, `not_completed`), `duration_ms`, `rows` (returned for a `SELECT`, affected otherwise), and the database's error code and message. For MySQL the error number is `error_number` and the SQLSTATE is `error_code`.

Also: the proxy writes `session.start` and `session.end` (with `database`), refused logins are `auth.denied` with `action: db`, and role changes are `db.bootstrap`.

- **Text** is logged as written. A message with several statements gets one event per statement. A statement over 256 KiB is truncated, and `statement_sha256` has the hash of the whole.
- **Prepared statements**: the text is logged at `Parse`/`COM_STMT_PREPARE`, and each `Execute` is logged with the statement's name and `parse_query_id`. **Parameter values are never logged**, in this release.
- **Never logged**: result rows, `COPY` data, and passwords.
- **`normalize_literals: true`** on a resource replaces literals with `?` in the logged text (`email = 'a@b.c'` becomes `email = ?`). Text that can't be tokenized is withheld in this mode.
- **In the console**, a database session's page lists its statements (time, type, text, outcome, rows, duration, error), up to 500, newest last. Database sessions have no terminal recording; this list is the record. The console keeps statement text up to 16 KiB in the control plane's database (table `db_statements`), visible only to admins and to the session's own user. The complete trail stays in S3 and Datadog.
- Statement text can still contain secrets that a user typed into it. Treat the audit store accordingly ([threat model](../threat-model.md)).

Joining your database's own logs to Limen: Limen sets `application_name` (PostgreSQL, Redshift) or the `limen_session` connection attribute (MySQL) to `limen:<session id>` / the session id.

## What Limen enforces, and what the database does

Limen decides **who may use which role on which database**: policy grants (`db: { roles, databases }`) are checked at the proxy and again at the worker. Everything *inside* the session is limited by **the database's own grants for that role**. Limen does not parse statements to allow or deny them (ADR-0012), so a role that can `DROP TABLE` lets its users do it, and they are audited doing it. Keep roles narrow (`limen_readonly`), and let [bootstrap](../runbooks/database-onboarding.md#bootstrap) manage the grants.

The worker adds a few guards the wire protocol makes cheap:

| Guard | PostgreSQL / Redshift | MySQL |
|---|---|---|
| One user, one database | The startup `user` must be the granted role; `database` must be the granted one (or absent). | The same, from the handshake. `USE` and `COM_INIT_DB` to another database are refused. |
| No switching identity | | `COM_CHANGE_USER` is refused. |
| No replication | `replication=...` startup is refused. | `COM_BINLOG_DUMP` and the other replication commands are refused. |
| No startup options | `options=...` is refused (use `SET` after connecting). | |
| No file access | | `LOCAL INFILE` is not offered. |
| Role escalation | `SET ROLE` is not blocked; bootstrap makes sure the role is a member of nothing, so there is no role to switch to, and reports drift. | Bootstrap revokes role grants the same way. |
| Cancel / kill | `CancelRequest` works, through a per-session key that only the same user can use. | `KILL [QUERY\|CONNECTION] <id>` works with the id the client was shown; every other `KILL` is refused. |

**Known limit:** sessions that share a database role share its powers on the server. The database lets a role cancel or terminate its own other sessions (`pg_cancel_backend`, `pg_terminate_backend`, `KILL` through a prepared statement), so two people on the same role can disturb each other's queries. Use separate roles where that matters.

## Resources

```yaml
kind: resource
version: v1
metadata: { name: orders-staging, labels: { env: staging, team: payments } }
spec:
  postgres:                        # or mysql, or redshift
    endpoint: "orders.internal:5432"
    default_database: orders
    tls_ca_file: /etc/limen/rds-ca-bundle.pem   # required; the certificate is verified
    # Secret mode (any server): each role's password is a file in this directory.
    iam_auth: false
    password_dir: /run/limen/db-secrets
    # Role bootstrap: see the runbook.
    admin_user: limen_admin
    admin_password_file: /run/limen/db-secrets/.admin
    bootstrap:
      - role: limen_readonly
        grants: [{ database: orders, access: read }]
      - role: limen_rw
        grants: [{ database: orders, access: write }]
  worker_selector: { pool: staging-vpc }
```

| Field | Meaning |
|---|---|
| `endpoint` | `host:port` the **worker** can reach. |
| `default_database` | Used when the user doesn't name one. |
| `iam_auth` | `true` (the default) for IAM on RDS, Aurora, and Redshift; `false` for secret mode. |
| `region` | The AWS region (IAM only). |
| `password_dir` | Secret mode: a directory on the worker with one file per role, named for the role. |
| `tls_ca_file` | PEM bundle that signs the database's certificate. **Required**: Limen verifies the certificate and the name. |
| `tls_server_name` | The name the certificate carries, when it isn't the host in `endpoint`. |
| `insecure_dev` | Plain text to the database. Refused unless the worker runs with `--allow-insecure-db-targets` (the local compose profile). |
| `normalize_literals` | Replace literals in logged statement text with `?`. |
| `cluster_identifier` / `workgroup` | Redshift IAM: the provisioned cluster, or the serverless workgroup. |
| `admin_user`, `admin_password_file`, `bootstrap` | Role bootstrap. `admin_secret_arn` (Secrets Manager) is **not supported yet**: use the password file. |

Grants in a role:

```yaml
allow:
  - resources: { kind: [postgres, mysql], labels: { env: [staging] } }
    db: { roles: [limen_readonly], databases: [orders] }   # "*" for any database
```

Database role names must be `limen_` followed by lowercase letters, digits, or underscores. The prefix is reserved: Limen never creates or changes any other role.

## Aurora

Aurora is the same code. The cluster **writer** and **reader** endpoints are separate resources of kind `postgres` or `mysql`, each with its own `endpoint`. With IAM, set `region` and use the cluster endpoint.

## Redshift

`redshift` resources use the PostgreSQL relay with these differences:

- **Login.** Password mode (`password_dir`) works as for PostgreSQL, with SCRAM or the legacy **MD5** exchange Redshift uses. With IAM, the worker calls `GetClusterCredentials` (set `cluster_identifier`) or Redshift Serverless `GetCredentials` (set `workgroup`), and logs in as the user the API returns (`IAM:<role>`, `IAMR:<role>`). The database user still appears as `<role>` in policy and audit.
- **Compatibility.** The relay passes the standard v3 protocol through and uses only the startup, simple query, extended query, `COPY`, and cancel messages. Redshift doesn't implement every PostgreSQL feature (for example `LISTEN`/`NOTIFY`, large objects, many catalog functions); those fail on the cluster, not in Limen.
- **Role bootstrap** works for password mode. Redshift has no `rds_iam`, so IAM mode creates the user and relies on the credential API.
- **Unverified.** There is no Redshift emulator. The Redshift-specific parts (credential APIs, MD5 against a Redshift server, version quirks) are *unverified against a real cluster*. The shared PostgreSQL test suite runs against vanilla PostgreSQL with the Redshift engine profile, including a role that logs in with MD5.

## What is tested

| Area | How | Status |
|---|---|---|
| PostgreSQL relay: simple and extended protocol, `COPY`, cancel, guards, audit, fail-closed | `crates/limen-worker/tests/db_pg.rs` against PostgreSQL 18 | Tested |
| PostgreSQL TLS (`verify-full` against a CA, wrong name refused) | the same, against the compose target | Tested |
| MySQL relay: text and binary protocol, multi-statements, guards, `KILL`, audit | `db_mysql.rs` against MySQL 8.4 with TLS | Tested |
| Role bootstrap: create, idempotent re-run, drift repair, no secrets in events | `db_bootstrap.rs`, `db_mysql.rs` | Tested |
| Through the proxy and worker: login, denial, audit, lock ends the session | `limen-e2e/tests/phase6.rs`, `deploy/compose/demo-phase6.sh` | Tested |
| SigV4 signing | AWS's published examples (unit tests) | Matches the examples |
| RDS/Aurora IAM tokens; `rds_iam` and `AWSAuthenticationPlugin` | token format and SQL shape; stub `rds_iam` role | **Unverified against real AWS** |
| Redshift credential APIs, MD5 against Redshift | local HTTP stand-in; MD5 against PostgreSQL | **Unverified against a real cluster** |

## Not in this release

- Secrets Manager for the bootstrap admin (`admin_secret_arn`); use `admin_password_file`.
- Logging parameter values (`audit.log_parameters`); they are always omitted.
- Statement-level policy (for example "deny `DROP`"). Use the database's grants.
- MySQL cursors (`COM_STMT_FETCH`), compression, and `LOCAL INFILE`; PostgreSQL GSSAPI encryption and protocol versions other than 3.0.
- Grafana panels and typed audit-table columns for `db.*` events. The events are complete in S3 and Datadog; the Athena and Trino tables don't list the new fields yet.
- Per-resource idle timeouts: sessions end after an hour of silence, and at `max_session_ttl`.
