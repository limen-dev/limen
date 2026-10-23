# ADR-0015: One IAM-authenticated DB role per policy role

- Status: Accepted (owner approved 2026-10-13)
- Date: 2026-10-13

## Context
The brief says the worker bootstrap "creates and maintains the DB roles mapped to policy roles", and that end users never see DB credentials.

## Decision
- **One database login role per policy-declared DB role**, for example `limen_read` and `limen_write`. Per-user DB roles are not used.
  - PostgreSQL: `CREATE ROLE limen_read LOGIN; GRANT rds_iam TO limen_read;` plus the declared grants.
  - MySQL: `CREATE USER 'limen_read'@'%' IDENTIFIED WITH AWSAuthenticationPlugin AS 'RDS' REQUIRE SSL;` plus the declared grants.
- The worker's IAM role gets `rds-db:connect` on exactly `arn:aws:rds-db:<region>:<acct>:dbuser:<resource-id>/limen_*`.
- **Bootstrap** reads the admin secret from Secrets Manager (the ARN comes from the resource definition) only during reconcile. It holds the secret in memory as `Secret<String>` and drops it after use. Reconcile runs at startup and every 10 min, is idempotent, and reports drift. The `limen_` prefix is reserved, and roles without it are never touched.
- **Attribution.** The DB sees `limen_read`, not the human user. Per-user attribution lives in Limen's audit. The worker also sets `application_name` (PostgreSQL) or a connection attribute (MySQL) to `limen:<session_id>`, so DB-side logs can be joined to Limen sessions.

## Consequences
- \+ A bounded number of DB roles, no per-user churn, and simple grants.
- − DB-native audit logs can't tell users apart without the session join.
- Note (AWS docs): adding `rds_iam` to a PostgreSQL user makes IAM auth take precedence over the password. Never grant it to the master user.
- *Unverified against real service* until an AWS account exists. Locally we test bootstrap SQL against vanilla PostgreSQL and MySQL with the IAM-specific clauses stubbed.

## Amendment (2026-10-17, ADR-0033)
- **Secret mode.** For servers without IAM authentication (self-hosted, and the local demo) the worker logs in with a password read from `password_dir/<role>` on the worker. Bootstrap creates the file (mode 0600) and sets the same password on the database. IAM remains the default for RDS and Aurora (`iam_auth: true`).
- **Bootstrap placement.** Reconcile no longer runs by default every 10 minutes inside the worker. It is a one-shot task (`limen-worker --db-bootstrap-once`, with `--db-bootstrap-check` to only report), and an in-process loop is opt-in (`--db-bootstrap-interval`). This keeps the admin credential out of the data-path process by default.
- **Admin credential.** A file (`admin_password_file`) today; Secrets Manager (`admin_secret_arn`) is not supported yet.
- **No role membership.** Bootstrap keeps `limen_*` roles members of nothing (except `rds_iam`), which is what makes `SET ROLE` harmless.

## Amendment: concise role names (2026-10-23)

Managed SQL roles keep the reserved `limen_` prefix and use consistent `read` / `write` suffixes: `limen_read` and `limen_write`. This updates the preferred names, not validation: existing `limen_*` names remain supported, and changing a policy role does not rename existing database principals automatically.
