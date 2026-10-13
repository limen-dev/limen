# ADR-0015: One IAM-authenticated DB role per policy role

- Status: Proposed
- Date: 2026-10-13

## Context
The brief says the worker bootstrap "creates and maintains the DB roles mapped to policy roles", and that end users never see DB credentials.

## Decision
- **One database login role per policy-declared DB role**, for example `limen_readonly` and `limen_rw`. Per-user DB roles are not used.
  - PostgreSQL: `CREATE ROLE limen_readonly LOGIN; GRANT rds_iam TO limen_readonly;` plus the declared grants.
  - MySQL: `CREATE USER 'limen_readonly'@'%' IDENTIFIED WITH AWSAuthenticationPlugin AS 'RDS' REQUIRE SSL;` plus the declared grants.
- The worker's IAM role gets `rds-db:connect` on exactly `arn:aws:rds-db:<region>:<acct>:dbuser:<resource-id>/limen_*`.
- **Bootstrap** reads the admin secret from Secrets Manager (the ARN comes from the resource definition) only during reconcile. It holds the secret in memory as `Secret<String>` and drops it after use. Reconcile runs at startup and every 10 min, is idempotent, and reports drift. The `limen_` prefix is reserved, and roles without it are never touched.
- **Attribution.** The DB sees `limen_readonly`, not the human user. Per-user attribution lives in Limen's audit. The worker also sets `application_name` (PostgreSQL) or a connection attribute (MySQL) to `limen:<session_id>`, so DB-side logs can be joined to Limen sessions.

## Consequences
- \+ A bounded number of DB roles, no per-user churn, and simple grants.
- − DB-native audit logs can't tell users apart without the session join.
- Note (AWS docs): adding `rds_iam` to a PostgreSQL user makes IAM auth take precedence over the password. Never grant it to the master user.
- *Unverified against real service* until an AWS account exists. Locally we test bootstrap SQL against vanilla PostgreSQL and MySQL with the IAM-specific clauses stubbed.
