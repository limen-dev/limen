# ADR-0014: Self-hosted Grafana on ECS over Athena

- Status: Accepted (owner decision, 2026-10-13; the owner considered a Datadog-only alternative and kept Grafana)

## Context
S3 is the long-term, tamper-evident audit store. Datadog log retention is short and costly per GB, and Datadog can't query S3 directly.

## Decision
- Grafana OSS runs as one more Fargate service in the same Terraform. That keeps "one `terraform apply`" true.
- The Athena data source plugin uses the Grafana task role (Athena, Glue, read-only S3 on the audit bucket, and its own query results bucket).
- Dashboards, data sources, and alert rules are provisioned from `dashboards/grafana/` as files. The UI is read-only for provisioned items.
- Grafana login uses Okta OIDC (`generic_oauth`). Only the `limen:auditor` and `limen:admin` groups get access.

## Consequences
- − One more stateful service. Its SQLite state lives on EFS, or it uses Aurora as Grafana's DB; this gets decided in Phase 3.
- *Unverified locally:* Athena isn't available in compose. Dashboard SQL is checked against Trino over MinIO in Phase 3, and against real Athena once an AWS account exists.
