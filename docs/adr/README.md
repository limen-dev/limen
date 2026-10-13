# Architecture Decision Records

The format is [MADR](https://adr.github.io/madr/). Each record has a status: `Proposed`, `Accepted`, `Superseded by ADR-NNNN`, or `Deprecated`.
Every ADR below is **Proposed** until the owner approves the Phase 0 design.

| # | Title | Status |
|---|---|---|
| [0001](0001-language-rust.md) | Rust for all components | Proposed |
| [0002](0002-component-roles.md) | Workers terminate protocols; the proxy authorizes and routes | Proposed |
| [0003](0003-reverse-tunnel.md) | Reverse tunnel: gRPC served by the worker over an outbound connection | Proposed |
| [0004](0004-proxy-peering.md) | Proxy HA through tunnel registry and proxy peering | Proposed |
| [0005](0005-single-port-ingress.md) | Single public port with ALPN and path routing behind an NLB | Proposed |
| [0006](0006-identity-and-credentials.md) | OIDC login with key-bound nonce, 10-minute X.509 and SSH certificates | Proposed |
| [0007](0007-certificate-authority.md) | Three CA keys behind a Signer trait, KMS in production | Proposed |
| [0008](0008-policy-model.md) | YAML label-based policy, push-applied, signed snapshots | Proposed |
| [0009](0009-audit-pipeline.md) | Disk spool, at-least-once delivery, S3 hash chain, Datadog | Proposed |
| [0010](0010-state-store.md) | Aurora PostgreSQL through sqlx; advisory-lock leader election | Proposed |
| [0011](0011-failure-semantics-and-observability.md) | Control-plane outage semantics and observability stack | Proposed |
| [0012](0012-dependency-selection.md) | Dependency selection and maintenance criteria | Proposed |
| [0013](0013-license.md) | Apache-2.0 license | Accepted |
| [0014](0014-dashboards.md) | Self-hosted Grafana on ECS over Athena | Accepted |
| [0015](0015-database-credentials.md) | One IAM-authenticated DB role per policy role | Proposed |

ADR-0013 and ADR-0014 are marked Accepted because the owner decided them directly during Phase 0 clarification.
