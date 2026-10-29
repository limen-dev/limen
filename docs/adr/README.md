# Architecture Decision Records

The format is [MADR](https://adr.github.io/madr/). Each record has a status: `Proposed`, `Accepted`, `Superseded by ADR-NNNN`, or `Deprecated`.
Each ADR's status line gives its approval date.

| # | Title | Status |
|---|---|---|
| [0001](0001-language-rust.md) | Rust for all components | Accepted |
| [0002](0002-component-roles.md) | Workers terminate protocols; the proxy authorizes and routes | Accepted |
| [0003](0003-reverse-tunnel.md) | Reverse tunnel: gRPC served by the worker over an outbound connection | Accepted |
| [0004](0004-proxy-peering.md) | Proxy HA through tunnel registry and proxy peering | Accepted |
| [0005](0005-single-port-ingress.md) | Single public port with ALPN and path routing behind an NLB | Accepted |
| [0006](0006-identity-and-credentials.md) | OIDC login with key-bound nonce, short-lived X.509 and SSH certificates | Accepted |
| [0007](0007-certificate-authority.md) | Three CA keys behind a Signer trait, KMS in production | Accepted |
| [0008](0008-policy-model.md) | YAML label-based policy, push-applied, signed snapshots | Accepted |
| [0009](0009-audit-pipeline.md) | Disk spool, at-least-once delivery, S3 hash chain, Datadog | Accepted |
| [0010](0010-state-store.md) | Aurora PostgreSQL through sqlx; advisory-lock leader election | Accepted |
| [0011](0011-failure-semantics-and-observability.md) | Control-plane outage semantics and observability stack | Accepted |
| [0012](0012-dependency-selection.md) | Dependency selection and maintenance criteria | Accepted |
| [0013](0013-license.md) | Apache-2.0 license | Accepted |
| [0014](0014-dashboards.md) | Self-hosted Grafana on ECS over Athena | Accepted |
| [0015](0015-database-credentials.md) | One IAM-authenticated DB role per policy role | Accepted |
| [0016](0016-join-methods.md) | How proxies and workers join: single-use, IAM (planned), static tokens | Accepted |
| [0017](0017-web-console.md) | Web console: read-mostly, server-rendered, built into the control plane | Accepted |
| [0018](0018-data-store-protocols.md) | Search, document, and messaging protocols (OpenSearch/Elasticsearch, MongoDB/Atlas/DocumentDB, Redshift, RabbitMQ, Kafka) | Proposed |
| [0019](0019-machine-identities.md) | Machine identities (bots) for CI and automation | Accepted |
| [0020](0020-scale-out.md) | Scale-out: many control planes, proxies, and workers | Accepted |
| [0021](0021-docs-site-and-homepage.md) | Documentation site and project homepage | Accepted |
| [0022](0022-web-apps-and-tcp-services.md) | Identity-aware access to internal web apps and TCP services | Accepted |
| [0023](0023-roadmap-in-github.md) | The roadmap lives in GitHub milestones and labels | Accepted |
| [0024](0024-release-strategy.md) | Releases and distribution: one version, signed binaries and images, Terraform by tag | Accepted |
| [0025](0025-access-requests.md) | Access requests and just-in-time approval (with break-glass) | Accepted (built in Phase 13) |
| [0026](0026-audit-and-recording-search.md) | Searching audit events and recordings, and the auditor role | Accepted (built in Phase 13) |
| [0027](0027-resource-discovery.md) | Resource discovery by workers, with quarantine for tag-derived labels | Accepted (built in Phase 13) |
| [0028](0028-policy-tooling.md) | Policy tooling: test, simulate, diff, explain | Accepted (built in Phase 13) |
| [0029](0029-access-reviews-and-evidence.md) | Access reviews and compliance evidence packs | Accepted (built in Phase 13) |
| [0030](0030-live-session-watch.md) | Watching a live session (read-only) | Accepted (built in Phase 13) |
| [0031](0031-positioning.md) | Positioning: access you can prove (provable, explainable, justified, agent-ready, open) | Proposed |
| [0032](0032-ai-agents-as-principals.md) | AI agents as principals: a bot flavour with accountable owners and per-action approval | Proposed |
| [0033](0033-sql-database-access.md) | SQL database access: PostgreSQL, MySQL, Aurora, Redshift (Phase 6) | Accepted |
| [0034](0034-redis-and-valkey-access.md) | Redis and Valkey access (Phase 7): RESP codec in the worker, ACL users, redacted values | Accepted |
| [0035](0035-mongodb-access.md) | MongoDB, Atlas, and DocumentDB access (Phase 9): BSON/OP_MSG relay in the worker, SCRAM/X.509/IAM, redacted command shapes | Accepted |
| [0036](0036-search-access.md) | OpenSearch and Elasticsearch access (Phase 10): HTTP front in the worker, policy by method class and index pattern | Accepted |
| [0038](0038-kubernetes-access.md) | Kubernetes (EKS) access through impersonation, with recorded exec (Phase 8) | Accepted |
| [0039](0039-detached-connections.md) | Detached connections (`--detach`) and `limen conns` | Accepted |
| [0040](0040-trace-export.md) | Trace export over OTLP | Accepted |
| [0037](0037-messaging-access.md) | RabbitMQ, Amazon MQ, Kafka, and MSK access (Phase 11): AMQP and Kafka codecs in the worker, multi-broker slot rewrite, bodies never logged | Proposed |
| [0042](0042-management-api.md) | One management API for the CLI, the console, and infrastructure as code (Phase 14): the `limen.manage.v1` contract, one owner per document, scoped bot writers that complete resource profiles, server-side guardrails | Proposed (final design) |

ADR-0013 and ADR-0014 are marked Accepted because the owner decided them directly during Phase 0 clarification. ADR-0018 to ADR-0022 and ADR-0025 to ADR-0032 were requested by the owner on 2026-10-14 and initially marked `Proposed`; ADR-0022 was accepted when the owner approved its Phase 12 implementation defaults.
