# ADR-0018: Search, document, and messaging protocols

- Status: Proposed (owner requested 2026-10-14; each protocol is confirmed when its phase starts)
- Date: 2026-10-14

## Context
Beyond SSH, SQL, Redis, and Kubernetes, the owner wants Limen to reach: OpenSearch and Elasticsearch, RabbitMQ (including Amazon MQ), Kafka (including MSK), MongoDB (Atlas must work) and DocumentDB, and Redshift. Each should work with the managed AWS service **and** with any compatible self-hosted server, so no feature may depend on an AWS-only API without a generic fallback.

The pattern from ADR-0002 holds: the **worker terminates the protocol next to the target** and holds the credential; the proxy only authorizes and routes; the CLI exposes a local listener (or a plugin) so the user's own tools work unchanged. What changes per protocol is how the worker authenticates, what is audited, and how hard the wire protocol is to proxy.

## Decisions (one per target)

| Target | Wire | Worker authenticates with | Audit | Difficulty and risk |
|---|---|---|---|---|
| **Redshift** | PostgreSQL protocol v3 | `redshift:GetClusterCredentials` / `GetClusterCredentialsWithIAM` (provisioned) or `redshift-serverless:GetCredentials`, or a password for non-AWS PostgreSQL | Same as PostgreSQL | **Low.** It reuses the PostgreSQL module (ADR-0015). Redshift is wire-compatible but is not PostgreSQL: some catalog queries and extended-protocol features differ, so it gets its own compatibility tests. *Unverified against a real cluster.* |
| **MongoDB (any, Atlas)** | MongoDB wire protocol (OP_MSG) | Self-hosted: SCRAM-SHA-256 or X.509. **Atlas:** SCRAM, X.509, `MONGODB-AWS` (IAM), or Atlas workforce OIDC. SRV (`mongodb+srv://`) resolution happens at the worker. | Command name, database, collection, and a redacted filter by default; full text opt-in. Values redacted like Redis. | **Medium.** The worker must not let a client switch databases or users in ways policy forbids. Atlas is reached over the internet, so the worker's egress IP (or PrivateLink) must be allowed by Atlas. |
| **DocumentDB** | MongoDB wire (a compatible subset) | Password, or IAM (`MONGODB-AWS`, `authSource=$external`) on instance clusters version 5.0, not for the primary user ([AWS docs](https://docs.aws.amazon.com/documentdb/latest/developerguide/iam-identity-auth.html)). TLS with the AWS CA bundle is required. | As MongoDB | **Low once MongoDB works**, plus a compatibility matrix: DocumentDB doesn't implement every command. |
| **OpenSearch / Elasticsearch** | HTTP(S) REST | OpenSearch Service: SigV4 (service `es`; OpenSearch Serverless is `aoss`) using the worker's role, with fine-grained access control mapping. Elasticsearch and self-hosted OpenSearch: basic auth, API key, or mTLS. | Every request: method, path, index, status, bytes. Bodies of `_search`/`_bulk` are not logged by default (they can hold PII); opt-in per resource. | **Medium.** HTTP is easy to proxy, but "which index does this touch" needs path and body awareness (`_msearch`, `_bulk`, aliases, `/_all`). Policy is by index pattern and by method class (read, write, admin). |
| **RabbitMQ / Amazon MQ** | AMQP 0-9-1 (5672/5671), plus the management HTTP API | Broker users, LDAP, OAuth 2.0, or X.509. **IAM** is available on RabbitMQ 3.13 and 4.2+ by exchanging IAM credentials for an STS JWT ([AWS docs](https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/rabbitmq-authentication.html)); older brokers need a worker-held user. | Connection, vhost, channel operations (declare, bind, consume, publish): exchange, routing key, size. **Message bodies are never logged.** | **Medium.** AMQP framing is small. The management UI/API is reached as a web resource (ADR-0022). |
| **Kafka / MSK** | Kafka binary protocol | MSK: IAM (`SASL/OAUTHBEARER` with `AWS_MSK_IAM`), SCRAM, or mTLS. Self-hosted: SASL (PLAIN, SCRAM, OAUTHBEARER, GSSAPI) or mTLS. | Connection, API key, topic, consumer group, bytes. Record values are never logged. | **High.** A client connects to *every broker*, at the addresses the cluster advertises in Metadata responses. The worker must either rewrite advertised addresses to per-broker local ports, or the CLI must run a small local multi-listener. This needs a design spike before committing to a date. |

All of them follow ADR-0015's rule where a database has IAM or roles: the credential is short-lived and held by the worker, the user never sees it, and denial is the default.

## Consequences
- Phases 9 to 11 add these in the order of lowest risk first: documents (reuses Redis-style redaction), search (HTTP), then messaging (Kafka last).
- A generic compatibility promise needs a **conformance suite per protocol** against at least one real open-source server (MongoDB, Elasticsearch/OpenSearch, RabbitMQ, Kafka, all runnable in compose) and, where the AWS variant differs, a documented difference list marked *unverified against real service* until tested.
- Policy gains one grant section per protocol, in the same style as `ssh`, `db`, `redis`, `kube` (ADR-0008).
- Audit schema gains one event kind per protocol; the Grafana "privileged commands" and "who accessed what" panels learn the new kinds.
