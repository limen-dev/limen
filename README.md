<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg">
    <img src="assets/logo.svg" alt="Limen" width="320">
  </picture>
</p>

<p align="center"><b>Identity-aware access to your infrastructure. Short-lived, audited, self-hosted.</b></p>

<p align="center">
  <a href="https://github.com/jfcmartins/limen/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/jfcmartins/limen/ci.yml?branch=main&label=CI&logo=githubactions&logoColor=white"></a>
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-14B8A6"></a>
  <img alt="Written in Rust" src="https://img.shields.io/badge/written%20in-Rust-DEA584?logo=rust&logoColor=white">
  <a href="https://github.com/jfcmartins/limen/milestones"><img alt="Roadmap" src="https://img.shields.io/badge/roadmap-milestones-5319e7"></a>
</p>

# Limen

Limen is a self-hosted, open-source platform for identity-aware access to infrastructure. Engineers, and the bots that act for them, log in through their identity provider and get short-lived, audited access to SSH hosts, databases, caches, search and message brokers, Kubernetes, and internal web apps. There are no static SSH keys, shared database passwords, or hand-made users.

> **Status: Phase 3.5 complete.** OIDC login, policy, proxies with peering, workers, SSH with session recording, the audit pipeline (S3, Datadog, Grafana), and a web console work end to end against local stand-ins. Everything else below is planned: see the [roadmap](#roadmap).

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/images/console-overview-dark.jpg">
    <img src="docs/images/console-overview-light.jpg" alt="The Limen web console, showing resources, sessions, and workers" width="860">
  </picture>
</p>

Try it locally: [`deploy/compose/README.md`](deploy/compose/README.md), or run `deploy/compose/demo-phase2.sh` (SSH), `deploy/compose/demo-phase3.sh` (audit pipeline and dashboards), or `deploy/compose/demo-phase35.sh` (web console, locks, session kill).

## What it connects to

<table>
  <tr>
    <td align="center" valign="top" width="25%"><br><img src="assets/icons/terminal.svg" height="48" alt="SSH"><br><br><b>SSH</b><br><sub>EC2 and any SSH host<br>per-session certificates, recorded</sub><br><sub>✅ Working</sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/postgresql" height="48" alt="PostgreSQL"><br><br><b>PostgreSQL</b><br><sub>RDS · Aurora · Amazon Redshift<br>IAM auth, every statement audited</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/9">Phase 6</a></sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/mysql" height="48" alt="MySQL"><br><br><b>MySQL</b><br><sub>RDS · Aurora<br>IAM auth, every statement audited</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/9">Phase 6</a></sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/redis" height="48" alt="Redis / Valkey"><br><br><b>Redis / Valkey</b><br><sub>ElastiCache<br>values redacted in audit</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/10">Phase 7</a></sub><br><br></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/kubernetes" height="48" alt="Kubernetes"><br><br><b>Kubernetes</b><br><sub>Amazon EKS<br>impersonation, recorded exec</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/11">Phase 8</a></sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/mongodb" height="48" alt="MongoDB"><br><br><b>MongoDB</b><br><sub>any server · Atlas · DocumentDB<br>SCRAM, X.509, IAM</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/12">Phase 9</a></sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/opensearch" height="48" alt="OpenSearch"><br><br><b>OpenSearch</b><br><sub>Amazon OpenSearch Service<br>index-aware policy</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/13">Phase 10</a></sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><picture><source media="(prefers-color-scheme: dark)" srcset="https://cdn.simpleicons.org/elasticsearch/white"><img src="https://cdn.simpleicons.org/elasticsearch" height="48" alt="Elasticsearch"></picture><br><br><b>Elasticsearch</b><br><sub>self-hosted and Elastic Cloud<br>index-aware policy</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/13">Phase 10</a></sub><br><br></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/rabbitmq" height="48" alt="RabbitMQ"><br><br><b>RabbitMQ</b><br><sub>any broker · Amazon MQ<br>no message bodies in audit</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/14">Phase 11</a></sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><picture><source media="(prefers-color-scheme: dark)" srcset="https://cdn.simpleicons.org/apachekafka/white"><img src="https://cdn.simpleicons.org/apachekafka" height="48" alt="Kafka"></picture><br><br><b>Kafka</b><br><sub>any cluster · Amazon MSK<br>IAM, SCRAM, mTLS</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/14">Phase 11</a></sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="assets/icons/globe.svg" height="48" alt="Internal web apps"><br><br><b>Internal web apps</b><br><sub>SSO in front of any web UI<br>every request audited</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/15">Phase 12</a></sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="assets/icons/network.svg" height="48" alt="TCP services"><br><br><b>TCP services</b><br><sub>anything else, through a local port<br>same policy, same audit</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/15">Phase 12</a></sub><br><br></td>
  </tr>
</table>

Each target works with the managed AWS service **and** any compatible self-hosted server. ✅ working and tested, ⏳ planned (the link goes to its milestone). Everything is tested against local stand-ins. Nothing has been verified against real AWS, Okta, or Datadog yet.

## Who and what can log in

<table>
  <tr>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/okta" height="48" alt="Okta"><br><br><b>Okta</b><br><sub>OIDC login, groups to roles</sub><br><sub>✅ Tested with Dex<br>⚠️ not yet with Okta</sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/openid" height="48" alt="Any OIDC provider"><br><br><b>Any OIDC provider</b><br><sub>Keycloak, Entra ID, Auth0, Dex</sub><br><sub>✅ Working with Dex</sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="assets/icons/bot.svg" height="48" alt="Bots and automation"><br><br><b>Bots and automation</b><br><sub>CI jobs as audited principals<br>no long-lived secrets</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/6">Phase 4</a></sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/githubactions" height="48" alt="GitHub Actions"><br><br><b>GitHub Actions</b><br><sub>OIDC tokens become bot logins</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/6">Phase 4</a></sub><br><br></td>
  </tr>
  <tr>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/gitlab" height="48" alt="GitLab CI"><br><br><b>GitLab CI</b><br><sub>ID tokens become bot logins</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/6">Phase 4</a></sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="assets/icons/key-round.svg" height="48" alt="AWS IAM and Kubernetes"><br><br><b>AWS IAM and Kubernetes</b><br><sub>workload identity for bots</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/6">Phase 4</a></sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><picture><source media="(prefers-color-scheme: dark)" srcset="https://cdn.simpleicons.org/datadog/white"><img src="https://cdn.simpleicons.org/datadog" height="48" alt="Datadog"></picture><br><br><b>Datadog</b><br><sub>logs and monitors as Terraform</sub><br><sub>✅ Working (fake intake)</sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/grafana" height="48" alt="Grafana"><br><br><b>Grafana</b><br><sub>audit dashboards over S3 and Athena</sub><br><sub>✅ Working (Trino locally)</sub><br><br></td>
  </tr>
</table>

## Where it runs

<table>
  <tr>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/kubernetes" height="48" alt="Kubernetes"><br><br><b>Kubernetes</b><br><sub>StatefulSet or Deployment</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/7">Phase 5</a></sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="assets/icons/hard-drive.svg" height="48" alt="Amazon ECS and EC2"><br><br><b>Amazon ECS and EC2</b><br><sub>Fargate tasks or an Auto Scaling group</sub><br><sub>⏳ <a href="https://github.com/jfcmartins/limen/milestone/7">Phase 5</a></sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/terraform" height="48" alt="Terraform"><br><br><b>Terraform</b><br><sub>audit store and monitors today</sub><br><sub>✅ Working (audit module)</sub><br><br></td>
    <td align="center" valign="top" width="25%"><br><img src="https://cdn.simpleicons.org/docker" height="48" alt="Docker Compose"><br><br><b>Docker Compose</b><br><sub>the full local stack</sub><br><sub>✅ Working</sub><br><br></td>
  </tr>
</table>

## Roadmap

The roadmap lives in [GitHub milestones](https://github.com/jfcmartins/limen/milestones): one per phase, with the checklist in its epic issue and the exit criteria in its description. [`docs/design.md`](docs/design.md#13-phases-and-exit-criteria) holds the technical definition of "done" ([ADR-0023](docs/adr/0023-roadmap-in-github.md)).

| Phase | What | Status |
|---|---|---|
| 0 – 3.5 | Foundations, control plane, SSH, audit pipeline, web console | ✅ Done: [0](https://github.com/jfcmartins/limen/milestone/1), [1](https://github.com/jfcmartins/limen/milestone/2), [2](https://github.com/jfcmartins/limen/milestone/3), [3](https://github.com/jfcmartins/limen/milestone/4), [3.5](https://github.com/jfcmartins/limen/milestone/5) |
| 4 | Machine identities (bots) | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/6) |
| 5 | Scale-out: many control planes, proxies, workers | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/7) |
| Docs | Documentation site and homepage | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/8) |
| 6 | PostgreSQL, MySQL, Aurora, Redshift | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/9) |
| 7 | Redis and Valkey | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/10) |
| 8 | Kubernetes (EKS) | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/11) |
| 9 | MongoDB, Atlas, DocumentDB | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/12) |
| 10 | OpenSearch and Elasticsearch | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/13) |
| 11 | RabbitMQ and Kafka | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/14) |
| 12 | Internal web apps and TCP services | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/15) |
| 13 | Hardening and production readiness | ⏳ [milestone](https://github.com/jfcmartins/limen/milestone/16) |

## Why "Limen"
Limen is Latin for "threshold", the root of the English word *liminal*. A threshold is the point you cross once you are allowed in. That is what Limen does: you prove who you are through your identity provider, Limen lets you across into infrastructure for a short, audited window, and then closes the door behind you.

The name is short enough to type as a command (`limen login`, `limen ssh`). Both "LIE-men" and "LEE-men" are in common use.

## Documentation
- [Design](docs/design.md): architecture, data paths, failure semantics
- [ADRs](docs/adr/README.md): key decisions and their trade-offs
- [Threat model](docs/threat-model.md)
- [Policy reference](docs/policy.md)
- [Runbooks](docs/runbooks/README.md)
- A public documentation site and homepage are planned ([ADR-0021](docs/adr/0021-docs-site-and-homepage.md))

## Repository layout
| Path | Contents |
|---|---|
| `crates/` | Rust workspace: `limen-control-plane`, `limen-proxy`, `limen-worker`, `limen-cli` (binary `limen`), and the libraries they share |
| `proto/` | Protobuf definitions for the control plane API and the worker tunnel |
| `deploy/` | Dockerfiles, docker-compose dev stack, Terraform (audit store, Datadog monitors) |
| `dashboards/` | Grafana dashboards and alert rules, generated for Athena and Trino |
| `docs/` | Design, ADRs, threat model, runbooks |

## Development
Tools are pinned in `mise.toml`: Rust, protoc, cargo-deny, cargo-audit, actionlint, Terraform.

```sh
mise install
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check && cargo audit

# Integration tests need PostgreSQL, a KMS emulator, and an S3-compatible store:
docker compose -f deploy/compose/docker-compose.yml up -d postgres kms s3
AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1 \
LIMEN_TEST_S3_ENDPOINT=http://localhost:8333 \
LIMEN_TEST_DATABASE_URL=postgres://limen:limen-dev-only@localhost:5432/limen \
LIMEN_TEST_KMS_ENDPOINT=http://localhost:8099 cargo test --workspace --all-features
```

The local dev stack needs a Docker-compatible runtime. OrbStack is recommended on macOS. To put the CLI on your PATH: `cargo install --locked --path crates/limen-cli`. Contributions: see [CONTRIBUTING.md](CONTRIBUTING.md).

## License
[Apache-2.0](LICENSE). Icons are from [Simple Icons](https://simpleicons.org) (CC0) and [Lucide](https://lucide.dev) (ISC). Product names and logos belong to their owners and appear here only to say what Limen works with.
