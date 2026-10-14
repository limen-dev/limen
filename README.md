<p align="center"><img src="assets/logo.svg" alt="Limen" width="320"></p>

# Limen

Limen is a self-hosted, open-source platform for identity-aware access to infrastructure. Engineers log in through their identity provider and get short-lived, audited access to SSH hosts, RDS and Aurora (PostgreSQL and MySQL), ElastiCache Redis, and EKS. There are no static SSH keys, shared database passwords, or hand-made users.

> **Status: Phase 2 complete.** OIDC login, policy, the control plane, proxies (with peering), workers, and SSH access with session recording work end to end. Databases, Redis, and Kubernetes arrive in Phases 4 to 6, and the audit pipeline to S3, Datadog, and Grafana in Phase 3. See the [roadmap](docs/design.md#13-phases-and-exit-criteria).

Try it locally: [`deploy/compose/README.md`](deploy/compose/README.md), or run `deploy/compose/demo-phase2.sh`.

## Why "Limen"
Limen is Latin for "threshold", the root of the English word *liminal*. A threshold is the point you cross once you are allowed in. That is what Limen does: you prove who you are through your identity provider, Limen lets you across into infrastructure for a short, audited window, and then closes the door behind you.

The name is short enough to type as a command (`limen login`, `limen ssh`). Both "LIE-men" and "LEE-men" are in common use.

## What it connects to

| | Service | Targets | How access works | Status |
|---|---|---|---|---|
| <img src="https://cdn.simpleicons.org/linux" alt="Linux" height="22"> | **SSH** | EC2 instances and any SSH host | Per-session OpenSSH certificates from a Limen CA, recorded sessions, `ssh.exec` audit. Use plain `ssh` through `limen ssh` | ✅ Phase 2, working |
| <img src="https://cdn.simpleicons.org/postgresql" alt="PostgreSQL" height="22"> | **PostgreSQL** | RDS PostgreSQL, Aurora PostgreSQL | RDS IAM auth tokens held by the worker, a local `psql` listener with no password, every statement audited | ⏳ Phase 4 |
| <img src="https://cdn.simpleicons.org/mysql" alt="MySQL" height="22"> | **MySQL** | RDS MySQL, Aurora MySQL | RDS IAM auth, a local `mysql` listener with no password, every statement audited | ⏳ Phase 4 |
| <img src="https://cdn.simpleicons.org/redis" alt="Redis" height="22"> | **Redis** | ElastiCache Redis (7.0+) and Valkey (7.2+) | ElastiCache IAM auth or worker-managed ACL users, a local `redis-cli` listener, every command audited with values redacted | ⏳ Phase 5 |
| <img src="https://cdn.simpleicons.org/kubernetes" alt="Kubernetes" height="22"> | **Kubernetes** | Amazon EKS | The worker impersonates the user with RBAC bound to role groups. `kubectl` works through a kubeconfig plugin. `exec` is recorded | ⏳ Phase 6 |

| | Integration | Notes | Status |
|---|---|---|---|
| <img src="https://cdn.simpleicons.org/okta" alt="Okta" height="22"> | **Okta** (OIDC) | Browser PKCE and device flow, Okta groups mapped to roles | Login works, tested against Dex. Not yet tested against a real Okta tenant |
| <img src="https://cdn.simpleicons.org/openid" alt="OpenID" height="22"> | **Any OIDC provider** | Dex and Keycloak work for local development | ✅ Working with Dex |
| <img src="https://cdn.simpleicons.org/datadog" alt="Datadog" height="22"> | **Datadog** | Logs, metrics, and traces, plus monitors as Terraform | ⏳ Phase 3 |
| <img src="https://cdn.simpleicons.org/grafana" alt="Grafana" height="22"> | **Grafana** | Audit dashboards over S3 with Athena | ⏳ Phase 3 |

✅ working and tested, ⏳ planned (see the [roadmap](docs/design.md#13-phases-and-exit-criteria)). Everything is tested against local stand-ins. Nothing has been verified against real AWS, Okta, or Datadog yet.

## Documentation
- [Design](docs/design.md): architecture, data paths, failure semantics
- [ADRs](docs/adr/README.md): key decisions and their trade-offs
- [Threat model](docs/threat-model.md)
- [Policy reference](docs/policy.md)
- [Runbooks](docs/runbooks/README.md)

## Repository layout
| Path | Contents |
|---|---|
| `crates/` | Rust workspace: `limen-control-plane`, `limen-proxy`, `limen-worker`, `limen-cli` (binary `limen`), and the libraries they share |
| `proto/` | Protobuf definitions for the control plane API and the worker tunnel |
| `deploy/` | Dockerfiles, docker-compose dev stack, Terraform (ECS, EC2, Datadog) |
| `dashboards/` | Grafana dashboards and alert rules, provisioned as code |
| `docs/` | Design, ADRs, threat model, runbooks |

## Development
Tools are pinned in `mise.toml`: Rust, protoc, cargo-deny, cargo-audit, actionlint.

```sh
mise install
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check && cargo audit

# Integration tests need PostgreSQL and a KMS emulator:
docker compose -f deploy/compose/docker-compose.yml up -d postgres kms
LIMEN_TEST_DATABASE_URL=postgres://limen:limen-dev-only@localhost:5432/limen \
LIMEN_TEST_KMS_ENDPOINT=http://localhost:8099 cargo test --workspace --all-features
```

The local dev stack needs a Docker-compatible runtime. OrbStack is recommended on macOS.

To put the CLI on your PATH: `cargo install --locked --path crates/limen-cli` (installs `limen` into `~/.cargo/bin`).

## License
[Apache-2.0](LICENSE)
