# Limen

Limen is a self-hosted, open-source platform for identity-aware access to infrastructure. Engineers log in through their identity provider and get short-lived, audited access to SSH hosts, RDS and Aurora (PostgreSQL and MySQL), ElastiCache Redis, and EKS. There are no static SSH keys, shared database passwords, or hand-made users.

> **Status: Phase 0 (design).** No component works end to end yet. See the [roadmap](docs/design.md#13-phases-and-exit-criteria).

## Documentation
- [Design](docs/design.md): architecture, data paths, failure semantics
- [ADRs](docs/adr/README.md): key decisions and their trade-offs
- [Threat model](docs/threat-model.md)
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
```

The local dev stack (Phase 1 onward) needs a Docker-compatible runtime. OrbStack is recommended on macOS.

## License
[Apache-2.0](LICENSE)
