# Contributing

## Repository layout
| Path | Contents |
|---|---|
| `crates/` | Rust workspace: `limen-control-plane`, `limen-proxy`, `limen-worker`, `limen-cli` (binary `limen`), and the libraries they share |
| `proto/` | Protobuf definitions for the control plane API and the worker tunnel |
| `deploy/` | Dockerfiles, docker-compose dev stack, Terraform (audit store, Datadog monitors) |
| `dashboards/` | Grafana dashboards and alert rules, generated for Athena and Trino |
| `docs/` | Design, ADRs, threat model, runbooks |


## Building and testing
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

The local dev stack needs a Docker-compatible runtime. OrbStack is recommended on macOS. To put the CLI on your PATH, run `scripts/install-cli.sh` (installs `limen` to `~/.local/bin`; re-run it after pulling to upgrade). Contributions: see [CONTRIBUTING.md](CONTRIBUTING.md).


## Commits
Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `chore:`, `ci:`, `test:`, `refactor:`, `perf:`, `build:`. Add a scope where it helps, for example `feat(proxy): ...`. Keep each commit small, with one logical change.

## Planning and pull requests
The roadmap is GitHub milestones (one per phase) with an epic issue holding each phase's checklist ([ADR-0023](docs/adr/0023-roadmap-in-github.md)). Open a pull request per change, put it in the phase's milestone, and write `Closes #N` (or `Part of #N` for the epic) so progress and release notes update themselves. Labels: `area: …` for the part of the system, `unverified` when something has only run against a local stand-in.

## Before opening a PR
```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
cargo audit
actionlint
```

## The CLI's look
All terminal output goes through `crates/limen-cli/src/ui.rs` (colour, glyphs, tables, spinner, errors). It prints plain text when piped or when `NO_COLOR` is set, and `--color always|never` overrides. Add new output there rather than with bare `println!`, and cover layout with a test that strips the colour.

## Rules
- A new dependency needs a row in [ADR-0012](docs/adr/0012-dependency-selection.md).
- A new entry point, credential type, or data store needs an update to the [threat model](docs/threat-model.md).
- A change to the audit event envelope must bump `limen_audit::SCHEMA_VERSION`.
- No `unsafe` (forbidden workspace-wide). Never put secrets in logs: wrap them in the secret newtype.
