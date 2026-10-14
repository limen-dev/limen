# Contributing

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

## Rules
- A new dependency needs a row in [ADR-0012](docs/adr/0012-dependency-selection.md).
- A new entry point, credential type, or data store needs an update to the [threat model](docs/threat-model.md).
- A change to the audit event envelope must bump `limen_audit::SCHEMA_VERSION`.
- No `unsafe` (forbidden workspace-wide). Never put secrets in logs: wrap them in the secret newtype.
