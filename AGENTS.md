# Limen: instructions for coding agents

Self-hosted, Rust, identity-aware access (SSH, databases, Kubernetes, web apps). Layout, build and test commands, commit style and the PR checklist are in `CONTRIBUTING.md`; crate roles in `docs/design.md` §12; phase status in §13; decisions in `docs/adr/`; demos in `demos/README.md`. This file holds only what is specific to agents.

## Rules
- **Worktree only.** `git worktree add .claude/worktrees/<topic> -b <branch>`; edit, build and commit there. Never edit the main checkout or switch its branch.
- **Approved work only.** Read `docs/design.md` §13 before changing behavior. Work on phases the owner approved; don't build ahead.
- **Verify before claiming.** Run it, and say what you ran and what you didn't. Anything tested only against a local stand-in is `unverified`. A `SKIPPED` test is not a pass.
- **Invariants** (full list in `CONTRIBUTING.md` Rules): secrets never logged (`limen_core::secret::Secret`), mTLS everywhere, audit fails closed, no `unsafe`. Never weaken one to make a test pass.
- **Certificates.** Don't bypass browser warnings or touch trust stores. Dev CA: `deploy/compose/.state/internal-ca.pem` (`curl --cacert`).
- **Ask before irreversible or outward-facing actions:** force-push, deleting data or branches, tagging, marking a PR ready, commenting. Look at the target before deleting or overwriting.

## Checks
Pick what fits the change; CI runs the rest.
- Always: `cargo fmt --all`, then `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`.
- Tests for the crates you touched. Integration tests need `postgres kms s3` from `deploy/compose` and the `LIMEN_TEST_*` variables in `CONTRIBUTING.md`.
- Generated files must be regenerated, not hand-edited: `scripts/gen-cli-reference.sh` (`docs/cli-reference.md`), `python3 deploy/grafana/generate.py`, `python3 deploy/compose/scripts/gen-dev-users.py` (dev users live only in `deploy/compose/config/dev-users.toml`).
- Per area: `cargo deny --locked check && cargo audit` for dependency changes; `cd proto && mise exec -- buf lint && mise exec -- buf format --diff --exit-code` and `buf breaking` for `proto/`; `scripts/check-versions.sh` after editing image pins in `deploy/compose/.env`; `mise exec -- actionlint` for workflows; `mise exec -- gitleaks git --redact --no-banner .` before a PR.
- Behavior or phase work: run the matching `demos/demo-*.sh` (headers say what each needs) and add or update one for new phases. Tools come from `mise.toml` via `mise exec -- <tool>`.

## Git and PRs
- Conventional, small, focused commits. Stage specific files, never `git add -A`. Don't push or tag unless asked.
- Open PRs as drafts: `gh pr create --draft --body-file <file>`, body from `.github/pull_request_template.md` (it is not auto-filled). CI runs only once the PR is marked ready.
- Don't push and mark ready at the same moment: the two runs share a concurrency group and the later cancels the earlier. Push, let the skipped run settle, then mark ready.

## Subagents
Use them when they save time or keep context clean (broad searches, independent tasks, a review of a finished diff). Give a self-contained brief; parallel writers get separate worktrees; check their output before relying on it. They follow these rules and don't push or open PRs unless told.
