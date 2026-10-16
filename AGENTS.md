# Limen: instructions for coding agents

Self-hosted, Rust, identity-aware access (SSH today; databases and more planned). Read `docs/design.md` §13 for phases and `docs/adr/` for decisions before changing behavior.

## Rules
- **Always work in a git worktree.** Create one for every task under `.claude/worktrees/` in the repo (e.g. `git worktree add .claude/worktrees/<topic> -b <branch>`) and make all edits, builds, and commits there. Never edit files directly in the main checkout (the repo root), and don't switch its branch.
- **Work phase by phase.** Roadmap = GitHub milestones. Don't start a phase the owner hasn't approved. Every phase ships tests, docs, and a runnable demo (`deploy/compose/demo-*.sh`).
- **Never claim something works unless you ran it.** Anything only tested against a local stand-in is "unverified against real service" (label `unverified`).
- **Secrets never appear in logs.** Use `limen_core::secret::Secret`. mTLS everywhere; no long-lived user credentials. Audit fails closed.
- New dependency: add a row to ADR-0012 and check maintenance/advisories first. New entry point or data store: update `docs/threat-model.md`.
- Conventional commits, small and focused. Stage specific files (never `git add -A` over someone else's edits). Don't push or tag without being asked.
- Don't bypass browser certificate warnings or touch trust stores; dev CA is `deploy/compose/.state/internal-ca.pem` (use `curl --cacert`).

## Agent use (cost)

When using Superpowers workflows, minimize unnecessary subagent usage. This policy overrides the delegation defaults of `subagent-driven-development` and `dispatching-parallel-agents`; keep their brainstorming, planning, and testing steps, and skip the delegation.

- Prefer completing tasks directly in the main conversation.
- Do not spawn subagents for simple tasks, small bug fixes, or small code changes.
- Spawn a subagent only for a broad search across many files where the conclusion is all you need, or for an independent task that returns a short result.
- Do not launch multiple agents to investigate the same problem.
- Avoid parallel agents unless the tasks are genuinely independent and parallel execution gives a clear benefit.
- Run at most one subagent at a time, and only when the tasks share no state.
- Never spawn subagents to summarize or re-read work already in context.
- Never spawn additional subagents from a subagent.
- For routine implementation, use one main agent and work through the task sequentially.
- For complex tasks, delegate only when the benefit justifies the extra token cost, and never to more than one subagent.
- Avoid repeated code reviews or duplicate codebase exploration. Review each diff once; don't run several reviewers over the same change.
- Before spawning, state in one line why the main conversation can't do the task. If you can't, don't spawn.
- Preserve essential Superpowers workflows (brainstorming, planning, testing) without unnecessary agent delegation.

Prioritize efficient token usage and correct completion over maximizing the number of agents.

## Commands
```sh
cargo fmt && cargo clippy --workspace --all-targets --all-features --locked -- -D warnings   # pedantic lints, must be clean
# integration tests (need the compose services: postgres kms s3):
AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1 LIMEN_TEST_S3_ENDPOINT=http://localhost:8333 \
LIMEN_TEST_DATABASE_URL=postgres://limen:limen-dev-only@localhost:5432/limen LIMEN_TEST_KMS_ENDPOINT=http://localhost:8099 \
cargo test --workspace --all-features --locked          # without the env vars, integration tests print SKIPPED
cargo deny --locked check && cargo audit; mise exec -- actionlint
deploy/compose/demo-phase35.sh --keep                   # full-stack check (also demo-phase2/3.sh)
```
Tools are pinned in `mise.toml` (`mise exec -- <tool>`). Docker runtime is OrbStack.

## Layout
`crates/limen-{control-plane,proxy,worker,cli}` binaries; `limen-{core,ca,policy,session,audit,tunnel,proto,component}` libraries; `limen-testkit` and `limen-e2e` for tests. Console: `crates/limen-control-plane/src/console/` (+ `templates/`, `assets/`). Terraform in `deploy/terraform`. Dashboards are generated: `python3 dashboards/grafana/generate.py`. Dev users live only in `deploy/compose/dev-users.toml` (run `python3 deploy/compose/gen-dev-users.py` after editing); tests use `limen_testkit::users`.

## Gotchas
- sqlx wants literal SQL: build shared fragments with `macro_rules!` + `concat!`, never `format!`.
- Console templates are compiled in (askama): rebuild after editing them. Static assets are fingerprinted; reference them with `?v={{ chrome.assets }}`.
- Console CSP forbids inline script and third-party origins; use external files and classes. Don't loosen it without an ADR note.
- Don't use `timeout` or `sleep`-polling in shell on macOS; run long commands in the background.
