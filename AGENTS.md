# Limen: instructions for coding agents

Self-hosted, Rust, identity-aware access (SSH today; databases planned). Read `docs/design.md` §13 (phases) and `docs/adr/` (decisions) before changing behavior.

## Rules
- **Work in a git worktree.** `git worktree add .claude/worktrees/<topic> -b <branch>`; make all edits, builds, and commits there. Never edit the main checkout or switch its branch.
- **Phase by phase.** Status is in `docs/design.md` §13 (✅ = done). Several phases are already implemented, so check there before any change. Only work on a phase the owner has approved; don't build ahead, even partially (planned integrations are data-only stubs). Each phase ships tests, docs, and a demo (`deploy/compose/demo-*.sh`).
- **Verify before claiming.** Run it before saying it works. Anything tested only against a local stand-in is labelled `unverified`.
- **Secrets stay out of logs.** Use `limen_core::secret::Secret`. mTLS everywhere; no long-lived user credentials. Audit fails closed.
- **Dependencies and entry points.** New dependency: add a row to ADR-0012 after checking maintenance and advisories. New entry point or data store: update `docs/threat-model.md`.
- **Commits.** Conventional, small, focused. Stage specific files, never `git add -A`. Don't push or tag unless asked.
- **Certificates.** Don't bypass browser warnings or touch trust stores. Dev CA: `deploy/compose/.state/internal-ca.pem` (use `curl --cacert`).

## Agent use (cost)
Overrides the delegation defaults of Superpowers `subagent-driven-development` and `dispatching-parallel-agents`. Keep their brainstorming, planning, and testing steps; skip the delegation.

- Do the work in the main conversation by default. Skip subagents for simple tasks and small changes.
- Spawn one only for a broad search where the conclusion is all you need, or an independent task with a short result. State in one line why the main conversation can't do it; if you can't, don't spawn.
- At most one subagent at a time, and only when tasks share no state. Never spawn from a subagent.
- Never spawn to summarize or re-read work already in context. Don't investigate the same problem twice.
- Review each diff once, with one reviewer at most.

Efficient token use and correct completion beat maximizing agent count.

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
- Binaries: `crates/limen-{control-plane,proxy,worker,cli}`.
- Libraries: `limen-{core,ca,policy,session,audit,tunnel,proto,component}`; tests in `limen-testkit` and `limen-e2e`.
- Console: `crates/limen-control-plane/src/console/` (`templates/`, `assets/`). Terraform: `deploy/terraform`.
- Generated dashboards: `python3 dashboards/grafana/generate.py`.
- Dev users: only in `deploy/compose/dev-users.toml`; regenerate with `python3 deploy/compose/gen-dev-users.py`. Tests use `limen_testkit::users`.

## Gotchas
- sqlx needs literal SQL: build shared fragments with `macro_rules!` + `concat!`, never `format!`.
- Askama templates are compiled in: rebuild after editing. Static assets are fingerprinted; reference them with `?v={{ chrome.assets }}`.
- Console CSP forbids inline script and third-party origins. Use external files and classes; don't loosen it without an ADR note.
- On macOS, don't use `timeout` or `sleep`-polling in shell. Run long commands in the background.
