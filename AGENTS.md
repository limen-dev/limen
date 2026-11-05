# Limen: instructions for coding agents

Self-hosted, Rust, identity-aware access (SSH today; databases planned). Before changing behavior read `docs/design.md` §13 (phase status, ✅ = done; several are implemented) and the relevant `docs/adr/`.

## Rules
- **Worktree only.** `git worktree add .claude/worktrees/<topic> -b <branch>`; edit, build and commit there. Never edit the main checkout or switch its branch.
- **Phase by phase.** Work only on phases the owner approved; don't build ahead (planned integrations are data-only stubs). A phase ships tests, docs and a demo (`demos/demo-*.sh`).
- **Verify before claiming.** Run it, then report what ran and what you didn't verify. Anything tested only against a local stand-in is `unverified`. `SKIPPED` integration tests are not a pass.
- **Security invariants.** Secrets via `limen_core::secret::Secret`, never logged. mTLS everywhere; no long-lived user credentials; audit fails closed. Never weaken these to make a test pass.
- **Dependencies.** New dependency: add a row to ADR-0012 after checking maintenance and advisories. New entry point or data store: update `docs/threat-model.md`.
- **Versions.** Container images are pinned only in `deploy/compose/.env` (then run `scripts/check-versions.sh`); tools in `mise.toml`.
- **Docs travel with code.** Behavior changes update docs/ADRs in the same PR.
- **Certificates.** Don't bypass browser warnings or touch trust stores. Dev CA: `deploy/compose/.state/internal-ca.pem` (`curl --cacert`).
- **Confirm before irreversible or outward-facing actions** (force-push, deleting data or branches, tagging, marking ready, commenting). Look at the target before deleting or overwriting.

## Git and PRs
- Conventional, small, focused commits. Stage specific files, never `git add -A`. Don't push or tag unless asked.
- Open PRs as drafts: `gh pr create --draft --body-file <file>`, body from `.github/pull_request_template.md` (it is not auto-filled). CI runs only once the PR is marked ready.
- Don't push and mark ready at the same moment: the two runs share a concurrency group and the later cancels the earlier. Push, let the skipped run settle, then mark ready.

## Subagents
Spawn them freely when they help; use judgment, not a quota.
- **Use for:** broad searches (`Explore`), independent tasks (a crate, a doc pass, writing tests), a fresh-eyes diff review, long test or demo runs while you continue.
- **Parallel is fine** when tasks share no state (files, migrations, ports, compose stack); otherwise run them one after another. Each parallel writer gets its own worktree.
- **Brief them fully:** goal, paths, constraints from this file, what to return. They follow every rule here and don't push, tag or open PRs unless told.
- **Verify their output:** reports are claims; check the diff and re-run key checks.
- **Avoid:** spawning for small changes, to re-read context you already hold, or to repeat an investigation. Subagents don't spawn subagents. One review per diff.

## Commands
```sh
cargo fmt && cargo clippy --workspace --all-targets --all-features --locked -- -D warnings   # pedantic lints, must be clean
# integration tests (need compose services: postgres kms s3):
AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1 LIMEN_TEST_S3_ENDPOINT=http://localhost:8333 \
LIMEN_TEST_DATABASE_URL=postgres://limen:limen-dev-only@localhost:5432/limen LIMEN_TEST_KMS_ENDPOINT=http://localhost:8099 \
cargo test --workspace --all-features --locked
cargo deny --locked check && cargo audit; mise exec -- actionlint; mise exec -- gitleaks git --redact --no-banner .   # a new gitleaks finding fails CI
(cd proto && mise exec -- buf lint && mise exec -- buf breaking --against "$(git rev-parse --git-common-dir)#ref=origin/main,subdir=proto")   # ADR-0042
demos/demo-phase35.sh --keep                   # full-stack check (also demo-phase2/3.sh)
```
Always run fmt + clippy and the tests of crates you touched. Add `deny`/`audit` for dependency changes, `buf` for `proto/`, gitleaks + actionlint before a PR, a demo for phase work. Tools: `mise exec -- <tool>`. Docker runtime: OrbStack.

## Layout
- Binaries: `crates/limen-{control-plane,proxy,worker,cli}`. Libraries: `limen-{core,ca,policy,session,audit,tunnel,proto,component,kube}`. Tests: `limen-testkit`, `limen-e2e`.
- Dev stack: `deploy/compose/` (`setup.sh`; see its README). Demos: `demos/`. Terraform: `deploy/terraform`.
- Console: Rust in `crates/limen-control-plane/src/console/`; Askama `templates/` and static `assets/` (css, js, icons.svg) sit beside `src/` in the same crate.
- Dashboards: `python3 deploy/grafana/generate.py`.
- Dev users: only in `deploy/compose/config/dev-users.toml`; regenerate with `python3 deploy/compose/scripts/gen-dev-users.py`. Tests use `limen_testkit::users`.

## Gotchas
- sqlx needs literal SQL: build shared fragments with `macro_rules!` + `concat!`, never `format!`.
- Askama templates are compiled in: rebuild after editing. Reference static assets with `?v={{ chrome.assets }}` (fingerprinted).
- Console CSP forbids inline script and third-party origins: use external files and classes (`style-src-attr 'unsafe-inline'` is allowed, scripts never). The policy is `CSP` in `console/mod.rs`; don't loosen it without an ADR note.
- macOS: no `timeout` or `sleep`-polling in shell; run long commands in the background.
