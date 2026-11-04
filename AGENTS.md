# Limen: instructions for coding agents

Self-hosted, Rust, identity-aware access (SSH today; databases planned). Read `docs/design.md` §13 (phases) and `docs/adr/` (decisions) before changing behavior.

## Workflow
1. **Orient.** Check `docs/design.md` §13 for phase status (✅ = done) and the relevant ADRs. Several phases are already implemented.
2. **Isolate.** Work in a git worktree: `git worktree add .claude/worktrees/<topic> -b <branch>`. Make all edits, builds, and commits there. Never edit the main checkout or switch its branch.
3. **Plan, then build.** For anything beyond a small fix, state the plan first. Prefer the smallest change that solves the problem; match surrounding code and conventions.
4. **Verify.** Run the checks in [Commands](#commands) that apply to what you touched. Run it before saying it works.
5. **Report.** Say what you ran and what passed or failed, with output for failures. Anything tested only against a local stand-in is labelled `unverified`. Say what you did not verify.

## Rules
- **Phase by phase.** Only work on a phase the owner has approved; don't build ahead, even partially (planned integrations are data-only stubs). Each phase ships tests, docs, and a demo (`demos/demo-*.sh`).
- **Security invariants.** Secrets stay out of logs: use `limen_core::secret::Secret`. mTLS everywhere; no long-lived user credentials. Audit fails closed. Never weaken one of these to make a test or demo pass.
- **Image versions.** Container images are pinned only in `deploy/compose/.env`; edit it and run `scripts/check-versions.sh` (CI runs it). Tool versions are in `mise.toml`.
- **Dependencies and entry points.** New dependency: add a row to ADR-0012 after checking maintenance and advisories. New entry point or data store: update `docs/threat-model.md`.
- **Docs travel with code.** Behavior changes update the relevant docs and ADRs in the same PR. A decision that changes an ADR gets a new or amended ADR, not a silent edit.
- **Certificates.** Don't bypass browser warnings or touch trust stores. Dev CA: `deploy/compose/.state/internal-ca.pem` (use `curl --cacert`).
- **Ask before the irreversible.** Confirm first for anything destructive or outward-facing: force-push, deleting branches or data, pushing, tagging, marking a PR ready, posting comments. Look at the target before deleting or overwriting.

## Git and pull requests
- **Commits.** Conventional, small, focused. Stage specific files, never `git add -A`. Don't push or tag unless asked.
- **Pull requests.** Always open them as drafts (`gh pr create --draft`). CI doesn't run on a draft; it starts when the PR is marked ready for review.
  - Write the body from `.github/pull_request_template.md` (what and why, related, how it was verified, not verified, review guide, checklist, compatibility and rollback) and pass it with `--body-file`: `gh pr create --draft` without a body does not fill it in.
  - Don't push and mark a PR ready at the same moment: the two runs share a concurrency group and the later one cancels the earlier, which can leave the real run cancelled. Push, let its (skipped) run settle, then mark ready.

## Subagents
Use subagents when they save time or keep the main context clean; don't use them to avoid thinking.

**Good uses**
- Broad searches or codebase exploration where only the conclusion matters (`Explore`).
- Independent, well-scoped tasks with a short result: a separate crate, a doc pass, a test-writing task.
- A fresh-eyes review of a finished diff.
- Long-running verification (full test suite, demos) that can run while you continue.

**Don't**
- Spawn for simple tasks, small changes, or work that needs the context you already hold.
- Spawn to summarize or re-read work already in context, or to investigate a problem someone is already investigating.
- Spawn from a subagent.

**How**
- Parallel subagents are fine when their tasks share no state: different crates or files, no shared database, ports, or compose stack. Tasks that touch the same files, migrations, or the dev stack run one at a time. Keep it to a handful (about 3) at once.
- Give each a self-contained brief: goal, relevant paths, constraints from this file, what to return. Tell it which worktree to use; parallel writers each get their own worktree.
- Subagents obey every rule here. They don't push, tag, open PRs, or touch the main checkout unless the brief says so.
- Treat their reports as claims, not facts: check the diff and re-run the key verification before relying on them.
- Review each diff once, with one reviewer.

## Commands
```sh
cargo fmt && cargo clippy --workspace --all-targets --all-features --locked -- -D warnings   # pedantic lints, must be clean
# integration tests (need the compose services: postgres kms s3):
AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1 LIMEN_TEST_S3_ENDPOINT=http://localhost:8333 \
LIMEN_TEST_DATABASE_URL=postgres://limen:limen-dev-only@localhost:5432/limen LIMEN_TEST_KMS_ENDPOINT=http://localhost:8099 \
cargo test --workspace --all-features --locked          # without the env vars, integration tests print SKIPPED
cargo deny --locked check && cargo audit; mise exec -- actionlint; mise exec -- gitleaks git --redact --no-banner .   # secret scan; a new finding fails CI
(cd proto && mise exec -- buf lint && mise exec -- buf breaking --against "$(git rev-parse --git-common-dir)#ref=origin/main,subdir=proto")   # management API contract (ADR-0042)
demos/demo-phase35.sh --keep                   # full-stack check (also demo-phase2/3.sh)
```
Tools are pinned in `mise.toml` (`mise exec -- <tool>`). Docker runtime is OrbStack.

Which checks to run: always fmt and clippy; tests for crates you changed (integration tests when the compose services are up, and note `SKIPPED` output is not a pass); `cargo deny`/`audit` when dependencies change; `buf` when `proto/` changes; gitleaks and actionlint before a PR; a demo for phase work.

## Layout
- Binaries: `crates/limen-{control-plane,proxy,worker,cli}`.
- Libraries: `limen-{core,ca,policy,session,audit,tunnel,proto,component,kube}`; tests in `limen-testkit` and `limen-e2e`.
- Dev stack: `deploy/compose/` (`setup.sh` starts it; `stacks/`, `config/`, `scripts/`; see its README). Demos: `demos/`.
- Console: `crates/limen-control-plane/src/console/` (`templates/`, `assets/`). Terraform: `deploy/terraform`.
- Generated dashboards: `python3 deploy/grafana/generate.py`.
- Dev users: only in `deploy/compose/config/dev-users.toml`; regenerate with `python3 deploy/compose/scripts/gen-dev-users.py`. Tests use `limen_testkit::users`.

## Gotchas
- sqlx needs literal SQL: build shared fragments with `macro_rules!` + `concat!`, never `format!`.
- Askama templates are compiled in: rebuild after editing. Static assets are fingerprinted; reference them with `?v={{ chrome.assets }}`.
- Console CSP forbids inline script and third-party origins. Use external files and classes; don't loosen it without an ADR note.
- On macOS, don't use `timeout` or `sleep`-polling in shell. Run long commands in the background.
