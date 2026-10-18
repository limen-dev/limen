<!-- Open this PR as a draft (gh pr create --draft). CI starts when you mark it ready for review. -->

## What and why
<!-- What changes, and the reason. Link the phase in docs/design.md section 13, the ADR, or the issue. -->

## How it was verified
<!-- What you ran and what it showed (commands, demo, tests). Anything tested only against a local stand-in is labelled `unverified`. -->

## Not verified
<!-- What you did not run or cannot run here (real cloud services, other platforms). Write "nothing" if so. -->

## Checklist
- [ ] Tests added or updated, and `cargo fmt` + `cargo clippy ... -D warnings` are clean (see AGENTS.md)
- [ ] Docs updated (guide, runbook, README, `docs/design.md` status)
- [ ] Demo added or still passing (`demos/`) for phase work
- [ ] No secrets in logs (`limen_core::secret::Secret`); mTLS and fail-closed audit intact
- [ ] New dependency: row added to ADR-0012 (maintenance and advisories checked)
- [ ] New entry point or data store: `docs/threat-model.md` updated
- [ ] Commits are conventional, small and focused

## Compatibility
<!-- Breaking changes, migrations, config or policy changes, and how to roll back. Write "none" if so. -->
