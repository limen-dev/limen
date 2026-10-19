<!-- Open this PR as a draft (gh pr create --draft). CI starts when you mark it ready for review. -->

## What and why
<!-- What changes, and the reason, in a few sentences. -->

Related: <!-- Phase in docs/design.md section 13, ADR, or `Closes #123` -->

## How it was verified
<!-- What you ran and what it showed: commands, demo, tests. Anything tested only against a local stand-in is labelled `unverified`. -->

## Not verified
<!-- What you did not or could not run (real cloud services, other platforms). Write "nothing" if so. -->

## Review guide
<!-- Optional, for large changes: where to start, what moved versus what changed, what to look at hardest. -->

## Checklist
Tick each item that applies; write "n/a" after the ones that don't.
- [ ] Tests added or updated; `cargo fmt` and `cargo clippy ... -D warnings` clean
- [ ] Docs updated (guide, runbook, README, `docs/design.md` status)
- [ ] Phase work: demo in `demos/` added or still passing
- [ ] Secrets stay out of logs (`limen_core::secret::Secret`); mTLS and fail-closed audit intact
- [ ] New dependency: row added to ADR-0012 (maintenance and advisories checked)
- [ ] New entry point or data store: `docs/threat-model.md` updated
- [ ] Commits are conventional, small and focused

## Compatibility and rollback
<!-- Breaking changes, migrations, config or policy changes, and how to roll back. Write "none" if so. -->
