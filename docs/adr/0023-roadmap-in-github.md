# ADR-0023: The roadmap lives in GitHub milestones and labels

- Status: Accepted (owner approved the approach 2026-10-14)
- Date: 2026-10-14

## Context
Until now the roadmap was a table in `docs/design.md`. It records *exit criteria* well, but it is a file someone has to remember to edit, it shows no progress, and it can't be filtered or linked from a pull request.

## Decision
- **One GitHub milestone per phase**, titled `Phase N: <name>`, ordered by number. A milestone's description holds the goal and exit criteria. Its progress bar is the status.
- **One epic issue per phase** (label `epic`) holds the checklist of work items. Finished phases have a closed milestone and a closed epic that lists the commits that delivered it, so history is browsable from the same place as the plan.
- **Labels** have three families: `area: …` (what part of the system), `type: …` (feature, bug, docs, security, chore), and `needs: …` (design, real-service test). The label `unverified` marks anything that works against a local stand-in but has not been run against the real service, which is the project's honesty rule made visible.
- **Work is linked, not copied.** From now on changes go through pull requests that say `Closes #n`, so milestone progress updates itself and release notes (generated, grouped by label through `.github/release.yml`) write themselves.
- **A GitHub Project** ("Limen roadmap") sits on top as the board: it holds the epics (and later the work items), with Status (Todo, In Progress, Done) and the built-in Milestone and Label fields. Milestones own scope and progress; the Project is only the view. Board and Roadmap views are added in the GitHub UI, because the CLI can't create views.
- `docs/design.md` keeps the *why*: architecture, ADRs, and the exit criteria. It no longer tracks status. The README's roadmap section is a table that links to the milestones.
- Releases: pre-1.0 versions are cut at phase boundaries (`v0.N.0`), tagged on the commit that closes a milestone.

## Consequences
- Commits are not assigned to milestones (GitHub only assigns issues and pull requests), so a commit reaches a milestone through its issue or pull request. Direct pushes to `main` don't show up in a milestone; use pull requests.
- The milestones are in a private repository today, so they are visible to collaborators only until the repository is public.
