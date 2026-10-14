# ADR-0029: Access reviews and compliance evidence

- Status: Proposed (owner requested 2026-10-14; priority: **should have**)
- Date: 2026-10-14

## Context
Auditors ask the same questions every year: who had access to what, who approved it, and did anyone check? Limen already holds the answers (policy, mappings, grants, signed and hash-chained audit). Collecting them should be a button, not a project.

## Decision
- **Access reviews.** `limen admin review start` (or a schedule, default quarterly) takes a **snapshot of effective access**: who can reach what, through which role or grant (from ADR-0028's engine and the `users` table). Items are assigned to **reviewers** (the owner of a resource, by an `owner` label, or the owners of a role). Each reviewer *certifies* or *flags for removal* in the console, with a comment. Reviewers can't review their own access. Open reviews send reminders and escalate.
- **Acting on a flag.** Limen can't edit IdP groups. A flagged item creates a **deny override** (`access_denies`, carried in the signed snapshot like locks) for that user and role, and a task for whoever owns the IdP group. Overrides are listed, audited, and expire when the IdP change is confirmed or after a set time.
- **Evidence packs.** `limen admin evidence --from --to` produces a signed archive: the review results, sessions, approvals and grants (ADR-0025), locks, kills, revokes and policy changes for the period, plus a manifest of SHA-256 hashes anchored in the audit chain (`evidence.export` event). `limen-audit-verify` learns to verify a pack offline, so an auditor needs no access to Limen.
- **Control mapping.** The docs map evidence to common controls (for example SOC 2 CC6 and ISO 27001 access-control clauses) as **guidance, not certification**; wording is reviewed before it is published.
- **Console:** reviews list, a reviewer's task view, and an evidence page. Dashboard panel: review completion and overdue items.

## Threats this design has to survive
- **Rubber-stamping:** the reviewer view shows last use (sessions in 90 days), unused access is highlighted, and the dashboard shows the certify-without-comment rate.
- **Evidence that can be quietly edited:** packs are signed and anchored in the audit chain, and verify offline.
- **Reviewer conflicts:** self-review is refused; owners come from labels in policy, which is Git-reviewed.
- **Overrides outliving their purpose:** every override has an expiry and appears in the next review.

## Consequences
- A third mechanism (deny overrides) joins locks and grants in the snapshot; the "lock wins" rule extends to it.
- Open questions to settle when the phase starts: how owners are resolved for discovered resources (ADR-0027), and whether an evidence PDF is worth building next to the signed JSON and CSV.
