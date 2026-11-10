# ADR-0050: Policy suggest: right-size roles from real usage

- Status: Accepted (issue #114; the owner asked on 2026-11-10 for it to be built end to end). Everything below that answers an open question from the issue is a default for review.
- Date: 2026-11-10

## Context
Roles only grow: adding access is easy and nobody removes it. Unused access widens the blast radius of a stolen credential and is a standing audit finding. Limen sees every session, so it knows what was actually used. ADR-0029 puts last use in front of a *reviewer*, but nothing writes the fix. `limen policy suggest` does: it reads the session history and proposes a **tighter** policy.

## Decision
- **It only tightens, and it never applies anything.** The output is a YAML file containing the changed role documents, a text report, and the proof (`limen policy diff active --new <file>`) that the result only loses access. It builds nothing but removals: an allow rule, or one entry from a rule's list of logins, database roles, users or Mongo roles. It never adds, widens, renames or touches a deny rule. A property test checks that for random policies and usage, the effective-access diff (ADR-0028) of active versus suggested shows no gained access.
- **What a suggestion is.** Two kinds, both on *standing* `allow` rules:
  1. **Unused rule:** nothing matching the rule was used in the window. Suggestion: remove the rule.
  2. **Unused principal:** the rule was used, but one login, database role, Redis user, Mongo role, RabbitMQ user or Kafka user it lists was not. Suggestion: remove that entry, only when at least one entry remains.
  A role whose every allow rule is unused cannot be written back, because a role needs at least one rule (`validate_role`). It is reported as **unused role**: remove the role and its group mappings together. Narrowing selectors (labels, names) and database lists is not built: it needs more than "was it used".
- **Usage source.** The `sessions` table that the console already fills from `session.start` and `session.end` events: user, resource, principal, and the time of the last activity (end, or start if it has not ended). Only aggregates reach the rule matcher; statement text, commands and recordings are never read.
- **Attribution: a session counts as use of every rule that could have allowed it.** A session records the resource and principal, not which role authorized it. So a session by anyone, on resource R as principal P, counts as use of every standing allow rule in every role whose selector matches R and which grants P. This over-counts when two roles overlap, and over-counting can only hide a suggestion, never create a wrong one. Wrongly removing the rule that was actually used is the failure this rule exists to prevent.
- **What can be assessed.** SSH, PostgreSQL, MySQL and Redshift, Redis, MongoDB, RabbitMQ, Kafka and raw TCP. Kubernetes, search and web-app rules record their use per request, not per session with a principal, so they are **not assessed**: they stay untouched and the report lists them. A rule whose `resources` selector matches a kind that is not assessed is left alone too.
- **Window and coverage.** Default 90 days, the same as ADR-0029; `--window-days` accepts 7 to 365 (a quarterly job needs 120 or more). The command **refuses** when Limen has not been watching long enough: the oldest first login must be at least a window old. The error says the longest window it could honour. This is the answer to short history: no answer is given, rather than a wrong one. `sessions` is never pruned today; if retention is ever added, this check must read the retention bound (a comment at the query says so).
- **Too new to judge.** A rule is never suggested for removal if its role document changed inside the window (`policy_document_heads.updated_at`), or if it matches a resource document created inside the window: that access has not had a full window to be used. A document with no recorded age is treated as new, so not knowing never makes something look old (it costs a suggestion, never a wrong one).
- **Rare-but-critical access.** Break-glass roles, requestable roles (used only through grants), and shadow roles are never suggested. A role can opt out with the label `suggest: keep`. A label is used on purpose: a new policy field would make every component from before this change refuse the policy (see the version-skew note in ADR-0046), and labels already exist on roles. A longer window covers the rest.
- **"Which roles a user needs" is a report, not YAML.** Roles come from IdP groups, which Limen cannot edit (ADR-0029). The report lists, per person, the standing roles whose rules none of their own sessions in the window matched. Those are the people to ask, or to remove from an IdP group.
- **Where it runs.** Online only, on the control plane, against the active policy: `limen policy suggest`. The library (`limen_policy::suggest`) is pure: policy, usage rows and a clock go in, suggestions come out. The control plane gathers the rows and stamps the result with the policy version and digest. Offline use is not offered, because the history is in the database.
- **Access.** `limen:admin` only, the same as the other policy reads. Bots, including writer bots, are refused. It exposes who used what, so every call writes a `policy.suggest` audit event (caller, window, policy version, counts, no names) **before** returning. If audit is unavailable the call fails, like an evidence export.
- **Output format (decided).** A YAML file plus a diff, from the CLI. No pull request is opened by Limen: that would need a Git credential in Limen. The file starts with a header comment naming the policy version it was made from, and the intended path is: copy the roles into the policy repository, run `policy diff active --new` and `policy test`, and open the pull request as for any change.

## Threats this design has to survive
- **A suggestion that breaks someone's access:** attribution over-counts, short history is refused, new rules and resources are exempt, the opt-out label exists, and the output is a proposal that goes through `policy test`, `policy diff` and review.
- **A suggestion that opens access:** removals only, and the property test above.
- **A stale suggestion:** it is stamped with the policy version and digest; applying it over a newer policy is the reviewer's diff, not a silent write.
- **Disclosure of usage:** admin only, audited, aggregates only; the YAML contains no user names; the per-person report appears in the text and JSON output for the admin who asked.
- **Cost:** one aggregate query over the window (at most 365 days), grouped by person, resource and principal. If that yields more than 500,000 rows the call is refused rather than cut short, because an answer built from part of the history would be wrong.
- **Gaming the history:** someone can make a rule look used by opening a session with it. They can only do that with access they already hold, and the session is audited and recorded.

## Consequences
- A new gRPC call on the admin service (`SuggestPolicy`), a new audit kind (`policy.suggest`), a new module in `limen-policy`, and a CLI command. The threat model gets a row for the new entry point.
- No schema change to policy documents and no migration.

## Open for review
- Whether labels (`suggest: keep`) are enough, or a per-rule marker is worth the version-skew cost later.
- Whether to read the audit trail in S3 or Athena for history beyond what `sessions` keeps, once retention exists.
- Narrowing selectors and database lists from `session.start` data.
- Kubernetes, search and web-app rules, which need per-request usage with a principal.
- Whether the console should show the report next to the access reviews.
