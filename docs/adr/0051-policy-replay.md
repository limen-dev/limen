# ADR-0051: Replay recorded sessions against a policy change

- Status: Accepted (issue #115, epic #117; the owner approved it on 2026-11-09). Labels are reconstructed from the current policy (option A) by the owner's decision; everything else is a default for review.
- Date: 2026-11-09

## Context
ADR-0028's `policy diff` compares *effective access* for hypothetical people, and ADR-0046's shadow mode watches live traffic after a rule ships. Neither answers the question a reviewer asks before a tightening lands: "who actually used the access this removes?" The nightly bot, the engineer who connects once a week and the migration job are invisible in the YAML and obvious in last month's sessions.

The issue (#115) assumed events carry the policy digest and labels of the time. They do not. `session.start` holds the user, resource, kind, upstream login or role, database, worker and proxy; it holds **no roles, groups, labels or policy version**. So the replay reconstructs the request from what is recorded and from current state, and says plainly what it could not reconstruct.

## Decision
- **Compare two policies, not one policy against "it happened".** Each recorded session is turned into an access request and evaluated under the active policy and under the proposed one, with identical inputs. A session is reported as **affected** only when the active policy allows it and the proposed one does not (denied, or only available by request). Everything else is counted, not listed. Records the active policy already refuses are put in their own bucket (`already_refused`): they mean the reconstruction differs from what happened (a role since removed, a group since changed), not that this change hurts anyone. Without this split every approximation would read as "would have denied". Replaying the active policy against itself reports zero affected sessions, and a test pins it.
- **One engine.** `limen-policy` gains a pure function, `Policy::replay`, that takes plain records and calls `evaluate_eligible` (the ADR-0028 function that wraps the enforcement path's `evaluate`) for both policies. A property test requires each record's outcome to equal `evaluate_eligible` for the same request. No second decision implementation.
- **What is replayed.** Rows of the control plane's `sessions` projection (a copy of `session.start`) in the window, grouped by (user, kind, resource, upstream principal, database, access-request ids). Supported: SSH, PostgreSQL, MySQL, Redshift, MongoDB, Redis, OpenSearch and Elasticsearch, RabbitMQ, Kafka, web and TCP. **Not replayed** (counted under `skipped` with the reason, never silently dropped): Kubernetes (the worker's per-group check has no recorded principal), per-request checks inside a session (`deny_commands`, web path rules), sessions whose database was not recorded (before migration 0030), and people the control plane no longer knows.
- **Reconstructing the roles** (the part the owner did not decide; a default for review). The roles are assembled by the same functions as at login and in the proxy:
  - *People:* the groups from their latest login (`users.groups`), through each policy's `roles_for_groups`, with the deployment's bootstrap admin groups. Groups that changed since the session make this approximate.
  - *Bots:* the bot document's `roles` in each policy. A bot absent from the proposed policy holds nothing under it.
  - *Grants:* roles from the session's access requests (`access_grants` by request id), added for that resource exactly as `Restrictions::effective_roles` does at enforcement time. Access-review denies (ADR-0029) are not replayed.
  - *Requestable roles* come from `requestable_roles_for_groups`, so "now needs a request" is distinguished from "denied".
- **Reconstructing labels (option A).** Resource labels are those in the policy being evaluated, which is what enforcement would use today. The report says so, and marks a resource `labels_changed` when a `resource.relabel` event for it falls inside the window. Reading the labels a resource had at the time is out of scope; it needs resource change history (#75).
- **Shadow rules.** Sessions that stay allowed are also run through `shadow_denies` of the proposed policy, so the report adds "shadow rule `role/rule` would have fired for N sessions" (ADR-0046) without changing any outcome.
- **The proposed policy is built the way `apply` builds it.** The control plane takes it from a dry-run `policy_store::write` (so other sources' documents, ADR-0042 §3, are kept) and overlays accepted discovered resources as the active policy does. The console takes the pasted complete policy, as its dry run already does. `--replay` requires the old side to be `active`.
- **Surfaces.** `limen policy diff active --new <paths> --replay[=DAYS]` (default 30, at most 30) via a new `replay_days` on `ApplyPolicyRequest` (dry run only) and a `replay` block on the response; the console's "Check a change" result gains a "What this would have changed" section with a window field. Text, JSON and Markdown output. The effective-access diff still reports widening; replay covers narrowing, because only allowed sessions are recorded.
- **Exit code.** `--fail-on-affected` makes the command exit non-zero when any session is affected, for CI.

## Threats this design has to survive
- **A way to read a lot of audit data:** replay returns aggregates per (user, resource, principal) with counts and first/last time, never statements, client addresses, session ids, recordings or request text. It is admin-only (`limen:admin`), in the gRPC `Admin` service and the console; not in the bots' management API. Every replay is audited (`policy.replay`: who, window, policy digests, counts, never the rows) *before* it runs, and fails closed if the audit cannot be written. A per-person rate limit applies.
- **Resource exhaustion:** the window is capped at 30 days (the console's audit copy is trimmed at 30), the query groups in SQL and is limited to 20,000 groups (the response says when it was truncated), the policy size cap of `apply` applies, and the work is bounded by the group count.
- **SQL injection:** all queries are parameterized; the window is an integer.
- **A false "all clear":** the report states what it did not cover, counts skipped and already-refused sessions, and a truncated or approximate result says so at the top. "No sessions affected" is never printed without the number of sessions examined and skipped.
- **Information disclosure through the console:** admin-only like the rest of the policy page; CSRF-checked POST; all output escaped by the template engine.
- **Drift from enforcement:** shared code and the property test.

## Consequences
- A nullable `database` column on `sessions` (migration 0030), filled from `session.start` going forward.
- A new audit event kind `policy.replay`, emitted by the control plane only.
- New fields on `ApplyPolicyRequest` and `ApplyPolicyResponse` (additive; `buf breaking` clean).
- No behavior change for enforcement.

## Open for review
- Whether to record the login's groups on the session projection so the people's roles are exact (today: latest login).
- Whether to replay Kubernetes once the worker records the group.
- Whether to extend to denied attempts (`auth.denied`) to also show widening against real attempts.

## As built
Differences from, and additions to, the decisions above:
- **Console location.** The upstream paste-a-policy check was replaced by a per-document "Preview impact" while this was in review; the replay select lives there and in the save form, not in "Check a change".
- **Bounds.** 30-day window, 20,000 groups (newest kept, `truncated` set), `SET LOCAL statement_timeout = '10s'` on the scan, and at most 500 affected rows in the answer (`affected_omitted` carries the rest; totals stay exact).
- **Audit.** `policy.replay` has three phases: `start` (before any read, fail closed), `done` (counts, best effort) and `failed` (when a run errors after it started).
- **No false all-clear.** `--fail-on-affected` also fails when the replay was truncated, or when nothing could be replayed but sessions were skipped. Session rows without a user or resource are counted as skipped.
- **Output hygiene.** Terminal and Markdown output strip control and bidi characters and escape Markdown and mention characters; the console relies on template autoescaping.
- **Known limits.** The CLI replay uses the default policy source only. Access-review denies are not replayed. Roles use the latest login's groups. Sessions before migration 0030 have no recorded database and are skipped.
- **Numbering.** Migration is 0030 and this ADR is 0051 after rebasing onto upstream.
