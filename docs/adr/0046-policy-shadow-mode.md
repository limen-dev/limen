# ADR-0046: Shadow mode for policy rules

- Status: Proposed (issue #116, epic #117). Granularity (deny rules and roles), audit failure (allow, count the loss) and widening (needs a second admin) were decided by the owner on 2026-11-08; everything else is a default for review.
- Date: 2026-11-08

## Context
Tightening production access is risky because nobody knows what a new `deny` will break until it is live. Teams either skip the change or break someone's pipeline. ADR-0028 gives them `policy test` and `policy diff`, which reason about *policy*, not about the traffic that actually arrives. Shadow mode closes that gap: a rule is evaluated against real requests, but only reported.

## Decision
- **Scope of v1.** Resource-level `deny` rules and whole roles. `deny_commands` on database and Mongo grants are fields on *allow* grants, not `deny` rules, so they are out of scope (see Open for review).
- **Where it applies.** A `deny` rule, or a whole role, may carry `mode: shadow` (default `enforce`). `allow` rules cannot be shadowed: a shadowed allow would grant nothing, so the validator rejects it on a rule. On a role, `mode: shadow` means the role's `deny` rules are reported and its `allow` rules are ignored, so a shadow role cannot grant access either.
- **Rule names.** Deny rules are unnamed list items today. A `deny` rule with `mode: shadow` must have a `name`, unique within its role; the name is the stable identifier in audit events, tests and the console. Renaming a shadow rule starts a new history.
- **Expiry is a validator rule, not a runtime switch.** Every shadow rule or role needs `shadow_until: <date>`. `apply` rejects a missing date, a date in the past, and one more than 90 days ahead. Once a date has passed, `apply` of *any* change to that policy is refused until the rule is enforced or the date renewed (renewal is widening, see below). Before that, the console, `policy diff` and a metric warn as it approaches. A shadow rule keeps being shadow after its date at runtime: behavior is always fully described by the signed policy version (design §7.3), never by the clock, and no clock skew reaches enforcement. Rejected alternative: auto-enforce at the date. It would turn a forgotten rule into a surprise outage, which is the failure shadow mode exists to prevent, and make `who-can` and `diff` depend on time.
- **Evaluation.** Enforced rules are evaluated exactly as in design §7.2, and the decision is final. Shadow denies are then evaluated for the same request. A shadow deny is reported only when the final decision is **allow**, because a request that enforced rules already refused teaches nothing about the shadow rule. The decision itself is never changed by a shadow rule.
- **Audit event.** `policy.shadow_deny` carries the principal, resource, the role and rule name that matched, the reason, and the policy version. It sits beside the normal allow event for the same request and uses the same fields for correlation. Secrets are never included.
- **If the event cannot be written, the request is still allowed.** This is a deliberate, narrow exception to "audit fails closed". A shadow rule is documented as unable to deny; failing closed on its report would make it deny after all. The loss is counted in a metric (`limen_policy_shadow_events_dropped_total`) and logged without secrets. The ordinary allow/deny events keep their configured failure mode (ADR-0009, design §8) and are unaffected. In practice the exception rarely triggers: the shadow event and the allow event share the spool, so a full spool under `fail_closed` already denies through the normal path. `CONTRIBUTING.md`'s invariant list gets a matching note when this is accepted.
- **Widening.** Changing a rule or role from `enforce` to `shadow` removes a deny that currently holds, so it is widening of standing access. It is held for a second admin **whatever `--widening-approval` says**, including for a person's apply under the default `writers` mode. This deviates from ADR-0042, which holds only bot writers' widening by default; the deviation is intended and ADR-0042 gets a cross-reference. The effective-access diff already sees this change, since shadow rules count as not enforced. Extending or renewing `shadow_until` changes no effective access, so the diff cannot see it; a separate check in `ApplyPolicy` compares the old and new dates and holds the change the same way. `shadow` to `enforce` is a tightening and applies directly.
- **Tooling (ADR-0028).** `explain` and the trace say a shadow deny matched and that it did not apply. `who-can`, `what-can` and `diff` treat shadow rules as not enforced, so the effective-access diff shows the access that is really open. `policy test` gains `expect: allow` with `shadow_deny: [role/rule-name]`, so CI can assert that a rule would fire. Console: the policy page lists shadow rules with their expiry, and an event view groups `policy.shadow_deny` by rule so "is the log quiet?" is one screen. Dashboards (ADR-0014) get a count per rule.
- **One engine.** `limen-policy` returns the shadow matches next to the `Decision` without changing the `Decision` enum, so every enforcement point (proxy, worker, web per-request) keeps treating anything but `Allow` as a denial. The property test from ADR-0028 is extended: with every shadow rule set to enforce, the trace's shadow matches must equal the enforcement path's denials.

## Threats this design has to survive
- **Shadow mode as a quiet way to turn a deny off:** widening approval, a mandatory expiry, an audit event on every change, and the refusal to apply past the date.
- **A shadow rule lingering for years:** the 90-day cap and the `apply` refusal after the date; the console and `policy diff` list rules close to expiry.
- **A shadow rule that denies:** it never changes the `Decision`, and a test per enforcement point asserts this with the audit sink broken.
- **Noise or event flooding:** one event per request and matching rule. The hash-chained trail is not sampled, so a busy shadow rule produces volume; the console groups by rule and the dashboard counts per rule. Whether to add a per-rule cap is left for review.
- **Information disclosure:** shadow events are admin and auditor data, like other policy events. `explain` for ordinary users does not mention shadow rules.

## Consequences
- New schema fields (`mode`, `shadow_until`) on `deny` rules and roles, in the strict schema and the generated reference. Old documents are unchanged.
- A new audit event type, a metric, a dashboard panel and a console view.
- A narrow, documented exception to the fail-closed invariant that needs a test to keep it narrow.

## Open for review
- Whether the 90-day cap should be configurable.
- Whether a shadow deny should also be reported when an enforced rule already denied (flag-gated, default off).
- Whether auto-enforcing at `shadow_until` should be offered as an opt-in per rule.
- Whether `deny_commands` (database and Mongo grants) should get an equivalent mode in a later version.
- Whether a per-rule cap on shadow events is needed.
