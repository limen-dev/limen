# ADR-0028: Policy tooling: test, simulate, diff, explain

- Status: Accepted and built (Phase 13). The owner asked for the whole phase on 2026-10-25.
- Date: 2026-10-14

## Context
Policy is deny-by-default YAML kept in Git, with a console dry run that shows a diff before applying. That is a good start, but a growing policy needs what code has: tests that run in CI, a way to ask "who can reach this?" and "what can she reach?", a before-and-after view of *effective access*, and clear reasons when something is denied.

## Decision
- **One engine, no second implementation.** Every feature below calls the same decision code as enforcement (`limen-policy`). A property test feeds random inputs to both the simulator and the enforcement path and requires identical answers.
- **`limen policy test`:** offline, for CI. Test files are policy documents of `kind: policy_test`:
  ```yaml
  kind: policy_test
  version: v1
  metadata: { name: prod-is-locked-down }
  spec:
    cases:
      - who: { groups: [developers] }
        resource: orders-prod
        principal: { login: ubuntu }
        expect: deny
      - who: { groups: [sre] }
        resource: orders-prod
        principal: { db_role: limen_read }
        expect: allow
        via_role: sre-prod-readonly
  ```
  Exit code is non-zero on any failure. `limen admin apply --require-tests` refuses to apply when tests fail. A workflow snippet and a pull-request comment script ship in `docs/`.
- **`limen policy who-can <resource>`** lists the roles, group mappings, and eligible-by-request roles (ADR-0025) that reach it, with the rule that matches. **`limen policy what-can <user|group|bot>`** is the forward query. Both work offline on a policy directory or online against the active policy.
- **`limen policy diff <old> <new>`** compares *effective access*, not YAML: "group `sre` gains `ssh` to `web-prod` as `ubuntu`", "role `deployer` loses `bastion-*`". It is the thing a reviewer reads. Output is text, JSON, and Markdown (for a PR comment).
- **`limen explain <resource>`** (and the same text in denial messages and the console) says **why**: which roles you hold, which selector didn't match (`env=prod` needed, your roles allow `env=staging`), whether a lock or an expired grant applies. A user sees only their own roles and never learns whether a hidden resource exists (it answers the same as for a missing one). Admins can ask about anyone and get the full trace (`limen policy explain --user ... --resource ...`).
- **Console:** the resource page gains "Who can reach this?"; the policy page gains an **access simulator** (pick groups or a user, see reachable resources) next to the existing dry run, which now shows the effective-access diff too.
- **Library first:** the logic lives in `limen-policy` as pure functions, with the CLI, console, and API as thin callers.

## Threats this design has to survive
- **Simulator drifting from enforcement:** shared code and the property test above.
- **Information disclosure through `explain`:** scoped to the caller's own roles; hidden resources are indistinguishable from missing ones; admin-only trace.
- **A green test suite that proves little:** `limen policy test --coverage` reports resources and roles no case touches, and `must deny` cases are first-class.
- **Tests applied to the wrong identities:** cases name groups and principals explicitly; they don't depend on the live user table.

## Consequences
- A new document kind (`policy_test`) the validator accepts and the engine ignores at runtime.
- `limen-policy` needs a trace-producing decision function; enforcement keeps using the allocation-light one, and a test asserts both agree.

## As built (Phase 13)
Accepted by the owner's request to build the phase. Differences:

- **`expect` has three values**: `allow` (standing access), `request` (requestable), `deny` (no way in, not even by asking), so a "must deny" is not satisfied by something a person could simply ask for.
- **`limen policy diff old --new new`** takes `active` for the running policy, `--format text|json|markdown`, and `--fail-on-widening` (standing access only). It compares groups, bots, and roles, and shows access by request separately; access that merely became standing is not reported as a loss of request access.
- **`explain` for users** describes only the roles they hold or can request; a hidden resource reads exactly like a missing one (a test pins this). Admins get the full trace, including locks and grants.
- **`apply --require-tests`** is enforced by the control plane, and `apply` prints the effective-access changes, warnings, and test results.
- **Agreement with enforcement** is tested with 5,000 random requests against `evaluate_eligible` and `trace`.
- **CI:** `examples/ci/policy-check.yml` and `scripts/policy-pr-comment.sh`.
