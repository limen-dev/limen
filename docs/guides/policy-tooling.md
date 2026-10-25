# Testing and questioning policy

Policy is YAML in Git. A growing policy needs what code has: tests that run in CI, a way to ask "who can reach this?", a diff of *effective access*, and clear reasons when something is denied ([ADR-0028](../adr/0028-policy-tooling.md)).

**One engine.** Every command here calls the same decision code as enforcement (`limen-policy`). A test feeds 5,000 random requests to both the tracing path and the enforcement path and requires the same answer.

## Tests in the policy

```yaml
kind: policy_test
version: v1
metadata: { name: prod-is-locked-down }
spec:
  cases:
    - name: developers cannot ssh to prod as root
      who: { groups: [developers] }
      resource: orders-prod
      principal: { login: root }
      expect: deny                 # no way in at all, not even by asking
    - name: developers can ask for the prod database
      who: { groups: [developers] }
      resource: orders-prod
      principal: { db_role: limen_read, database: orders }
      expect: request              # not granted, but requestable
    - name: sre reads prod through the right role
      who: { groups: [sre] }
      resource: orders-prod
      principal: { db_role: limen_read, database: orders }
      expect: allow                # standing access
      via_role: sre-prod-readonly
```

`who` is `groups`, a `bot`, or `roles` held directly, never a user name, so a case does not depend on who is in the user table. A case against a resource that does not exist **fails** (a "must deny" on a typo would otherwise pass). `policy_test` documents are validated like the rest and ignored at runtime.

```sh
limen policy test policy/ --coverage      # exits non-zero on any failure; lists resources and roles no case touches
limen admin apply policy/ --require-tests # refuses to apply if a case fails, or if there are none
```

`apply` and the console's *Check a change* also show the policy's test results next to the diff.

## Who can reach this, and what can they reach

```sh
limen policy who-can orders-prod --from policy/      # offline, from files
limen policy who-can orders-prod --active            # the running policy (limen:admin)
limen policy what-can --group developers --group on-call
limen policy what-can --bot deploy-staging
```

Each lists the role, how (`standing`, `by request`, `break-glass`), the principals, the groups and bots that hold it, and who approves. In the console, a resource page has **Who can reach it**, and **Policy → Access simulator** answers `what-can`.

## What a change does

```sh
limen policy diff policy-main/ --new policy/ --format markdown   # for a pull request comment
limen policy diff active --new policy/ --fail-on-widening
```

The diff compares *effective access*, not YAML: "group `sre` gains ssh access to `web-prod` as ubuntu", "role `deployer` loses ...", "group `developers` gains ... (after a request is approved)". `--fail-on-widening` exits non-zero when anyone gains **standing** access, so CI can ask for a closer look. `limen admin apply` and the console print the same lines.

Warnings (valid, probably not meant): a group that can both request and approve a role, a requestable role a group already holds, a role that selects on a label copied from a cloud tag.

## Why was I refused

```sh
limen explain orders-prod --as db_role=limen_read --database orders
limen explain orders-prod --user alice@example.com        # admins: the full trace
```

A user's answer describes only **their own roles**, in words that name nothing about resources they cannot see, and a resource that exists but is hidden reads *exactly* like one that does not exist. If they could ask for it, it says how. Admins get the full trace: which rule matched, or why each did not ("needs env in [staging], the resource has env=prod"), plus locks and grants.

## In CI

`examples/ci/policy-check.yml` is a GitHub Actions workflow that runs the tests, posts the effective-access diff as a pull request comment (`scripts/policy-pr-comment.sh`), and fails when standing access widens without a label. Copy it into your policy repository.
