# Self-test and controls report

Limen tests its own controls on a schedule and keeps a signed report of the result. An auditor can then see, without asking anyone, that the controls were being tested and what they found. Design and decisions: [ADR-0051](../adr/0051-scheduled-self-test.md).

**It is the control plane attesting to itself.** The signature proves that a control plane your internal CA issued produced exactly these results and that nobody edited them afterwards. It does not prove the checks ran honestly: a compromised control plane could sign a clean report. Every report says so inside the signature. To prove the audit trail, someone who does not have to trust Limen runs [`limen audit verify`](../runbooks/audit-verify.md) against it.

## What it checks

Each check names the path it exercised and claims nothing wider. A check ends `passed`, `failed` or `skipped`; **a skipped check is not a pass**, and the report says why it was skipped.

| Check | What it exercised | Skipped when |
|---|---|---|
| `policy.declared_tests` | Your own `policy_test` documents, run against the policy in force now (the applied policy plus accepted discovered resources, which apply-time tests never see) | You declare no `policy_test` |
| `policy.engine` | The deployed policy engine on a fixed policy: deny overrides allow, a label mismatch denies, an unknown resource denies, a requestable role is no access. It says nothing about *your* policy | never |
| `cert.expired_refused` | The production certificate verifier refuses a user certificate past its end date | never |
| `cert.foreign_ca_refused` | The verifier refuses a certificate from a CA it was not given | never |
| `lock.refused` | The SQL the API and the grant and certificate paths use sees a lock (any letter case) and an ended login, and nothing for another name; and those answers become refusals. It does not open a session | never |
| `audit.sinks` | No audit sink is stuck behind, and S3 shipping is not paused | never |
| `audit.manifest_tail` | The newest S3 manifests of every writer: signed by that writer, numbered without a gap, chained by hash | no S3 audit sink, or no manifests yet |
| `recording.integrity` | The newest five recordings, re-hashed and compared with the hash the worker reported | no ended session has a recording |

`audit.manifest_tail` reads **manifests only**. The control plane's role cannot read event batches (the `audit` Terraform module's writer policy), and the self-test does not widen it. So the check cannot see a modified batch or a gap in an event sequence, which is what `limen audit verify` is for.

## The test principal cannot gain access

- Names starting with `selftest:` are reserved. The user CA will not issue a certificate for one, the verifier does not accept one, OIDC login and SCIM refuse them.
- Certificate checks use throwaway CAs created and dropped inside the run. The real CA keys sign nothing for the test.
- The lock check inserts its probe in a transaction that is always rolled back. No other replica, the console or an evidence pack ever sees it.
- No check connects to a resource, issues a grant or starts a session.

## Running it

It runs every 24 hours. `--selftest-interval` (`LIMEN_SELFTEST_INTERVAL`) changes that; `0s` turns the schedule off. With several control planes, one runs each slot. A fresh process waits a few minutes before its first run.

```sh
limen admin selftest run                 # now; waits, exits 2 if a control failed (limen:admin)
limen admin selftest ls                  # recent runs (limen:admin or limen:auditor)
limen admin selftest report --out limen-controls.json
```

A manual run is allowed once a minute; if one is already running you get that one. The console has a **Controls** page with the same.

## Checking a report offline

```sh
limen audit verify --controls limen-controls.json --ca-file internal-ca.pem
limen audit verify --controls limen-controls.json --ca-file internal-ca.pem --strict   # skipped counts as failed
limen audit verify --controls limen-controls.json --ca-file internal-ca.pem --audit-events audit.jsonl
```

It checks the signature (judged at the time the report records, so it still verifies after the signer's certificate expires), every section against the signed manifest, and that every check the report says it expected is present once. With `--audit-events` it also looks for the run's `selftest.run` event, which carries the report's manifest hash: the event is written before the report exists, so a report that was never produced or was swapped shows. It exits 2 if the report is damaged or a control failed.

Evidence packs (`limen admin evidence`) include a `controls` section listing the runs of the period with their manifest hashes.

## Alerts

| Metric | Meaning |
|---|---|
| `limen_selftest_last_run_timestamp_seconds` | When the last run finished |
| `limen_selftest_last_run_ok` | 1 if it passed, 0 if it failed or ended in an error |
| `limen_selftest_checks{status}` | Checks by outcome in the last run |
| `limen_selftest_check_ok{check}` | 1 passed, 0 failed, NaN while skipped or when the last run has no report |

The Prometheus rules in `deploy/prometheus/alerts.yml` fire on a failed run and on no run for more than twice the interval. A run that could not finish (audit unavailable, no signing key) is an `error`, which counts as not OK. The audit event `selftest.run` carries `data.status` (`passed`, `failed`, `error`) for SIEM rules. A failing check does not lock anyone or stop anything; it is a signal to a person.

## Limits

- Tested against local stand-ins only (a PostgreSQL, SeaweedFS and a KMS emulator); not against AWS. Issue label: `unverified`.
- The manifest-tail check sees the newest 20 manifests per writer, not the whole chain.
- The recording check samples the newest five, up to 128 MiB.
- Reports are kept 400 days.
