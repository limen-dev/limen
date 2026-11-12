# ADR-0053: Scheduled self-test and controls report

- Status: Proposed (issue #113, `needs: design`). Built at the owner's request with the defaults below; the decisions under Open for review are not yet approved, and the status stays Proposed until they are.
- Date: 2026-11-10

## Context
ADR-0031 positions Limen as access you can prove. Today an auditor can verify the audit chain and an evidence pack offline, but nothing shows, on a schedule and without a person asking, that the controls themselves still work: that a denied path is still denied, that an expired certificate is still refused, that a lock still stops an account, that the trail is still being sealed. Issue #113 asks for a periodic self-test, its results audited and exported as a signed "controls are working" report, with an alert when a check fails. It must never touch real user data or open real resources.

A report that overstates what was tested is worse than none (ADR-0031, Risks). The design therefore starts from what each check can honestly claim.

## Decision
### The test principal can never gain real access
The self-test has no identity that any issuer will vouch for. This is enforced structurally, then tested:
- **A reserved name.** Usernames starting with `selftest:` (compared ASCII case-insensitively) are reserved, like `bot:`. `limen_core::identity::is_selftest` is the one predicate. It is refused at six entry points: the user CA (`issue_user`), the certificate verifier (`verify_user`, so a certificate that somehow carries the name is not an identity), gRPC OIDC login, console sign-in, web-app sign-in, and SCIM provisioning. The three sign-in paths use one predicate, `limen_core::identity::is_reserved`; tests cover the CA, the verifier, the predicate, gRPC login and SCIM. Console and web-app sign-in are not exercised by a flow test (the repository has none for `bot:` there either). No policy document names users, so policy needs no rule; a `role_mapping` maps IdP groups, not names.
- **No credential is ever minted for it.** Certificate checks use throwaway in-memory CAs created and dropped inside the run. The real user and internal CA keys sign nothing for the self-test, and nothing it produces is returned or stored except the verdict.
- **No committed row.** The lock check inserts its probe row inside a transaction that is always rolled back, with a short statement timeout. Nothing is visible to other replicas, the console, or an evidence pack.
- **No real resource.** Policy checks evaluate; they do not connect, issue a grant, or create a session.

### What each check claims
A check's id and title name the path it exercised and nothing wider. Each result is `passed`, `failed`, or `skipped` (with the reason). **A skipped check is never a pass**, in the report, the metrics, or the exit code of `--strict`.

| Id | What it exercised | Skipped when |
|---|---|---|
| `policy.declared_tests` | The operator's own `policy_test` documents, run against the policy in force now (applied policy plus accepted discovered resources) | No `policy_test` document is declared |
| `policy.engine` | The deployed policy engine on a fixed in-memory policy: deny overrides allow, a label mismatch denies, an unknown resource denies, a requestable role is not an allow. An engine self-test: it says nothing about the operator's policy | Never |
| `cert.expired_refused` | The production `verify_user` refuses a certificate past its end date | Never |
| `cert.foreign_ca_refused` | `verify_user` refuses a certificate from a CA it was not given | Never |
| `lock.refused` | The two SQL checks the API (`lock_and_logout`) and the grant and certificate paths (`is_locked`) use see a lock, case-insensitively, and see no lock for a different name; and a locked or ended login maps to a refusal. It does **not** open a session | Never |
| `audit.sinks` | The audit spool is shipping: this replica is not fenced, and each sink is either caught up or accepted a batch recently | Never |
| `audit.manifest_tail` | The S3 manifests of every writer: the signature, signer, sequence numbers and hash chain of the last batches, plus the link to the one before them | No S3 audit sink |
| `recording.integrity` | A sample of recent recordings re-hashed and compared with the hash the worker reported. Reports session ids only | No recorded session in the window |

`audit.manifest_tail` is **deliberately a tail, not the whole chain**. The control plane's role can read manifests and recordings but not event batches (`deploy/terraform/modules/audit`, the writer policy), and this ADR does not widen it. So the check cannot see a modified batch or a gap in an event sequence; that is `limen audit verify`, run by someone who does not have to trust Limen. The check lists every manifest key to find each writer's newest, so it grows with the number of manifests (reads are bounded to 21 per writer) and has a 90-second timeout. It cannot see a writer whose newest manifests were deleted, or one whose prefix was removed whole, and it assumes the oldest manifest is sequence 0 (a lifecycle rule that expires old manifests would show as a gap). The report says this in words.

### The report is a self-attestation, and says so
The control plane signs the report with its own certificate, the same way it signs evidence packs. That proves the report was produced by a control plane the internal CA issued and was not edited. It does not prove the checks ran honestly: a compromised control plane could sign a clean report. So every report states, in a signed field, that it is the control plane attesting to itself and that the audit chain should be re-verified offline with `limen audit verify`. A run that ends in an error after its `selftest.run` event was written (signing or saving failed) writes a second event with `status: error`, which supersedes the first. The audit event anchors the report in the same trail, so a report that was never produced, or was replaced, shows.

- **Format `limen-controls/1`.** Same envelope as an evidence pack: a manifest of SHA-256 hashes of each section, signed under a new `Purpose::ControlsReport` (its own label, so a signature for one purpose cannot be presented as another). The offline verifier is the evidence verifier generalised to take the format and purpose, not a second implementation.
- **Sections.** `checks` (id, title, status, detail, duration) and `meta` (control plane, run id, trigger, policy version and digest, build version, interval, **the list of expected check ids**, the attestation note). A check dropped from `checks` is visible because `meta` still lists it, and both are under the signature. `limen audit verify --controls FILE` also fails a report whose expected and present ids differ.
- **Anchored first.** The `selftest.run` audit event, with the manifest hash, is written before the report exists: no event, no report. If audit is unavailable the run ends as `error` (no report), is counted, and alerts.
- **Evidence packs** gain a `controls` section: the runs in the period, with their manifest hashes. An auditor then sees, in the pack they already request, whether the controls were being tested.

### Scheduling and scale-out
- **Interval.** `--selftest-interval` (`LIMEN_SELFTEST_INTERVAL`), default 24 hours, `0` turns it off. Runs are also started by an admin (`limen selftest run`, console "Run now").
- **One run at a time, across replicas.** A run is a row in `selftest_runs`; a partial unique index allows one `running` row. A replica claims a run with `INSERT … ON CONFLICT DO NOTHING`, so a second replica, or a second click, gets the run in progress instead of a new one. A scheduled claim also requires that no scheduled run started within the interval. A `running` row older than 15 minutes (a crashed replica) is marked `abandoned`. No advisory lock is held on a pooled connection.
- **Manual runs are admin only and rate limited**: at most one manual run per minute.
- **Bounded.** Each check has a timeout; the recording sample is at most five recordings and 128 MiB in all; the manifest tail is the last 20 batches per writer.

### Alerting
- Metrics, published from the database by every replica so any one can serve them: `limen_selftest_last_run_timestamp_seconds`, `limen_selftest_last_run_ok` (1 passed, 0 failed or errored), `limen_selftest_checks{status}`, and `limen_selftest_check_ok{check}` (1 passed, 0 failed, NaN while skipped). Prometheus rules for a failed run and for no run in two days ship in `deploy/prometheus/alerts.yml`. A Datadog monitor and a Grafana alert are not built.
- A `selftest.run` event with `data.status` = `failed` or `error` is the audit-side signal for detections (issue #107).
- A failing check is **not** an automatic lock or shutdown. It is a signal to a person; automatic action on a self-test result is issue #109's design to make.

### Data kept
`selftest_runs` holds the run's status, counts, timing, trigger, who asked, the manifest hash and the exact signed report bytes (stored as `bytea`, because `jsonb` would change them). Reports hold no usernames except the admin who started a manual run, no session content, and session ids only for recordings that failed. Runs are pruned after 400 days, the longest period an evidence pack covers.

## Threats this design has to survive
- **The test principal becomes a real backdoor:** the reserved name is refused at every issuer and by the verifier, tested per entry point; no credential is minted; the lock probe is rolled back. An IdP user named `selftest:x` is refused at login.
- **The self-test claims more than it tested:** ids and titles name the path; skipped is its own status; the audit check is called a tail and says what it cannot see; the report states it is a self-attestation.
- **A tampered or truncated report:** every section is hashed under the signature; the expected check list is signed; tamper tests cover every manifest field and section.
- **A report forged for a different purpose, or an evidence pack passed off as a report:** own signature label and format string; each is rejected by the other's verifier.
- **The job as a denial of service or a data leak:** single-flight, rate-limited, timeouts, a bounded sample; no content in reports or logs.
- **Silence:** a self-test that stops running looks like a clean one, so staleness alerts, and a run that cannot finish is `error`, not absence.
- **Widened privileges:** the control plane's IAM is unchanged.

## Consequences
- A reserved username prefix, a migration, a job, three RPCs (`Controls` service), a CLI command group, a console page, metrics and alert assets, a new audit event kind (with its OCSF mapping), a `Purpose`, and a verifier option.
- A new data store (`selftest_runs`) and new entry points: both are in the threat model.
- No new dependency.

## Open for review
- The default interval (24 hours) and whether the job is on by default.
- Whether failing checks should ever act (lock, page) rather than signal.
- Whether the audit check should instead use the verifier role to read event batches (a wider, separately granted permission), giving a full-chain check at the cost of a standing read on recordings' bucket.
- Whether a `policy.declared_tests` failure should block policy applies until fixed.
- Whether a signed report should also be written to the audit bucket.

## Not verified
- Nothing here has run against AWS: the manifest-tail check is tested against SeaweedFS, and the recording check against the local store and SeaweedFS. KMS signing of the report is the same code path as evidence packs, tested against the KMS emulator only.
