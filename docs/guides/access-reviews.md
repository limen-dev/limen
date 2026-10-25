# Access reviews and evidence

Auditors ask the same questions every year: who had access to what, who approved it, and did anyone check? Limen already holds the answers. Collecting them should be a button ([ADR-0029](../adr/0029-access-reviews-and-evidence.md)).

## Reviews

```sh
limen admin review start --name "Q4 access review" --due-days 14
limen review ls                      # reviews with items for you
limen review items <review> --mine --open
limen review certify <item> -m "still on the team"
limen review flag <item> -m "moved to another team"
limen admin review ls --all
```

(`limen admin review ...` and `limen review ...` are the same commands; admins may use either.) In the console it is **Reviews**.

A review snapshots who holds what: one **item** per person (or bot) and role, with what the role reaches and **how much they used it in 90 days** (unused access is marked). Items go to an owner: the role's `owner` label, else the owner most of its resources name, else any admin.

```yaml
kind: role
metadata: { name: dba, labels: { owner: dba-lead@example.com } }
```

- **Nobody reviews their own access.** Their items go to the admin pool, and an admin cannot decide an item about themselves.
- **Certify** keeps it. **Flag** needs a comment and creates a **deny override**.
- Items undecided after the due date **escalate to the admins**; reviewers get reminders every three days in the last three days before.
- The review closes when its last item is decided. `--review-interval` (default 90 days) starts one by itself; `0` turns the schedule off.

### Deny overrides

Limen cannot edit IdP groups. A flag therefore creates an override for that person and role: carried in the signed snapshot like a lock, so it takes effect at every proxy and worker within seconds. It **withholds the role** (from their certificate, from a grant, from a mapping), **ends their open sessions** on what the role reaches, and **lifts itself** when their next login shows the IdP change (their roles no longer include it), or after `override_days` (default 30). `limen admin review overrides` lists them; `limen admin review lift <id> --reason ...` gives one back. A person who loses their only group cannot log in at all, so the override simply runs to its expiry.

Rubber-stamping is visible: the dashboards and review lists count items certified *without a comment*.

## Evidence packs

```sh
limen admin evidence --from 2026-07-01 --to 2026-10-01 --out q3-evidence.json
limen-audit-verify --evidence q3-evidence.json --ca-file internal-ca.pem \
                   --audit-events audit.jsonl      # optional: find the export in the trail
```

One JSON file: access requests with their approvals, grants (and revocations), reviews and decisions, deny overrides, locks, policy changes, sessions (with the requests that allowed them), a `meta` section with notes about the sources, and CSV copies for a spreadsheet (cells that would run as formulas are defused). A **manifest of SHA-256 hashes is signed by the control plane**, and exporting emits an `evidence.export` audit event carrying the manifest hash, so a pack that was edited, added to, or never produced shows. Verification needs only the internal CA certificate: an auditor needs no access to Limen.

Limits worth knowing: a pack covers at most 400 days and 50,000 rows per section; session kills and component revocations live in the console for two days and in the audit sinks for good, so use the trail for those; roles are those from each person's latest login.

## Mapping to controls (guidance, not certification)

| You are asked for | Evidence in the pack |
|---|---|
| Access is granted on approval and for a reason (SOC 2 CC6.1/CC6.2, ISO 27001 A.5.15/A.5.18) | `access_requests`, `access_grants`: who asked, why, who approved, for how long |
| Access is reviewed periodically (SOC 2 CC6.2/CC6.3, ISO 27001 A.5.18) | `reviews`: every item, its reviewer, decision, comment, and date; `deny_overrides` for what was removed |
| Access is removed when no longer needed (SOC 2 CC6.3, ISO 27001 A.5.18/A.8.2) | grants' `expires_at`/`revoked_at`; flagged items; `locks` |
| Privileged and emergency access is controlled and monitored (ISO 27001 A.8.2) | break-glass grants, `access.break_glass` events, their reviews |
| Changes to access rules are controlled (SOC 2 CC8.1) | `policy_changes` with author and source reference |
| Activity is logged and logs are protected (SOC 2 CC7.2, ISO 27001 A.8.15) | `sessions` with recording hashes; the signed, hash-chained audit trail verified by `limen-audit-verify` |

This is a map from Limen's records to the questions auditors ask, not a statement that using Limen satisfies a control. Your auditor decides that; the wording should be reviewed before it is shown to one.
