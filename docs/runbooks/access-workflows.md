# Running the access workflows

Setup and day-two tasks for access requests, search, discovery, reviews, and live watch. The user-facing behavior is in the guides: [requests](../guides/access-requests.md), [search](../guides/audit-search.md), [discovery](../guides/discovery.md), [policy tooling](../guides/policy-tooling.md), [reviews](../guides/access-reviews.md), [watching](../guides/watching-sessions.md).

## Turn on access requests

1. In policy, add a `request` block to the roles people should be able to ask for (and/or a `break_glass` role). `limen policy test` the change, then `limen admin apply --require-tests`.
2. Make sure approvers can **sign in**: they only need to appear in `request.approvers` or `approver_users`. Nobody needs a role mapped.
3. Configure at least one notifier so approvers know. Webhook: `--notify-webhook-url https://...` and `--notify-webhook-secret` (verify `X-Limen-Signature` = `sha256=HMAC(secret, timestamp + "." + body)` and reject old timestamps). Slack: `--notify-slack-url`. For break-glass, point `--break-glass-slack-url` at a channel people actually watch. Check `limen_notifications_total{outcome="failed"}`.
4. Tell people: `limen ls` shows what they can ask for; grants start within about 20 seconds of approval.

**Break-glass happened.** The event `access.break_glass` and the critical notice are the alarm. Look at what the person did: Audit trail, filter by user, or `limen audit search 'user:alice after:2h'`; the session pages link to the request. The next access review includes it (`via = break_glass`). To end it early: `limen admin revoke-grant <request id> --reason ...`.

**A grant must end now.** `limen admin revoke-grant <id> --reason ...`. Proxies end the sessions within about 10 seconds. To cut a person off entirely use [a lock](lock-user.md), which beats every grant.

## Turn on search

Nothing to do for events: the index fills from the audit stream and keeps 30 days (`--search-retention`). It needs the `pg_trgm` extension (a trusted extension on RDS and Aurora; the migration creates it). Recording text is a decision: `--search-recordings` indexes terminal output with secret shapes masked (best effort). Size it at up to 256 KiB per session plus the index. Map the `limen:auditor` role to your auditors' group. For history beyond the window set `--search-history-url`.

## Turn on discovery

1. Create the IAM role: `deploy/terraform/modules/discovery`, one per account, trusting the roles your workers run as.
2. Add a `kind: discovery` document ([example](../../examples/policy-workflows/discovery.yaml)). Set `worker_selector` to the pool of workers that can reach the targets, because it is also the selector of what they find.
3. Start those workers with `--discovery`. Watch `limen_discovery_scans_total{outcome}` and the worker log.
4. Review: console *Resources → Discovered*, or `limen admin discovery status`. Accept what you recognise. Roles that select a label copied from a tag are a risk the console warns about; prefer `auto_accept` only for labels no role selects on.
5. EC2 hosts need their SSH host key from the console output; images that do not print one show a blocker and cannot be accepted.

## Reviews

`limen admin review start` (or leave `--review-interval` at 90 days). Give roles an `owner` label first, or every item goes to the admins. Reviewers get console links and reminders. Flagged access is withheld at once; ask whoever owns the IdP group to remove the person, and the override lifts itself after their next login. `limen admin review overrides` lists what is withheld.

## Evidence for an audit

`limen admin evidence --from 2026-07-01 --to 2026-10-01 --out q3.json`. Hand the auditor the file and `internal-ca.pem`; they run `limen-audit-verify --evidence q3.json --ca-file internal-ca.pem`. For the kills and revocations the pack does not carry, point them at the S3 trail ([verifying it](audit-verify.md)).

## Watching a session

Admins: the session page, **Watch it**. Auditors may too if you start the control plane with `--auditors-may-watch`. Set `notify_observed: true` on roles whose users should be told. Everything a watcher does is in the audit trail as `session.watch.start` and `stop`.
