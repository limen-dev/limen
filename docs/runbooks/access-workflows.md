# Running the access workflows

Setup and day-two tasks for access requests, search, discovery, reviews and live watch. Behaviour is in the guides: [requests](../guides/access-requests.md), [search](../guides/audit-search.md), [discovery](../guides/discovery.md), [policy tooling](../guides/policy-tooling.md), [reviews](../guides/access-reviews.md), [watching](../guides/watching-sessions.md).

## Access requests

1. Add a `request` block to the roles people should be able to ask for (and/or a `break_glass` role). Run `limen policy test`, then `limen admin apply --require-tests`.
2. Approvers only need to appear in `request.approvers` or `approver_users` to sign in; no role needs mapping.
3. Configure at least one notifier. Webhook: `--notify-webhook-url https://...` and `--notify-webhook-secret`; verify `X-Limen-Signature` = `sha256=HMAC(secret, timestamp + "." + body)` and reject old timestamps. Slack: `--notify-slack-url`. For break-glass, point `--break-glass-slack-url` at a channel people watch. Alert on `limen_notifications_total{outcome="failed"}`.
4. Tell people that `limen ls` shows what they can ask for, and grants start within about 20 seconds of approval.

**Break-glass happened.** The `access.break_glass` event and the critical notice are the alarm. See what the person did: Audit trail filtered by user, or `limen audit search 'user:alice after:2h'` (session pages link to the request). The next access review includes it (`via = break_glass`). End it early with `limen admin revoke-grant <request id> --reason ...`.

**A grant must end now.** `limen admin revoke-grant <id> --reason ...`; proxies end its sessions within about 10 seconds. To cut a person off entirely, use [a lock](lock-user.md), which beats every grant.

## Search

Events need nothing: the index fills from the audit stream and keeps 30 days (`--search-retention`). It needs the `pg_trgm` extension (trusted on RDS and Aurora; the migration creates it). Indexing recording text is a decision: `--search-recordings` indexes terminal output with secret shapes masked (best effort), costing up to 256 KiB per session plus the index. Map `limen:auditor` to your auditors' group. For history past the window, set `--search-history-url`.

## Discovery

1. Create the describe-only IAM role, one per account, trusting the roles your workers run as (permissions: discovery guide, "IAM").
2. Add a `kind: discovery` document ([example](../../examples/policy-workflows/discovery.yaml)). Its `worker_selector` should be the pool that can reach the targets, since it also selects who serves what they find.
3. Start those workers with `--discovery`; watch `limen_discovery_scans_total{outcome}` and the worker log.
4. Review in the console (*Resources → Discovered*) or with `limen admin discovery status`. Accept what you recognise. Use `auto_accept` only for labels no role selects on; a role selecting on a tag-derived label is a risk the console warns about.
5. EC2 hosts need their SSH host key from the console output. An image that prints none shows a blocker and can't be accepted.

## Reviews

Run `limen admin review start`, or leave `--review-interval` at 90 days. Give roles an `owner` label first, or every item goes to the admins. Reviewers get console links and reminders. Flagged access is withheld at once; ask the IdP group's owner to remove the person, and the override lifts itself after their next login. `limen admin review overrides` lists what is withheld.

## Evidence for an audit

```sh
limen admin evidence --from 2026-07-01 --to 2026-10-01 --out q3.json
```

Give the auditor the file and `internal-ca.pem`; they run `limen audit verify --evidence q3.json --ca-file internal-ca.pem`. Kills and revocations aren't in the pack, so point them at the S3 trail ([verifying it](audit-verify.md)).

## Watching a session

Admins use **Watch it** on the session page. Auditors may too with the control plane flag `--auditors-may-watch`. Set `notify_observed: true` on roles whose users should be told. Watchers appear in the trail as `session.watch.start` and `stop`.
