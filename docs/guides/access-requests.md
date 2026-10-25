# Access requests and break-glass

Standing access means anyone whose group maps to a role can reach its resources at any hour. A *requestable* role is the opposite: it grants nothing until somebody asks, gives a reason, and an approver agrees. The access then exists for a limited time, and every session it allows points back to the request ([ADR-0025](../adr/0025-access-requests.md)).

## What you write

A role becomes requestable with a `request` block. It can still be mapped to groups too.

```yaml
kind: role
version: v1
metadata: { name: prod-db-readonly }
spec:
  allow:
    - resources: { kind: [postgres], labels: { env: [prod] } }
      db: { roles: [limen_read], databases: ["*"] }
  request:
    who: [developers]              # IdP groups that may ask
    approvers: [sre-leads]         # IdP groups that may approve ...
    approver_users: [alice@example.com]   # ... and/or named people
    approvals_required: 2          # different people; default 1
    max_duration: 2h               # the longest grant; default 2h, at most 7d
    require_reason: true           # default true
    ticket_pattern: '^(INC|OPS)-[0-9]+'   # the reason must match; linear-time matcher
```

`break_glass: true` makes a role an emergency one: it is granted at once, requires a reason, lasts at most an hour, and has no approvers.

```yaml
kind: role
version: v1
metadata: { name: prod-ssh-emergency }
spec:
  break_glass: true
  allow: [ ... ]
  request: { who: [developers] }
```

`notify_observed: true` on any role tells people on its SSH sessions that an administrator may watch them ([watching a live session](watching-sessions.md)).

## Asking, approving, using

```sh
limen ls                                   # shows what you can ask for, with no address
limen request orders-prod --for 30m --reason "INC-123: orders table is locked" --wait
limen requests                             # yours
limen requests --approvals                 # waiting for you to decide
limen approve <id> -m "ok for 30 minutes"  # or: limen deny <id> -m "use staging"
limen cancel <id>                          # withdraw your own pending request
limen request web-prod --break-glass --for 20m --reason "prod is down"
limen explain orders-prod                  # why you can't reach it, and what to do
```

In the console, **Access** has the same: *Ask for access*, *My requests*, *Waiting for me* (the approvals queue), and for admins and auditors *Active grants* and *Everyone's requests*. Resources you can ask for have a **Request access** button on their page. An approver sees the reason, the duration, and **what the requester did on that resource in the past 30 days**.

The grant starts within about 20 seconds of approval: proxies and workers refresh their signed policy snapshot every 10 seconds each.

## The rules that make it safe

- **Eligible is not granted.** Every enforcement point still denies; a request is a row, not a session.
- **A grant is scoped to one resource** and to the role asked for. Approving "orders-prod for 30 minutes" cannot open other databases that the same role selects.
- **Approval happens only in a signed-in Limen session.** Webhooks and Slack notify and link to the console; they never carry an approval.
- **Separation of duties.** You can never decide your own request (the code refuses, and so does a database trigger). Two approvals need two different people. Approver group membership is checked when they decide, using the groups the IdP reported at their latest login, not when the request was made. The requester must still be allowed to ask.
- **A lock always wins** over a grant. So does a [deny override](access-reviews.md).
- **Expiry is enforced three times:** the signed snapshot drops expired grants, the proxy and worker check the deadline on every decision, and a session started under a grant is capped to the grant's remaining time and ends when the grant is revoked.
- **Revoking ends the sessions the grant allowed:** `limen admin revoke-grant <id> --reason ...` (admins). They end within about 10 seconds.
- **Pending requests lapse** after 24 hours. One person can have 20 pending requests and make 100 in a day.
- **Bots cannot request.** Give a bot the role in its `bot` document.
- **People who only take part in requests can sign in with no roles**: if their groups appear in `request.who` or `request.approvers`, they log in holding nothing and reach nothing until a request is approved.

The reason is plain text: it is escaped everywhere it is shown and never reaches a shell or a query.

## Notifications

Configure one or more on the control plane:

| Flag | Sends |
|---|---|
| `--notify-webhook-url` and `--notify-webhook-secret` | a JSON POST signed with `X-Limen-Signature: sha256=HMAC(secret, timestamp "." body)` and `X-Limen-Timestamp` |
| `--notify-slack-url` | a Slack incoming-webhook message |
| `--break-glass-slack-url`, `--break-glass-webhook-url` | break-glass grants only, in addition to the above, flagged critical |
| `--notify-include-details` | add the requester, role, resource, and reason (off by default) |

By default a message names the request id and a console link only, so resource names do not leave Limen. URLs must be `https` (or `http` to localhost for development); redirects are not followed; delivery is best effort with retries and never blocks the request.

## Audit

`access.request`, `access.approve`, `access.deny`, `access.grant`, `access.revoke`, `access.expire`, `access.cancel`, and `access.break_glass`. Every session started under a grant carries `request_ids` in `session.start`, and the session page links to the request.

Metrics: `limen_access_requests_total`, `limen_access_decisions_total`, `limen_access_grants_total`, `limen_notifications_total`. The console dashboards show requests by outcome, time to approve, and grants by role.

## Not built

Automatic approval from an open incident, the on-call rota, or a ticket's state (the approver interface is shaped to allow it); a signed Slack approval button.
