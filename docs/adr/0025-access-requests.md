# ADR-0025: Access requests and just-in-time approval

- Status: Proposed (owner requested 2026-10-14; priority: **must have**)
- Date: 2026-10-14

## Context
Today access is standing: if a role maps to your groups, you can reach its resources whenever you like. The design (ADR-0008) reserved `Decision::RequiresApproval` and every enforcement point already treats it as deny, with tests. The goal now is access that **exists only when someone asked for it, for a stated reason, for a limited time**: "I need `orders-prod` for 30 minutes because of incident 123."

## Decision
- **Eligible is not granted.** A role can declare that it is *requestable* instead of (or as well as) being mapped to groups:
  ```yaml
  kind: role
  version: v1
  metadata: { name: prod-db-readonly }
  spec:
    allow: [ ... ]
    request:
      who: [developers]            # groups that may ask for this role
      approvers: [sre-leads]       # groups or users who may approve
      approvals_required: 1
      max_duration: 2h
      require_reason: true
      ticket_pattern: '^(INC|OPS)-\d+$'   # optional: the reason must carry a ticket id
    break_glass: false
  ```
  A resource reachable only through an eligible role evaluates to `RequiresApproval`. Every enforcement point still denies, and `limen ls` shows the resource with a "request access" hint instead of hiding it (a *hint*, never the target address).
- **A request is a row, not a session.** `limen request <resource> --for 30m --reason "INC-123"` (or the console) creates `access_requests`. Approvers are notified, and approve or deny in the console or with `limen admin approve|deny <id>`. **Approval happens only inside an authenticated Limen session.** Slack, e-mail, and webhooks notify and link to the console; they never carry the approval, so the approver's identity is always proven by the IdP login. (A signed Slack approval button is a later option, if the signature and identity mapping can be made as strong.)
- **Approval creates a grant.** An approved request becomes a time-boxed `access_grants` row (user, role, expiry, request id, approvers). The signed policy snapshot carries active grants, like locks and kills, so proxies and workers enforce them with no round trip. Certificates issued to the user include the granted roles with a TTL no longer than the grant. **A grant can be revoked** at any time (it ends open sessions, using the kill path). A **lock always wins** over a grant.
- **Separation of duties.** The requester can never approve their own request. The approver's group membership is checked at approval time, not at request time. Pending requests expire (default 24 h). `approvals_required: 2` needs two *different* approvers.
- **Break-glass** (`break_glass: true`) grants at once but requires a reason, notifies a configured channel, is limited to 1 hour, and emits `access.break_glass`; the console lists active break-glass grants prominently and reviews them (ADR-0029) always include them.
- **Audit.** New events: `access.request`, `access.approve`, `access.deny`, `access.grant`, `access.revoke`, `access.expire`, `access.break_glass`. Every session started under a grant carries `request_id`, so a recording links back to *why it was allowed*. The console shows the justification next to the session.
- **Console and CLI.** Console: my requests, an approvals queue (for approvers), active grants (for admins), and a dashboard panel (requests, time to approve, grants by role). CLI: `limen request`, `limen requests`, `limen admin approve|deny|revoke-grant`.
- **Notifications** go through a small notifier interface: a generic signed webhook first, Slack second. Contents are configurable so resource names don't have to leave Limen.
- **Storage:** `access_requests`, `access_approvals`, `access_grants` (migration). The snapshot gains `grants`.

## Threats this design has to survive
- **Self-approval through a second account or a shared group:** approvers must be distinct users; policy validation warns when `who` and `approvers` overlap; the audit trail shows both identities.
- **Approver fatigue and rubber-stamping:** the approval view shows the reason, the resource, the duration, and what the requester did in the past 30 days; dashboards show approval time and the share approved without comment.
- **Group changes mid-flight** (an approver leaves the group): re-checked at approval time; grants are not extended when groups change.
- **Stale access:** grants expire on their own; the snapshot drops them; expiry is enforced at the proxy too, not only at certificate issuance.
- **Injection through the reason text:** escaped everywhere it is rendered; length-limited; never used in a shell or a query.
- **Notification leaks** (resource names in a public channel): fields are configurable, and the default message names the request id and a console link only.

## Consequences
- Policy gains `request` and `break_glass`; the validator learns their rules. `Decision::RequiresApproval` finally has a producer, and the "treated as deny" tests become the safety net for it.
- The snapshot grows with active grants; bounded by their short lifetime.
- Automatic approval from external context (an open incident, the on-call rota, a ticket's state) is deliberately left out of v1; the approver interface is shaped so it can be added.
