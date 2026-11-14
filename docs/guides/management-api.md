# The management API, for client authors

`limen.manage.v1.ManagementService` ([ADR-0042](../adr/0042-management-api.md)) is how the CLI, the console and the Terraform provider ([`limen-dev/terraform-provider-limen`](https://github.com/limen-dev/terraform-provider-limen)) read and write policy. This page is for whoever writes a client. The contract is [`proto/limen/manage/v1/manage.proto`](../../proto/limen/manage/v1/manage.proto), where every message and field is documented; CI refuses breaking changes to it. Each kind's `spec` is described in the [policy reference](../policy.md).

Served now: reads and writes of **every document kind** (create, update, delete, batch, replace a source, transfer), **changes held for approval** (get, list, approve, reject, cancel), and `GetSchema`, which returns the JSON Schema of a kind's `spec` (`limen manage schema <kind>`). The schema is generated from the types the control plane parses with, and the same files are committed in [`docs/policy-schema/`](../policy-schema/) for clients that can't reach a server, such as a plan in a pull request. A writer's half of a resource from a profile is only part of a spec and may lack fields the schema requires, so validate `effective_spec_json` instead. Each field is described in the [policy reference](../policy.md).

## Who can call it

- A **person** with `limen:admin`: any kind, any namespace. `bot`, `discovery`, `resource_profile` and `policy_writer` are written only by people, so a client managing them logs in as a person (`limen login`), not a bot.
- A **bot** with a `policy_writer` grant ([policy reference](../policy.md#delegated-writes-resource_profile-and-policy_writer)): only the kinds the grant names (`resource`, `role`, `role_mapping`, `policy_test`), only in its namespace, only with names its patterns allow. Pipelines use this; it never needs `limen:admin`.
  - A resource completes a profile the grant names.
  - A role is never built-in, requestable or break-glass.
  - A mapping assigns only roles the writer's namespace owns, never a built-in role.
  - A writer can't touch documents it doesn't own, tests included.
  - Standing access arising from the writer's own roles and mappings waits for a person (below), whatever order they were written in.

Anyone else gets `PERMISSION_DENIED`.

## Connecting

1. **TLS to the proxy**, at the address the CLI uses: TLS 1.2 or 1.3, ALPN `h2`, server name the proxy's host. Trust the CA the operator gives you (dev stack: `deploy/compose/.state/internal-ca.pem`, or `.state/<project>/internal-ca.pem` for a demo's own stack). The proxy relays `/limen.manage.v1.ManagementService/` to the control plane; proxies older than Phase 14 don't, so upgrade them first.
2. **Log in as the bot**, unauthenticated, on the same setup:
   - `limen.v1.Auth/GetAuthConfig` returns `bot_audience` (default `limen`).
   - Get a workload identity token **for that audience** from the CI platform. On GitHub Actions: `$ACTIONS_ID_TOKEN_REQUEST_URL&audience=<bot_audience>` with `Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN`. It must be at most 15 minutes old and works once.
   - Generate an **ECDSA P-256** key locally (it never leaves the machine) and a DER-encoded PKCS#10 CSR for it.
   - `limen.v1.Auth/BotLogin { method: "github_actions" | "gitlab" | "oidc", token, csr_der, bot: "" }` returns `cert_pem` and `expires_at_unix` (at most an hour; no refresh: log in again with a new token).
3. **Call the API** on a new connection with `cert_pem` and the key as the TLS client certificate.

`limen login --bot github_actions` does steps 1–2 (`crates/limen-cli/src/commands/bot.rs`) and `limen admin manage ...` (the older `limen manage ...` still works, hidden from the menu) does step 3; read them as a reference implementation.

## Mapping a Terraform resource

Each Terraform resource is one document: `limen_resource`, `limen_role`, `limen_role_mapping`, `limen_policy_test`, `limen_bot`, `limen_discovery`, `limen_resource_profile`, `limen_policy_writer`. Keep `kind`, `name`, `etag` and the `ownership` you wrote with in state. `spec_json` is the document's `spec` as JSON, same fields as YAML: an object for every kind except `role_mapping`, whose spec is a list of `{idp_group, roles}`. `profile` is for resources only.

| Terraform | Call | Notes |
|---|---|---|
| plan | the same write with `WriteOptions.validate_only = true` | Runs every check and returns the impact (who gains access); changes nothing. A refused plan is audited. |
| create | `CreateDocument { document, ownership: { source, namespace }, options: { request_id } }` | `document.profile` is required for a bot; `spec_json` holds only the profile's settable fields, in the resource's shape, such as `{"postgres":{"endpoint":"db.internal:5432"}}`. |
| read / refresh | `GetDocument { kind, name }` | `NOT_FOUND`: it's gone (or never yours to see); remove it from state. |
| update | `UpdateDocument { document, etag, ownership }` | The whole desired state; no partial updates. A stale etag is `ETAG_MISMATCH`: read again and re-plan. |
| delete | `DeleteDocument { kind, name, etag, ownership }` | `allow_missing: true` for a retry. Deleting ends the resource's open sessions and grants. |
| import | `GetDocument`, then keep its `ownership` | A document another owner manages can't be written; `TransferDocument` moves one between a writer's own sources. |

- **Drift:** compare `spec_json` and `labels` with what you sent; they are exactly what you wrote (`spec_json` keys sorted). The profile's fixed half is in `effective_spec_json` and `effective_labels`, so it never shows as drift.
- **Past versions:** `GetDocument { policy_version }` reads a document as an earlier policy version had it (`limen manage get --policy-version N`). If its current revision was already there, it comes in full. An older revision comes as that version stored it, to admins only: the effective document and the version it first appeared in, with no owner or etag, since those are kept for current revisions only.
- **Retries:** send a fresh UUID `request_id` per operation, and the same one when retrying. A repeat returns the first result; the same id with a different body is `REQUEST_ID_REUSED`.
- **`ownership.source`** names your writer, such as `terraform/<workspace>`. Use different sources for two states in one namespace; writing a document another source manages is `OWNED_ELSEWHERE`.
- **Pull request plans can't log in:** a pull request run never matches a bot (ADR-0019). Plan online on the protected branch; validate offline in pull requests.

## Changes held for approval

A write that widens **standing** access (someone reaches something they couldn't, without asking) can be held for a person instead of applied ([ADR-0042 §6](../adr/0042-management-api.md)):

- A bot writer's write is held unless it only creates or updates resources from its profiles. The grant's bounds are that approval.
- With the control plane's `--widening-approval=all`, a person's write is held too, and a second admin approves it. `limen admin apply` prints the held change's id.

A held write returns `WRITE_OUTCOME_PENDING_APPROVAL` with the change in `pending_change`, and nothing is applied. A client that can't wait (a Terraform plan) sets `fail_if_approval_needed` (with `validate_only`) and gets `APPROVAL_REQUIRED`. A dry run without it returns `VALIDATED` with a warning that applying will wait for approval.

People decide: `ApproveChange` or `RejectChange` (a note is required), `limen manage changes approve|deny <id>` (`reject` still works), or the console's **Policy changes** page. Deciders are admins and members of the writer grant's `approvers.groups`. Bots never decide. Neither the author nor whoever started the CI run (`actor` on GitHub, `user_login` on GitLab) can decide a change. The author withdraws it with `CancelChange`.

Approval writes again on the **current** policy, as the author, re-checking the grant. The change becomes `SUPERSEDED` instead if a document it touches changed, it no longer fits the grant, or it would now give standing access the approver didn't see in the impact.

Changes expire after 7 days (`--policy-change-ttl`); decided ones stay readable for 90 days (their audit events stay in the trail). A client that sees `PENDING_APPROVAL` reports the change id and stops; run it again after approval and it finds the documents in place.

**Tests.** With `--policy-tests=required`, a write that makes any `policy_test` fail is refused (`TESTS_FAILED`) on every channel. The default, `advisory`, only reports results in `Impact.tests`.

## Errors

Every refusal has a gRPC code and a `google.rpc.ErrorInfo` detail (domain `manage.limen.dev`) whose `reason` is an `ErrorReason` name without its prefix. Match on the reason, never the message. `NOT_FOUND` and `ALREADY_EXISTS` carry no detail.

| Reason | Code | What to do |
|---|---|---|
| `OUTSIDE_GRANT` | `PERMISSION_DENIED` | `metadata.rule` says which: `namespace`, `name_pattern`, `kind`, `profile`, `field` (not settable by the profile, outside its bounds, or a requestable or break-glass role), `label`, `builtin_role` (a `limen:*` role), `role` (a mapping to a role the namespace doesn't own), `grant` (the grant is gone). Not retryable. |
| `ETAG_MISMATCH` | `FAILED_PRECONDITION` | `metadata.current_etag`. Read and re-plan. |
| `OWNED_ELSEWHERE` | `FAILED_PRECONDITION` | `metadata.channel`, `source`, `namespace` name the owner. |
| `INVALID_DOCUMENT` | `INVALID_ARGUMENT` | The document doesn't validate. |
| `IN_USE` | `FAILED_PRECONDITION` | A profile still has resources. |
| `QUOTA_EXCEEDED` | `RESOURCE_EXHAUSTED` | The grant's `max_documents`. |
| `RATE_LIMITED` | `RESOURCE_EXHAUSTED` | Wait for the `RetryInfo` delay. |
| `REQUEST_ID_REUSED` | `INVALID_ARGUMENT` | Use a new id for a new write. |
| `AUDIT_UNAVAILABLE` | `UNAVAILABLE` | Nothing changed; retry with the same `request_id`. |
| `TESTS_FAILED` | `FAILED_PRECONDITION` | `--policy-tests=required` and the write breaks a test; the message lists the cases. |
| `APPROVAL_REQUIRED` | `FAILED_PRECONDITION` | `fail_if_approval_needed` was set and the write would be held. |
| `CHANGE_NOT_DECIDABLE` | `FAILED_PRECONDITION` | Not pending (`metadata.state`), another approver is applying it, or you are its author or started its run. |

## Limits

Writes: 60 a minute per principal (bursts of 20). Dry runs: 600 a minute (bursts of 100). A batch: 100 writes. A spec: 256 KiB. A page: up to 500 documents; a listing that outlives a policy change gets `ABORTED` on its next page, so start it again.

## Trying it

`demos/demo-phase14.sh` brings up its own stack (project `limen-phase14`, proxy `localhost:38443`, CA in `deploy/compose/.state/limen-phase14/internal-ca.pem`) with a stand-in CI issuer at `http://localhost:38130` that mints GitHub-shaped tokens (`/github?repository=acme/demo-infra&ref=refs/heads/main&environment=staging&run_id=N`). Run it with `--keep` and point a client at it: the bot `demo-terraform` may write `demo-*` resources from profile `demo-ssh` in namespace `demo-team`. **Unverified** against real GitHub tokens.
