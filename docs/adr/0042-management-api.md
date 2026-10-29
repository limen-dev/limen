# ADR-0042: One management API for the CLI, the console, and infrastructure as code

- Status: Proposed, final design (owner asked for it on 2026-10-29; Phase 14). Accepting it closes #171 and opens stage 1.
- Date: 2026-10-29
- Contract: [`proto/limen/manage/v1/manage.proto`](../../proto/limen/manage/v1/manage.proto). The proto is the reference for every message and field; this ADR says why it is shaped that way and what the server must enforce.

## Context
Everything Limen manages (roles, role mappings, resources, bots, discovery rules, policy tests) is a policy document, applied with `limen admin apply` (ADR-0008). `Admin.ApplyPolicy` replaces the **whole** active policy with what it is sent. That works while one Git repository owns all of policy. The owner wants every object to be manageable from the CLI, the console, or Terraform. The motivating case: a team's Terraform module creates a database and, in the same plan and its own isolated state, registers it in Limen, while the security or platform team manages roles, mappings, and bots from its own state or repository. The Terraform provider (#73) is blocked on this.

What stands in the way today:

1. **No per-document writes and no precondition.** No call creates, reads, updates, or deletes one document; `ApplyPolicyRequest` carries no expected version. Two writers that read, change, and write back lose each other's changes, and each writer's apply deletes the other's documents.
2. **Automation can't write.** Bots may not hold built-in roles (ADR-0019, `limen-policy/src/bot.rs`), so no pipeline can call the admin API. This is deliberate and stays.
3. **Guardrails live in one channel.** `--require-tests` is enforced by the control plane, but "standing access must not widen without review" lives only in `examples/ci/policy-check.yml`.
4. **A resource document is powerful.** Beyond an address, a resource names the worker that serves it (`worker_selector`), credentials and files on that worker (`admin_secret_arn`, `password_dir`, `admin_password_file`, `tls_ca_file`), database roles to create (`bootstrap`), IAM behaviour (`iam_auth`, `region`, `cluster_identifier`, `cluster_name`), and audit redaction (`audit.log_values`, `audit.redact_keys`, `normalize_literals`). That is fine while only admins write policy. Handed to a team's pipeline as is, it would let that pipeline borrow another team's credentials through a shared worker, send a file from the worker to an endpoint it controls (the worker reads `admin_password_file` and presents it as a password to the target), reach the cloud metadata endpoint, or switch off redaction. **Delegating resource writes safely needs more than a label check.**
5. **A latent race in `ApplyPolicy`.** The diff, the access changes, the "nothing changed" shortcut, and the audit event's `previous_version` are computed against the replica's in-memory policy, which other replicas' applies reach only on the next 5-second refresh (`jobs.rs`). The insert takes no lock. During that window an apply through a stale replica can report wrong access changes, record a wrong `previous_version`, or skip the apply as "unchanged" while the active policy is different. Rare with one Git pipeline; routine under Terraform's parallel writes. Fixed as stage 1's first step (#182), independent of the rest.

## Decision

### 1. One API, one write path
`limen.manage.v1.ManagementService` is the only way policy changes. Inside the control plane, one module (`policy_store`) implements every write; the gRPC service, the console, and the legacy `Admin.ApplyPolicy` all call it, so no channel can skip a check another channel makes. `ApplyPolicy` becomes `ReplaceSource` for the source `default` (section 3) and stays until 1.0.

The proxy relays only an allow-list of services (`limen-proxy/src/relay.rs`); `/limen.manage.v1.ManagementService/` is added to it. Nothing else about the transport changes: mTLS through the proxy, the caller resolved from the forwarded certificate.

The API is designed for clients that retry and run in parallel:
- **Optimistic concurrency.** Every document has an opaque `etag`. Update, delete, and transfer require it; a stale one is refused with `ETAG_MISMATCH` and the current etag. Nothing is ever merged.
- **Whole-state updates, no field masks.** An update sends the complete desired document. Terraform always knows the whole desired state, and a partial-update API is where "which fields did that clear?" bugs live.
- **Idempotent retries.** `request_id` (a UUID) is remembered per caller for 24 hours: a retry with the same body returns the first result, a different body is refused. `DeleteDocument` takes `allow_missing` for clients that retry deletes.
- **Atomic batches.** `BatchWrite` applies up to 100 writes as one policy version, all or none, so a role and the mapping that uses it land together. `ReplaceSource` is the declarative form for a whole source.
- **Dry runs that are the real thing.** Every write takes `validate_only`, which runs the full path (authorization, validation, profiles, tests, impact) and stops before the commit. It is what `terraform plan` and `limen admin apply --dry-run` call.
- **Consistent paging.** Policy versions are immutable, so a listing is served from the version its first page saw; the page token pins version and filter and grants nothing (every page is authorized again).
- **Errors a program can act on.** gRPC codes plus `google.rpc.ErrorInfo` with a stable `reason` (`ErrorReason`), `BadRequest` field violations for invalid documents, and `RetryInfo` on rate limits. Building them adds `tonic-types` (same project and version as `tonic`), assessed in ADR-0012 in stage 1.

### 2. Typed envelope, JSON spec, one schema
A `Document` is a typed envelope (`kind`, `name`, `description`, `labels`, `ownership`, `etag`, version, times) around `spec_json`: the kind's `spec` in exactly the YAML shape, parsed by the same strict `serde` types as YAML (`deny_unknown_fields`).

The spec is deliberately *not* mirrored in protobuf. There are thirteen target types and every phase adds fields; a second schema would drift from the first, and the two would disagree about defaults (proto3 zero values against `serde` defaults), which is a bug class, not a style choice. Instead the Rust types are the single source: `GetSchema` returns a JSON Schema generated from them (`schemars`, assessed in ADR-0012 in stage 1), published with each release, and the Terraform provider generates its schema from that file. The server returns `spec_json` **normalized** (keys sorted, defaults omitted), so clients compare bytes and Terraform shows no phantom diffs.

### 3. One owner per document
Each document has an owner, `{channel, source, namespace}`.
- `channel` is set by the control plane from how the write arrived: `git` (`limen admin apply`), `console`, or `api`.
- `source` names the writer within the channel (`github.com/acme/limen-policy`, `terraform/payments-prod`). It keeps writers in one namespace from overwriting each other by accident. **It is not a security boundary;** the namespace is.
- `namespace` is the permission scope. It does not change names: names stay unique per kind across the control plane, so `limen ssh orders-prod` keeps working. Squatting is prevented by each writer's name patterns (section 4), not by prefixes.

The creator owns a document. Any other owner's write is refused with `OWNED_ELSEWHERE`, naming the owner, so "managed by terraform/payments-prod; change it there" is the error the console and CLI show. `ReplaceSource` touches only its own source. `TransferDocument` moves ownership: within its namespace a writer may move documents between its sources (for `terraform state mv` between states); anything else, including adopting a discovered resource (ADR-0027), needs a person with `limen:admin`. Every transfer is audited.

**Migration.** Every existing document becomes `{git, default, default}`, and `limen admin apply` without `--source` behaves exactly as today. Nobody's workflow changes until they opt in.

### 4. Writers: scoped grants, never `limen:admin`
A bot gets write access through a `policy_writer` document:

```yaml
kind: policy_writer
version: v1
metadata: { name: payments-terraform }
spec:
  bot: payments-terraform          # an existing bot (ADR-0019)
  namespace: payments              # exactly one
  names: ["payments-*"]            # every document it writes must match
  kinds: [resource, policy_test]   # stage 2 may add role, role_mapping
  profiles: [payments-postgres, payments-ssh]
  max_documents: 200
  approvers: { groups: [security] }   # who may approve its held changes, besides admins
```

A pipeline logs in as that bot with the existing workload-identity join and gets a certificate of at most an hour, with no admin role. Every write is checked against the grant, and refusals say which rule failed (`OUTSIDE_GRANT`, `rule = namespace | name_pattern | kind | profile | label | field`).

**People-only kinds.** `bot`, `discovery`, `resource_profile`, and `policy_writer` are written only by people with `limen:admin`, through `git` or `console`. No grant can name them. This closes the loops: a writer can't widen its own grant, mint a bot, or point discovery at an account.

**Escalation rules**, enforced in `policy_store`, not by convention:
- No writer assigns or names a built-in role (`limen:admin`, `limen:auditor`), in a mapping or a role.
- In stage 2, a writer may write roles and mappings only in its namespace, and any widening of standing access they cause is held for approval (section 6), always, whatever its grant says.
- Namespaces of different writers are disjoint unless an admin overlaps them on purpose (a validation warning).
- `policy_test` documents a writer owns run like anyone's, but a writer can't delete tests it doesn't own, so it can't remove the test that would stop it.

### 5. Resource profiles: delegation that is safe by construction
A writer never writes a full resource. It **completes a profile** that a person wrote:

```yaml
kind: resource_profile
version: v1
metadata: { name: payments-postgres }
spec:
  template:                        # fixed: the writer can't change any of this
    postgres:
      iam_auth: true
      region: eu-west-1
      tls_ca_file: /etc/limen/rds-ca.pem
    worker_selector: { network: payments-vpc }
  settable:                        # the only fields a writer may set, and their bounds
    postgres.endpoint:
      hosts: ["*.c9xk2p.eu-west-1.rds.amazonaws.com"]   # this account's RDS, not all of AWS
      ports: [5432]
    postgres.default_database: {}
  labels:
    fixed: { team: payments }
    allowed: { env: [dev, staging] }
```

With Terraform: `limen_resource { name = "payments-orders-db", profile = "payments-postgres", spec = { postgres = { endpoint = aws_db_instance.orders.endpoint } }, labels = { env = "staging" } }`.

The design has three layers, so one sloppy profile can't open what the code forbids:

1. **A ceiling in code.** `limen-policy` holds the list of fields that can *ever* be settable: target addresses and endpoints, `ssh.host_key`, and `default_database`. Everything else (`worker_selector`, every `*_arn`, `*_file`, and `*_dir`, IAM fields, `kubernetes.cluster_name`, `web.host`, `bootstrap`, `admin_user`, `insecure_dev`, TLS switches, every audit setting) is profile-only. A test walks every field of `ResourceSpec` and fails when a new field isn't classified, so a future field can't become writable by default.
2. **Bounds in the profile.** A settable endpoint needs `hosts` (exact names, or one leading `*.` wildcard) or `cidrs`, plus `ports`; an unbounded settable endpoint is a validation error. Labels are fixed or chosen from allowed values. The bounds are the admin's statement of which targets the team owns, so they must be as narrow as the team's own hosts or subnets: with an IAM template, a pattern that also covers another team's database lets the worker mint tokens for it. `limen policy` lints patterns that cover a whole cloud domain.
3. **A guard at the worker.** The snapshot marks a resource that came from a profile as *delegated* and carries its bounds. When connecting, the worker resolves the name and refuses loopback, link-local, unspecified, multicast, and cloud metadata addresses (`169.254.0.0/16`, `fd00:ec2::254`, `fe80::/10`), and any address outside the profile's `cidrs` when it has some. The check is on the address actually dialed, so DNS rebinding doesn't get around it.

Creating a resource from a profile counts as **preapproved**: the profile, its label bounds, and the roles that select those labels are the review. That is what lets a team's pipeline register a database in the same apply that creates it, without waiting for anyone.

### 6. Guardrails on the server, for every channel
- **Tests.** When the active policy has `policy_test` documents, every write must keep them passing. `--policy-tests=advisory|required` (control plane flag, default `advisory`, so upgrades change nothing) decides whether a failure refuses the write (`TESTS_FAILED`) or is reported in `Impact`. `required` is recommended and documented; `apply --require-tests` keeps working.
- **Widening of standing access** is computed on the server for every write (the ADR-0028 engine, already in `ApplyPolicy`). `--widening-approval=writers|all` (default `writers`):
  - `writers`: a bot writer's widening change is **held** as a pending `PolicyChange`, except resource creation from a profile (section 5). People's applies go through as today, with `widens_standing_access` in the audit event.
  - `all`: a person's widening change needs a second admin too.
- **Pending changes.** A held change records the writes, the impact, the base version, the reason, and the bot's CI facts. It is approved or rejected by a person: an admin, or a member of the grant's `approvers`. **Never its author**, and never a person whose Limen name equals the CI account that started the run (`actor` on GitHub, `user_login` on GitLab), so pushing a commit and approving its result takes two people. The approver always sees that CI account. *Limen has no mapping between IdP and CI accounts, so someone whose names differ on the two can approve their own run's change; that residual is in the threat model.* Approval validates the change again on the current policy; if a document it touches changed since it was made, it becomes `SUPERSEDED` instead of applying something nobody reviewed. Changes expire after 7 days.
- The Terraform provider sets `fail_if_approval_needed` in plan and reports the pending change's link at apply, so a run fails clearly instead of hanging; rerunning after approval finds the document in place.

### 7. Deleting a resource ends what depended on it
Deleting a resource (including `terraform destroy`) ends its open sessions and active grants (ADR-0025), the way a lock does, and the audit event names the owner. Deleting a profile or bot that is still used is refused (`IN_USE`).

### 8. Consistency: one writer at a time, against the database
Every write takes a transaction-scoped advisory lock (`pg_advisory_xact_lock`), reads the latest version **inside** the transaction, and computes etags, diffs, tests, impact, and the audit event against that. The in-memory policy is never the base of a write; a replica refreshes its copy from the commit it just made. This fixes the race in Context item 5 and makes etags meaningful across replicas. Writes are short (parse, check, insert); at Terraform scale the lock is not a bottleneck, and if it ever is, it can become per-namespace.

### 9. Storage that grows with changes, not with versions
`policy_versions.documents` stores the whole document set per version: 1,000 documents of 10 KB is 10 MB per version, and a busy Terraform estate makes hundreds of versions a day. Stage 1 stores document bodies once, by digest (`policy_documents`), and gives each version a **manifest** of `kind/name → digest` (about 80 bytes per document), plus ownership and etags in `policy_document_heads`. A one-document change then costs one body and one manifest. Old rows stay readable; the snapshot format sent to proxies and workers is unchanged. `request_id` results live in `policy_requests` for 24 hours.

### 10. Limits
Per writer: `max_documents` (default 200), and writes rate-limited per principal (default 60 a minute, bursts of 20, `RATE_LIMITED` with `RetryInfo`), using the `governor` limiters already in the control plane. Per request: 1 MiB total (as `ApplyPolicy`), 100 writes per batch, page sizes capped (500 documents, 200 changes or versions). Impact lists stop at 500 changes and say so.

### 11. Audit
Writes are audited before commit, and a write whose event can't be recorded is not made (`AUDIT_UNAVAILABLE`, safe to retry with the same `request_id`), as `ApplyPolicy` does today. Events:
- `policy.change`, extended with `channel`, `source`, `namespace`, `writer` (the grant), and the bot's `ci` facts;
- `policy.write_denied` for a writer refused by its grant or the escalation rules: a pipeline probing outside its grant is a detection signal, so it is recorded (rate-limited per principal), and the write is refused whether or not the event is recorded;
- `policy.change_pending`, `policy.change_decided` (approved, rejected, superseded, expired, cancelled), and `policy.ownership_transfer`.

Dry runs and reads are not audited, as today.

### 12. Compatibility
`limen.manage.v1` is a promise: additive changes only, field numbers and names never reused or renamed. CI runs `buf lint` (the STANDARD and COMMENTS rules: every message, field, and RPC is documented) and `buf breaking` with the strictest `FILE` rules against the base of each pull request (`proto/buf.yaml`, `ci-rust.yml`). The Go provider compiles against generated names, so a rename breaks it even when the wire format doesn't. Before 1.0, a break the owner accepts goes through with the `api-breaking-approved` label and an upgrade note in the release (ADR-0024). The internal `limen.v1` package is not held to this.

### 13. Clients
- **CLI.** `limen admin apply --source <name>` (`ReplaceSource`) and `limen policy get|ls|create|update|delete|transfer`; `limen policy changes ls|show|approve|reject`.
- **Console.** Edits documents through `policy_store`, shows every document's owner, and makes documents owned elsewhere read-only. Pending changes are approved there, next to access requests.
- **Terraform provider** (#73): a separate repository, [`limen-dev/terraform-provider-limen`](https://github.com/limen-dev/terraform-provider-limen), in Go with `terraform-plugin-framework`, generated from the published schema, with its own version and a stated range of supported servers. It logs in as a bot when it is configured. Limits to state in its docs, from the bot design (ADR-0019):
  - **Plans in pull requests can't reach Limen**: pull request runs never match a bot, by design. A PR plan runs offline (it validates against the published schema) and the protected-branch run does the online plan and apply.
  - **Token freshness.** Logins need a workload token at most 15 minutes old (`--bot-max-token-age`), and the certificate lasts at most an hour. GitHub Actions mints tokens on demand. *Platforms that issue one token per run (Terraform Cloud's workload identity) need the provider to log in at configure time, and an apply longer than the bot's lifetime fails its later writes. Unverified against Terraform Cloud.*

## Stages (Phase 14)
1. **Foundations and resources.** The `ApplyPolicy` race fix (#182); `policy_store`, versioned storage, and idempotency (#183); ownership and `ReplaceSource` (#172); the API for resources and the CLI (#173); `policy_writer` (#174); resource profiles and the worker guard (#184); resource deletion ending sessions (#175); the threat model and demo (#176).
2. **Guardrails and the other kinds.** Server-side tests and widening approval with pending changes (#177); the API for roles, mappings, bots, discovery, and tests (#178); console editing (#179).
3. **The provider** (#73), in its own repository.

## Answers to the proposal's open questions
1. **Does automation ever write bots?** No. `bot`, `discovery`, `resource_profile`, and `policy_writer` are people-only (section 4).
2. **Namespace as a field or a name prefix?** A field, so names and commands don't change, plus name patterns per writer to prevent squatting (section 3).
3. **Policy version rate.** One version per write or batch. Storage is made proportional to changes (section 9) and writes are rate-limited (section 10). Snapshot distribution is unchanged; measured in the stage 1 demo.
4. **Registry name.** The GitHub organization `limen-dev` (free plan, created 2026-10-29) owns the provider: repository `limen-dev/terraform-provider-limen`, source address `limen-dev/limen`. Limen itself moves there before its first public release, so image and module paths don't change after users depend on them.

## Alternatives considered
- **A provider over today's API** (one `limen_policy` resource holding every document): one state would own all of policy, and CI would need `limen:admin`.
- **Terraform renders YAML** into the policy repository: a team's module would commit into another team's repository, with no destroy in the same run.
- **Discovery with auto-accept** for tagged AWS resources (ADR-0027): no provider at all, and worth keeping as the zero-code path for AWS, but AWS only, not in a plan, eventually consistent.
- **The spec mirrored in protobuf messages**: rejected in section 2 (two schemas, two sets of defaults).
- **Field masks for partial updates**: rejected in section 1.
- **Writers with label constraints and full resource specs** (this ADR's first draft): rejected in Context item 4; profiles replace it.
- **A REST API next to gRPC**: a second surface to keep compatible. Not now.

## Threats this design has to survive
The full table is in `docs/threat-model.md` (TB13). In short:
- **A compromised pipeline** can do what its grant and profiles allow and no more: no people-only kinds, no built-in roles, no other namespace, no profile-only fields, no widening without a person, no approving its own change. Its writes carry the run's CI facts and the bot can be locked.
- **Confused deputy through the worker**: credentials, files, IAM, and the worker choice are profile-only, behind a code ceiling and a connect-time guard.
- **Lost updates and silent overwrites**: etags, one owner, source-scoped replace, writes serialized against the database.
- **Approval bypass**: approvers are people other than the author and (by name) the run's CI account, and approval re-validates. Residual: different names on the IdP and the CI platform.
- **Growth and flooding**: quotas, rate limits, change-proportional storage, bounded requests and lists.

## Consequences
- \+ Every object can be managed from the CLI, the console, or Terraform, with one set of rules and one implementation.
- \+ Automation gets the narrowest right that does the job, never admin; resource delegation is safe by construction.
- \+ The existing Git workflow keeps working unchanged (source `default`), and a latent race is fixed for it too.
- − A compatibility promise before 1.0, enforced in CI.
- − New state (heads, bodies, manifests, requests, pending changes), a migration, and two new kinds to document.
- − Two new dependencies to assess in stage 1 (`tonic-types`, `schemars`) and one tool added now (`buf`, ADR-0012).
