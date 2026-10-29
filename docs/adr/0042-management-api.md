# ADR-0042: One management API for the CLI, the console, and infrastructure as code

- Status: Proposed (owner asked for the proposal on 2026-10-29; Phase 15)
- Date: 2026-10-29

## Context
Everything Limen manages (roles, role mappings, resources, bots, discovery rules, policy tests) is a policy document, applied with `limen admin apply` (ADR-0008). `Admin.ApplyPolicy` replaces the **whole** active policy with the documents it is sent. That works when one Git repository owns all of policy, and fails as soon as there is more than one writer:

- **No per-document writes.** There is no call to create, read, update, or delete one role or resource. `GetPolicyDocuments` returns everything as one JSON blob.
- **No precondition.** `ApplyPolicyRequest` carries no expected version, so two writers that read, change, and write back lose each other's changes.
- **Writers erase each other.** A Git apply deletes what anyone else created, and the other way round.
- **Automation can't write.** Bots may not hold built-in roles (ADR-0019, `limen-policy/src/bot.rs`), so no pipeline can call the admin API. This is deliberate, and it is why `examples/ci/policy-check.yml` tests and diffs but never applies.
- **Guardrails live in one channel.** `--require-tests` is enforced by the control plane, but "standing access must not widen without a label" exists only in the CI workflow. A change from any other channel skips it.

The owner wants every object Limen manages to be manageable from the CLI, the console, or Terraform. The motivating case: a team's Terraform module creates a database and, in the same plan and its own isolated state, registers it in Limen; a security or platform team manages roles, mappings, and bots from its own Terraform state or Git repository. Issue #73 (the provider) is blocked on this.

## Decision

### 1. One API, three clients
A new gRPC package, **`limen.manage.v1`**, in its own file (`proto/limen/manage/v1/manage.proto`), is the only write path for policy documents. The CLI, the console, and the Terraform provider are all clients of it; none has logic of its own. It is separate from `limen.v1` so the internal component protocols can keep changing while this package makes a compatibility promise: additive changes only, field numbers never reused, a breaking-change check in CI.

Per document kind (`role`, `role_mapping`, `resource`, `bot`, `discovery`, `policy_test`): `Create`, `Get`, `List` (filter by namespace and labels), `Update`, `Delete`. Plus `Plan` (a dry run of any set of writes, returning the effective-access changes, warnings, and test results `ApplyPolicy` already computes) and `ApplySource` (section 2). Every write takes the document's `revision`; a stale revision is refused (`FAILED_PRECONDITION`), never merged. Every successful write still makes a new numbered, signed policy version and a `policy.change` event, so enforcement, snapshots, and audit don't change.

`Admin.ApplyPolicy` stays as a deprecated alias of `ApplySource` for the source `default` until 1.0.

### 2. Every document has exactly one owner
The control plane records, for each document, an **owner**: `{channel, source, namespace}`.

- `channel`: `git` (`limen admin apply`), `console`, `api` (a direct client such as Terraform).
- `source`: who writes it within the channel, e.g. `github.com/acme/limen-policy`, `terraform/payments-prod`. Set by the writer, recorded in audit.
- `namespace`: the permission scope (section 3). It does **not** change names: resource names stay globally unique per kind, so `limen ssh orders-prod` keeps working.

Rules:
- The writer that creates a document owns it. Another owner's write to it is refused with a message naming the owner ("managed by terraform/payments-prod; change it there").
- `ApplySource` (what `limen admin apply --source <name>` calls) replaces the documents owned by *that source* and nothing else. A file that contains a document owned elsewhere is a conflict, not an overwrite.
- Ownership moves only through an explicit, audited **transfer** by a `limen:admin` (the equivalent of `terraform import`), which also covers adopting a discovered resource (ADR-0027).
- The console shows the owner on every document and makes documents owned elsewhere read-only.
- Migration: all existing documents become owned by `{git, default, default}`, and `limen admin apply` without `--source` behaves exactly as today.

### 3. Automation writes through scoped writer grants, never `limen:admin`
A new document kind, **`policy_writer`**, gives one bot the right to write some documents and nothing else:

```yaml
kind: policy_writer
version: v1
metadata: { name: payments-terraform }
spec:
  bot: payments-terraform          # an existing bot (ADR-0019)
  namespaces: [payments]
  kinds: [resource]
  resource:
    labels:                        # labels the writer may set, and their allowed values
      team: [payments]
      env: [dev, staging]
    workers: { network: payments-vpc }   # which workers its resources may name
  widening: preapproved            # see section 4
```

A pipeline logs in as that bot through the existing join (GitHub Actions, GitLab, OIDC), with no long-lived credential, and gets a short certificate that carries no admin role. The control plane checks every write against the grant.

**Escalation rules**, enforced by the validator and the write path, not by convention:
- `policy_writer` documents are written **only by people** holding `limen:admin`, in the `git` or `console` channel. No grant can include the `policy_writer` kind.
- No automated writer assigns a built-in role (`limen:admin`, `limen:auditor`) in a `role_mapping`, or names one in a role.
- No automated writer creates or changes a `bot` whose roles exceed its own bot's, or changes its own bot. Whether automation may write bots at all is an open question (below); the first stage doesn't allow it.
- A writer's namespaces are disjoint from every other writer's unless an admin says otherwise; overlap is a validation warning.

### 4. Guardrails run on the server, for every channel
- `require_tests` becomes a per-namespace setting, enforced on every write, whatever the channel.
- **Widening standing access** (the ADR-0028 diff, already computed) is checked on the server. A writer grant says how it's handled:
  - `preapproved`: the grant's constraints are the approval. This suits resource registrars: adding a resource always widens access, and the allowed labels decide who can reach it.
  - `approval` (default for `role` and `role_mapping`): the write is held as a **pending policy change** that a second person approves in the console or CLI, the way access requests work (ADR-0025). The provider reports the pending change's link and fails, so `terraform apply` doesn't hang, and a rerun after approval succeeds.
- The console and the CLI apply the same rules to people: a person's widening change in a namespace marked `approval` needs another admin.

### 5. Deleting a resource ends what depended on it
Deleting a resource (including `terraform destroy`) ends its open sessions and active grants (ADR-0025) the way a lock does, and the audit event names the owner that deleted it. A resource that still has sessions isn't kept alive by them.

### 6. The Terraform provider is a separate repository, built last
`terraform-provider-limen`: Go with `terraform-plugin-framework`, a thin client of `limen.manage.v1`. It has its own semantic version and documents which server versions it supports. It lives outside this repository because the Terraform and OpenTofu registries expect a repository with that name holding signed releases, because it brings a second toolchain, and because ADR-0024's one-version rule doesn't fit a client with its own release rhythm. Until the repository is public, it is installed with `dev_overrides` or a private mirror. `limen_resource` comes first, then `limen_role`, `limen_role_mapping`, `limen_bot`, and data sources (`limen_resource_access`, which shows who can reach a resource through `who-can`, and `limen_workers`). Plan shows the effective-access changes from `Plan` as warnings.

## Stages (one phase, Phase 15)
1. **Ownership and the API for resources.** Section 1 for `resource`, section 2, section 3 with `kinds: [resource]`, section 5, CLI commands over the new API, the threat-model update, and a demo where two sources and one bot writer share a control plane without touching each other.
2. **Guardrails and the remaining kinds.** Section 4, then `role`, `role_mapping`, `bot`, `discovery`, `policy_test` in the API; the console edits policy documents (until now it browses and dry-runs).
3. **The provider** (#73), in its own repository, against the stage 1 and 2 API.

## Alternatives considered
- **A provider over today's API** (one `limen_policy` resource holding every document). Works now, but one state owns all of policy, so it doesn't serve teams with separate states, and it still needs admin rights in CI.
- **Terraform renders YAML** (`yamlencode` into the policy repository, existing CI applies). No new API, but a team's module would have to commit into another team's repository, and there is no destroy in the same run.
- **Discovery with auto-accept** (teams tag their AWS resources, ADR-0027 accepts trusted tag sets). No provider at all, but AWS only, limited to the kinds discovery knows, not visible in a plan, and eventually consistent. Worth keeping as the zero-code path for AWS users; it doesn't replace the API.
- **A REST API next to gRPC.** Easier for curl and some tools, but a second surface to keep compatible. Not now; gRPC has a good Go client and the CLI already uses it.

## Threats this design has to survive
- **A compromised pipeline** writes what its grant allows and nothing else: it can't reach `policy_writer`, built-in roles, or other namespaces, and widening of standing access outside a preapproved shape waits for a person. Its writes carry the run's CI facts (ADR-0019) in audit, and the bot can be locked.
- **Lost updates between writers:** per-document revisions and source-scoped apply.
- **Confused ownership** (one channel silently reverting another): single owner, refused cross-owner writes, audited transfer.
- **Label smuggling** (a team labels its resource to match a protected role): the grant's allowed label values, and the server-side widening check.
- **Drift between the console and enforcement:** one API, and the console has no write path of its own.
- New entry point: the `limen.manage.v1` service. `docs/threat-model.md` gets its section in stage 1.

## Open questions for the owner
1. Should automation ever write `bot` documents, or are bots always written by people?
2. Namespaces as a field (proposed) or as name prefixes (`payments/orders-db`)? A field keeps names and commands unchanged; a prefix makes ownership visible in every name.
3. Policy version rate: every write is a new signed snapshot. Fine for teams; at hundreds of writes an hour we may need to batch writes into one version. Measure in stage 1.
4. Provider name and owner on the registry once public (`limen/limen`?).

## Consequences
- \+ Every object can be managed from the CLI, the console, or Terraform, with one set of rules.
- \+ Automation gets the narrowest write right that does the job, never admin.
- \+ The existing Git workflow keeps working unchanged (source `default`).
- − More state per document (owner, revision) and a migration.
- − A compatibility promise on `limen.manage.v1` before 1.0, so changes to it need care.
- − Pending policy changes are a new approval flow to build, test, and show in the console.
