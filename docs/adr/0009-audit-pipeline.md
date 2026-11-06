# ADR-0009: Disk spool, at-least-once delivery, S3 hash chain, Datadog

- Status: Accepted (owner approved 2026-10-13)
- Date: 2026-10-13

## Decision
- **Envelope v1** (`limen_audit::Event`). The envelope and kind-specific `data` are defined in `crates/limen-audit/src/lib.rs` (`SCHEMA_VERSION`). A standalone JSON Schema file is not published yet. Any breaking change bumps `schema_version`, and the Glue table supports both versions.
- **Producers**: proxy, worker, and control plane. Each writes to its own **local segmented spool**: append-only files, `u32 len | u32 crc32c | payload` framing, group-commit fsync every 50 ms or 256 events, a durable consumer offset, and 64 MiB segments deleted after ack. The spool's max size and high-water mark are configurable.
- **Transport**: producers stream batches to control plane ingest (gRPC, through the proxy for workers). The control plane acks only after its own spool has fsynced. Producers retry until ack, so delivery is **at-least-once**. Consumers deduplicate on `event_id`.
- **Sinks** (control plane, leader per shard):
  - **S3**: JSONL.gz batches with SSE-KMS and optional Object Lock. Each batch gets a signed manifest that chains `prev_manifest_sha256` per writer instance. `limen admin audit verify` walks the chain.
  - **Datadog**: Logs HTTP intake.

  Each sink has its own offset, so a Datadog outage doesn't hold back S3 and vice versa.
- **Failure mode** `fail_closed` (default) or `degrade`. Exact semantics are in design §8.
- **Spool storage choice:** a custom segmented log rather than `redb`. The access pattern is pure append plus sequential read, it's easy to reason about crash safety, and there's no B-tree overhead. `redb` (actively maintained, 4.x) is the fallback if the custom log turns out to be harder than expected.
- **Parquet deferred.** JSONL with the Glue JSON SerDe and partition projection is enough at the target scale. The schema stays flat enough to convert later.

## Consequences
- \+ No single event loss on crash after the local fsync. Sink outages are absorbed up to the spool size.
- − Duplicates are possible. Athena views dedupe, and Datadog may show rare duplicates.
- *Tested in Phase 3:* kill -9 the producer mid-batch, break S3 (SeaweedFS), break the fake Datadog intake, and verify that the set of event IDs equals the set of IDs emitted.

## Amendment (Phase 3, 2026-10-14)
- **Framing uses CRC32 via `crc32fast`**, not CRC32C: the `crc32c` crate is unmaintained.
- **Local S3 is SeaweedFS** (`chrislusf/seaweedfs`); MinIO no longer publishes images and LocalStack needs a token. It requires signed requests, which caught a real bug: streamed recording uploads failed against an anonymous server.
- **Manifests** live at `manifests/<writer>/<seq>.json`; the verifier is `limen audit verify` (see the amendment below).
- **Recordings** are uploaded by the worker to the control plane in chunks, not multipart straight from the worker; the proxy never gets S3 access.
- **IAM** (`deploy/terraform/modules/audit`): the control plane can append and read manifests but not delete; Grafana reads events only; the verifier is read-only. The bucket policy denies `DeleteObjectVersion` and non-KMS puts; Object Lock is optional.
- *Unverified against real S3, KMS, Athena, or Datadog.*

## Amendment (2026-11-06): `limen audit verify`, with access that Limen lends
Proposed; awaiting owner approval. It replaces the Phase 3 "for now" separate binary.

- **Decision.** Verification is a subcommand of the one CLI, `limen audit verify`, next to `limen audit search`. The `limen-audit-verify` binary is removed, not aliased. The code moves from `limen-control-plane` into a library crate, `limen-verify`, with no dependency on the control plane or its database. The control plane writes manifests and packs through the types that crate defines, so what it writes and what the verifier reads cannot drift apart.
- **Why.** A second binary to find, install and document made the most important check feel like an afterthought. An auditor needs one tool to search the trail (ADR-0026) and to verify it.
- **Limen decides who may read the bucket; the caller still does the checking.**
  - `limen audit verify` signs in like any other command. The control plane checks the role (`limen:auditor` or `limen:admin`, as for `audit search`), records an `audit.verify_access` event, and only then hands the caller short-lived, read-only credentials for the audit bucket: it assumes the verifier role (the `verifier_policy_json` permissions) and returns the temporary credentials. Nobody holds standing AWS access to the bucket just to check it, and the control plane, not the CLI, knows which bucket it is.
  - The CLI then reads the bucket and checks every signature, hash and chain link **on the caller's machine**, against the CA pinned at `limen login`, never one Limen sends with the data. Limen is not asked whether the trail is fine, so it cannot vouch for itself, and a control plane that withheld access or lied about it could not make a broken chain verify.
  - There is no `--bucket` flag. Which bucket is the operator's decision, set on the control plane (`--audit-s3-bucket`, with `--audit-verifier-role-arn` and optionally `--audit-verifier-s3-endpoint`). The CLI ignores the caller's own AWS credentials.
- **Evidence packs stay open.** `limen audit verify --evidence <file> --ca-file <ca>` is offline, needs no login, and works for an auditor or customer with no access to Limen (ADR-0029, ADR-0031). It reveals nothing the pack does not already contain. This is the way for someone outside the organization to check.
- **Behavior is otherwise unchanged:** the same `OK:` / `PROBLEM:` / `GAP:` / `CONFLICT:` lines, and exit code 2 on any problem.
- **Who can run it, in one line.** Admins and auditors, through Limen, for the live trail; anyone, offline, for a pack they hold. A developer gets `permission denied` and the attempt is not recorded as a grant.
- **For S3-compatible stores without STS** (the dev stack): the control plane can hand out one fixed read-only key instead of a role (`--audit-verifier-access-key-id` and `--audit-verifier-secret-access-key`). It does not expire, so it is for development only, and the response says so by carrying no expiry.
- **Consequences.**
  - `limen-cli` gains the S3 client and the manifest code, so the binary is larger.
  - The control plane gains `sts:AssumeRole`, and `aws-sdk-sts` as a direct dependency.
  - The audit Terraform module can create the verifier role (`verifier_trusted_principal_arns`) and outputs `verifier_role_arn` and a policy for the control plane's role.
  - Verifying the live trail now needs a working control plane to get access. If it is down, the stored packs still verify offline, and an operator with their own AWS access can still read the bucket directly with any S3 tool, but not with Limen's verifier.
  - Breaking: `limen-audit-verify` and its `--bucket`, `--prefix`, `--endpoint` and `--path-style` flags are gone. Docs, runbooks, demos, the Terraform description and release packaging drop them.
