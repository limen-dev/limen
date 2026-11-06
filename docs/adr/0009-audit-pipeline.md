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

## Amendment (2026-11-06): the verifier is `limen audit verify`
Proposed; awaiting owner approval. It replaces the Phase 3 "for now" separate binary.

- **Decision.** Verification is a subcommand of the one CLI, `limen audit verify`, next to `limen audit search`. The `limen-audit-verify` binary is removed, not aliased. The code moves from `limen-control-plane` into a library crate, `limen-verify`, that has no dependency on the control plane or the database. The control plane writes manifests and packs through the types that crate defines, so what it writes and what the verifier reads cannot drift apart.
- **Why.** A second binary to find, install and document made the most important check feel like an afterthought. People already have `limen`, and an auditor needs one tool to search the trail (ADR-0026) and to verify it.
- **Behavior is unchanged.** Same flags, same `LIMEN_AUDIT_S3_*` environment variables, same `OK:` / `PROBLEM:` / `GAP:` / `CONFLICT:` lines, exit code 2 on any problem. `--evidence` checks an evidence pack (ADR-0029) offline.
- **Who can run it.** The check must not depend on trusting Limen, so it does not sign in to Limen and asks it nothing. Two modes, two gates:
  - *Bucket mode* reads S3 with the caller's own AWS credentials. Only the read-only verifier policy (`verifier_policy_json` in the audit Terraform module) lets it work; anyone else gets S3's `AccessDenied`, and the command says which policy is missing. A developer has no reason to hold that policy and does not get it by being a developer.
  - *Evidence mode* needs only the evidence file and the internal CA certificate. It is open on purpose: an auditor, a customer or a court checks a pack with no access to Limen (ADR-0029, ADR-0031). Checking a pack discloses nothing the pack does not already contain.
  - A role check in the CLI (`limen:auditor` or `limen:admin`) was rejected: it would run on the client, so it would stop nobody, and it would break offline use. Having the control plane verify its own trail is a possible addition for convenience, but it is Limen vouching for itself, so it would sit next to this check and never replace it.
- **Consequences.** `limen-cli` gains the S3 client and the manifest code as dependencies, so the binary is larger. The compose control-plane image carries `limen` so the demos can run `limen audit verify` beside the control plane. Docs, runbooks, demos, the Terraform description and the release packaging drop the old binary. This is a breaking change for anyone who scripted `limen-audit-verify`.
