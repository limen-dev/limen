# ADR-0009: Disk spool, at-least-once delivery, S3 hash chain, Datadog

- Status: Accepted (owner approved 2026-10-13)
- Date: 2026-10-13

## Decision
- **Envelope v1** (`limen_audit::Event`). Kind-specific `data` has a JSON Schema in `docs/audit-schema/`. Any breaking change bumps `schema_version`, and the Glue table supports both versions.
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
- **Manifests** live at `manifests/<writer>/<seq>.json`; the verifier is the `limen-audit-verify` binary for now.
- **Recordings** are uploaded by the worker to the control plane in chunks, not multipart straight from the worker; the proxy never gets S3 access.
- **IAM** (`deploy/terraform/modules/audit`): the control plane can append and read manifests but not delete; Grafana reads events only; the verifier is read-only. The bucket policy denies `DeleteObjectVersion` and non-KMS puts; Object Lock is optional.
- *Unverified against real S3, KMS, Athena, or Datadog.*
