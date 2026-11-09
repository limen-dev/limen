# ADR-0047: OCSF audit export for SIEMs

- Status: Proposed (issue #112, `needs: design`). Built in PR #294 at the owner's request with the defaults below; the owner has not yet approved the decisions listed under Open for review, and the status stays Proposed until they do.
- Date: 2026-11-09

## Context
Limen ships audit events to S3 (hash-chained, signed) and Datadog, always in its own envelope (ADR-0009, design §8). A team on Splunk, Sentinel, Chronicle or AWS Security Lake has to write and keep a parser for that envelope and its roughly 55 event kinds before the events are useful. [OCSF](https://schema.ocsf.io) is the vendor-neutral schema those platforms ingest. Issue #112 asks for an OCSF projection as a new sink, with the native format and hash chain staying the source of truth.

## Decision
- **A projection, never a replacement.** A new spool consumer, `ocsf`, reads the same control-plane spool as the S3 and Datadog consumers and writes OCSF JSON events. The native envelope and the S3 chain are unchanged and remain what `limen audit verify` checks. The sink is off unless configured.
- **Pinned schema version.** The sink emits one OCSF version, written into `metadata.version`, chosen in Open for review. The latest stable release at the time of writing is 1.9.0 (2026-08-03), but AWS Security Lake custom sources accept only 1.3 and earlier, so the version and the Security Lake path are linked decisions. A change of version is an ADR amendment, not a silent upgrade.
- **One exhaustive mapping.** `limen-audit` gets a pure function `to_ocsf(&Event) -> serde_json::Value`, a `match` on `EventKind` **with no wildcard arm**: adding an event kind fails to compile until its mapping is chosen. A table-driven test builds one sample of every kind and checks the required OCSF attributes.
- **Carried through on every record.** `metadata.uid` = Limen `event_id`; `metadata.product` names Limen, its version and the producing component; `unmapped.limen` holds `schema_version`, `kind`, `producer{component, instance_id, seq}`, `session_id` and the kind-specific `data` that has no OCSF home. A SIEM user can go from any OCSF record to the native event by `event_id`, and a `producer.seq` gap is still visible.
- **Chain position.** The chain lives in S3 manifests (writer, manifest seq, batch hash). A batch closes at 5 MiB or 60 s, and the OCSF consumer reads the spool independently of the S3 consumer, so it **cannot** know a manifest sequence number when it ships. v1 carries `event_id` and `producer.seq`, and documents that the batch holding an event is found by `event_id`. Carrying the manifest seq would need the sink to run downstream of closed S3 batches; that is an alternative in Open for review.
- **Class mapping.** Class and activity ids are from the OCSF 1.9.0 class pages on schema.ocsf.io and must be re-checked against the pinned version. The full per-kind table is generated from the code into the [guide](../guides/audit-ocsf.md#mapping), and a test fails if they differ. In short:
  - logins, logouts and denied logins are Authentication (3002); session start, end and kill are Network Activity (4001); `ssh.exec` is SSH Activity (4007)
  - `db.*`, `mongo.*` and `redis.*` are Datastore Activity (6005), with the activity from the statement class for `db.query`
  - `search.*` and `web.*` are HTTP Activity (4002), with the activity from the method
  - `kube.*`, `mq.*`, `kafka.*`, `audit.*`, `evidence.export` and `session.recording` are API Activity (6003)
  - policy changes, enrollment, revocation, locks and resource discovery are Entity Management (3004)
  - `access.grant` and `access.break_glass` are Authorize Session (3003, Assign Roles), the one activity that class defines for them; the other `access.*` and `review.*` kinds are Entity Management with *Other* and a readable `activity_name`
  - `policy.shadow_deny`, `policy.write_denied` and `session.watch.*` are Base Event (class 0): an evaluation, a refusal and a watch are not changes to an entity or a network event, so the whole event stays in `unmapped`

  A kind that fits no class well emits a Base Event. Nothing is dropped. Moving a kind to a more specific class later is a visible change to the generated table.
- **Severity.** `severity_id` is Informational by default, Low for refusals (`auth.denied`, `policy.write_denied`), Medium for `policy.shadow_deny`, High for `access.break_glass`. Defaults for review.
- **Secrets.** The projection copies only fields the native event already holds, which never include secrets (design §8), and adds none. Statement redaction (ADR-0033, ADR-0035) applies unchanged. A test asserts that no field named like a secret appears.
- **A projection must not gate the source of truth.** A spool segment is deleted only when every consumer has acked (the spool's minimum offset). A dead SIEM endpoint would hold segments until the spool is full, and a full spool under `audit.failure_mode: fail_closed` refuses logins and sessions, so an unreachable projection would cause an outage. Datadog has the same exposure today. For the OCSF sink v1 proposes a **bounded lag**: if it falls more than a configured amount behind (default 256 MiB of spool; the spool has a high-water mark that only drives `/readyz`, so there is no existing lag mechanism to build on), it skips ahead, counts the loss in `limen_audit_ocsf_skipped_total`, logs it without secrets and alerts, because the events are still in S3 and the other sinks. This is a narrow, loud exception to "nothing is dropped silently", with the native trail intact. Whether Datadog gets the same bound is left for review.
- **Transport (v1).** OCSF as gzipped NDJSON (`<prefix>dt=YYYY-MM-DD/hour=HH/<cp_instance>-<content hash>.jsonl.gz`) in a **separate bucket with its own KMS key** (and its own optional endpoint, `--audit-ocsf-s3-endpoint`), not a prefix of the audit bucket. The control plane refuses to start if the bucket or key is the audit one. The audit key also protects `events/`, `manifests/` and `recordings/` (session output), and read access to that bucket is deliberately gated (`audit.verify_access`, the verifier role in `deploy/terraform/modules/audit`). A standing SIEM reader on it would undercut that. The control plane's S3 write policy is also scoped to `events/*`, `manifests/*` and `recordings/*`, so a new prefix there would need a Terraform change anyway. The SIEM gets a reader role on the OCSF bucket only. Splunk, Sentinel and Chronicle can pull from it or through their forwarders. No new dependency. Rejected for v1: a generic HTTPS push (per-vendor auth and retry behavior we cannot test here) and Security Lake's native format, which needs **Parquet** (a new dependency and an ADR-0012 row), one class per source, and OCSF 1.3 or earlier. Either can be a later amendment.
- **Delivery.** At-least-once like every consumer; duplicates carry the same `metadata.uid`. A retryable error retries the batch. An event that cannot be parsed is wrapped as a Base Event with the raw text in `unmapped`, so this sink never loses it.
- **Documentation.** A guide, `docs/guides/audit-ocsf.md`, with the field mapping per kind generated from the same table the test uses, so it cannot drift, and how to find the native event from an OCSF record.

## Threats this design has to survive
- **The projection hides or alters evidence:** it is read-only over the spool and never feeds the chain. The guide says OCSF is not evidence; the signed S3 chain is.
- **A SIEM outage becomes a Limen outage:** the bounded lag above, with a test that stops the sink and checks the spool still drains for the other consumers.
- **Secrets or statement values reach a SIEM:** no new fields, a secret-name test, the existing redaction.
- **A wrong class or severity misleads detections:** the table is reviewed and covered by fixtures; unknown kinds fall back to Base Event.
- **A SIEM reader can read session recordings:** the OCSF bucket and key are separate from the audit ones, and the reader role has no access to the audit bucket.
- **Schema drift:** the version is pinned and written into every record.

## Consequences
- A new consumer, config flags, metrics, and an OCSF bucket, KMS key, writer policy and reader role in `deploy/terraform/modules/audit`. No change to the native format, chain or verifier.
- A mapping table to edit whenever an event kind is added, enforced by the compiler.
- No dependency added in v1.

## Open for review
- Which OCSF version to pin (1.9.0 current, or 1.3 for Security Lake).
- Whether v1 includes Security Lake (Parquet, one class per source) or defers it.
- S3 NDJSON (separate bucket) versus a generic HTTPS push as the first transport.
- Whether the sink should run downstream of closed S3 batches to carry the manifest sequence number.
- The bounded-lag default, and whether Datadog gets the same bound.
- Whether Limen-specific fields should be an OCSF extension instead of `unmapped`.

## Not verified
- Nothing has been ingested by a SIEM or Security Lake; this is a design. The class and activity ids and Security Lake requirements were read from schema.ocsf.io and the AWS documentation on 2026-11-09 and must be re-checked for the pinned version. The `metadata` object's sub-field types were not read.

## As built
Built for issue #112 in PR #294. Differences from the text above, and what is open:

- **Defaults taken for the owner's open decisions:** OCSF 1.9.0; S3 NDJSON in a separate bucket; no Security Lake; `event_id` and `producer.seq` as the link to the native event (no manifest sequence number); a 256 MiB lag bound for the OCSF sink only (Datadog is unchanged); `unmapped` instead of an OCSF extension.
- **Object keys** are `<prefix>dt=…/hour=…/<control plane id>-<first 32 hex of the SHA-256 of the batch>.jsonl.gz`, so a retry rewrites the same bytes and a wiped spool cannot overwrite an older object.
- **The lag bound** acts only when all three hold: the OCSF send failed, the OCSF consumer has the most records pending of all consumers, and the spool is over `--audit-ocsf-max-lag-bytes`. Then the batch is skipped and counted (`limen_audit_ocsf_skipped_total`). The flag must be below `--audit-spool-max-bytes`.
- **Secret scrub:** fields named like a secret are replaced with `[redacted]` at any depth (`token` is redacted unless the name ends in `_id`, `_sha256` or `_hash`).
- **Terraform:** a new `ocsf` module (bucket, key, writer and reader policies); the audit module is unchanged.
- **Not validated against each class's full schema.** The records carry the base attributes and the class-specific ones that Limen has (`user`, `actor`, `src_endpoint`, `http_request`, `http_response`, `status_id`); required attributes Limen has no value for are absent. A SIEM's first ingest is the test that is still missing, together with Security Lake.
- **Tested** against SeaweedFS (all events arrive with their ids; the audit bucket is untouched and verifies; an outage keeps events and delivers them on return; a blocking outage is skipped and counted), not against a SIEM.

