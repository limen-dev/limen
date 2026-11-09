# ADR-0047: OCSF audit export for SIEMs

- Status: Proposed (issue #112, `needs: design`). Nothing here is approved yet. The OCSF version, transport and lag policy are the owner's to decide (see Open for review); everything else is a default for review.
- Date: 2026-11-09

## Context
Limen ships audit events to S3 (hash-chained, signed) and Datadog, always in its own envelope (ADR-0009, design §8). A team on Splunk, Sentinel, Chronicle or AWS Security Lake has to write and keep a parser for that envelope and its roughly 55 event kinds before the events are useful. [OCSF](https://schema.ocsf.io) is the vendor-neutral schema those platforms ingest. Issue #112 asks for an OCSF projection as a new sink, with the native format and hash chain staying the source of truth.

## Decision
- **A projection, never a replacement.** A new spool consumer, `ocsf`, reads the same control-plane spool as the S3 and Datadog consumers and writes OCSF JSON events. The native envelope and the S3 chain are unchanged and remain what `limen audit verify` checks. The sink is off unless configured.
- **Pinned schema version.** The sink emits one OCSF version, written into `metadata.version`, chosen in Open for review. The latest stable release at the time of writing is 1.9.0 (2026-08-03), but AWS Security Lake custom sources accept only 1.3 and earlier, so the version and the Security Lake path are linked decisions. A change of version is an ADR amendment, not a silent upgrade.
- **One exhaustive mapping.** `limen-audit` gets a pure function `to_ocsf(&Event) -> serde_json::Value`, a `match` on `EventKind` **with no wildcard arm**: adding an event kind fails to compile until its mapping is chosen. A table-driven test builds one sample of every kind and checks the required OCSF attributes.
- **Carried through on every record.** `metadata.uid` = Limen `event_id`; `metadata.product` names Limen, its version and the producing component; `unmapped.limen` holds `schema_version`, `kind`, `producer{component, instance_id, seq}`, `session_id` and the kind-specific `data` that has no OCSF home. A SIEM user can go from any OCSF record to the native event by `event_id`, and a `producer.seq` gap is still visible.
- **Chain position.** The chain lives in S3 manifests (writer, manifest seq, batch hash). A batch closes at 5 MiB or 60 s, and the OCSF consumer reads the spool independently of the S3 consumer, so it **cannot** know a manifest sequence number when it ships. v1 carries `event_id` and `producer.seq`, and documents that the batch holding an event is found by `event_id`. Carrying the manifest seq would need the sink to run downstream of closed S3 batches; that is an alternative in Open for review.
- **Class mapping.** Class ids are from the OCSF 1.9.0 schema browser and must be re-checked against the pinned version.

| Limen kinds | OCSF class (uid) | Activity |
|---|---|---|
| `auth.login`, `auth.logout`, `auth.denied` | Authentication (3002) | Logon, Logoff; `auth.denied` is a failed Logon (`status_id` Failure) |
| `session.start`, `session.end`, `session.kill`, `session.watch.start`, `session.watch.stop` | Network Activity (4001) | Open, Close; kill and watch carry the actor in `actor.user` |
| `ssh.exec` | SSH Activity (4007) | Other, command in `unmapped` |
| `db.query`, `db.query.end`, `db.bootstrap`, `mongo.command`, `mongo.command.end`, `redis.command` | Datastore Activity (6005) | Query, Update, Other by statement class |
| `search.request`, `search.response`, `web.request`, `web.response`, `web.websocket` | HTTP Activity (4002) | by method |
| `kube.request`, `mq.operation`, `mq.summary`, `kafka.request`, `kafka.summary` | API Activity (6003) | Create, Read, Update, Delete by verb, else Other |
| `policy.*`, `join_token.create`, `worker.enroll`, `component.revoke`, `user.lock`, `user.unlock`, `resource.*` | Entity Management (3004) | Create, Update, Delete, Other |
| `access.*`, `review.*` | Authorize Session (3003) | request, approve, deny, grant, revoke as the activity; `access.break_glass` has `severity_id` High |
| `audit.search`, `audit.verify_access`, `evidence.export`, `session.recording` | API Activity (6003) | Read, Create |

  A kind that fits no class well emits a **Base Event** (class 0) with the whole native event in `unmapped`. Nothing is dropped. Moving a kind to a more specific class later is a visible change to this table and the fixtures.
- **Severity.** `severity_id` is Informational by default, Low for refusals (`auth.denied`, `policy.write_denied`), Medium for `policy.shadow_deny`, High for `access.break_glass`. Defaults for review.
- **Secrets.** The projection copies only fields the native event already holds, which never include secrets (design §8), and adds none. Statement redaction (ADR-0033, ADR-0035) applies unchanged. A test asserts that no field named like a secret appears.
- **A projection must not gate the source of truth.** A spool segment is deleted only when every consumer has acked (the spool's minimum offset). A dead SIEM endpoint would hold segments until the spool is full, and a full spool under `audit.failure_mode: fail_closed` refuses logins and sessions, so an unreachable projection would cause an outage. Datadog has the same exposure today. For the OCSF sink v1 proposes a **bounded lag**: if it falls more than a configured amount behind (default 256 MiB of spool), it skips ahead, counts the loss in `limen_audit_ocsf_skipped_total`, logs it without secrets and alerts, because the events are still in S3 and the other sinks. This is a narrow, loud exception to "nothing is dropped silently", with the native trail intact. Whether Datadog gets the same bound is left for review.
- **Transport (v1).** OCSF as gzipped NDJSON on a dedicated prefix of the audit bucket (`ocsf/dt=YYYY-MM-DD/hour=HH/<cp_instance>-<batch_seq>.jsonl.gz`), with the same SSE-KMS and client as the S3 sink. Splunk, Sentinel and Chronicle can pull from S3 or through their own forwarders. No new dependency. Rejected for v1: a generic HTTPS push (per-vendor auth and retry behavior we cannot test here) and Security Lake's native format, which needs **Parquet** (a new dependency and an ADR-0012 row), one class per source, and OCSF 1.3 or earlier. Either can be a later amendment.
- **Delivery.** At-least-once like every consumer; duplicates carry the same `metadata.uid`. A retryable error retries the batch. An event that cannot be parsed is wrapped as a Base Event with the raw text in `unmapped`, so this sink never loses it.
- **Documentation.** A guide, `docs/guides/audit-ocsf.md`, with the field mapping per kind generated from the same table the test uses, so it cannot drift, and how to find the native event from an OCSF record.

## Threats this design has to survive
- **The projection hides or alters evidence:** it is read-only over the spool and never feeds the chain. The guide says OCSF is not evidence; the signed S3 chain is.
- **A SIEM outage becomes a Limen outage:** the bounded lag above, with a test that stops the sink and checks the spool still drains for the other consumers.
- **Secrets or statement values reach a SIEM:** no new fields, a secret-name test, the existing redaction.
- **A wrong class or severity misleads detections:** the table is reviewed and covered by fixtures; unknown kinds fall back to Base Event.
- **Schema drift:** the version is pinned and written into every record.

## Consequences
- A new consumer, config flags, metrics and one S3 prefix. No change to the native format, chain or verifier.
- A mapping table to edit whenever an event kind is added, enforced by the compiler.
- No dependency added in v1.

## Open for review
- Which OCSF version to pin (1.9.0 current, or 1.3 for Security Lake).
- Whether v1 includes Security Lake (Parquet, one class per source) or defers it.
- S3 NDJSON versus a generic HTTPS push as the first transport.
- Whether the sink should run downstream of closed S3 batches to carry the manifest sequence number.
- The bounded-lag default, and whether Datadog gets the same bound.
- Whether Limen-specific fields should be an OCSF extension instead of `unmapped`.

## Not verified
- Nothing has been ingested by a SIEM or Security Lake; this is a design. The class ids and Security Lake requirements were read from schema.ocsf.io and the AWS documentation on 2026-11-09 and must be re-checked for the pinned version. The `metadata` object's sub-field types were not read.
