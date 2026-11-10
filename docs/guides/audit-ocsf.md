# OCSF audit export for SIEMs

Limen can write its audit trail in [OCSF](https://schema.ocsf.io) (the Open Cybersecurity Schema Framework) so Splunk, Microsoft Sentinel, Google Chronicle and similar tools can read it without a custom parser. Design and decisions: [ADR-0049](../adr/0049-ocsf-audit-export.md).

**It is a copy, not the record.** The native events, the S3 batches and the signed hash chain ([ADR-0009](../adr/0009-audit-pipeline.md)) stay the source of truth, and `limen audit verify` checks only those. The OCSF files are a projection for people who search in a SIEM. Anyone who needs to *prove* what happened uses the native trail.

## Turn it on

The export writes gzipped NDJSON (one OCSF event per line) to an S3 bucket of its own. Create the bucket with the [`ocsf` Terraform module](../../deploy/terraform/modules/ocsf/README.md), which also outputs the IAM policies, then start the control plane with:

| Flag (environment) | Meaning |
|---|---|
| `--audit-ocsf-s3-bucket` (`LIMEN_AUDIT_OCSF_S3_BUCKET`) | The OCSF bucket. Turns the export on. **Must not be the audit bucket.** |
| `--audit-ocsf-s3-kms-key` (`LIMEN_AUDIT_OCSF_S3_KMS_KEY`) | SSE-KMS key for the objects. **Must not be the audit KMS key.** With the `ocsf` Terraform module this flag is **required and must be the module's `kms_key_arn` output, the full ARN**: the module's bucket policy denies any write that names no key or another one (an alias or a bare key id does not match). |
| `--audit-ocsf-s3-prefix` (`LIMEN_AUDIT_OCSF_S3_PREFIX`) | Key prefix: empty, or ending in `/`. |
| `--audit-ocsf-s3-endpoint` (`LIMEN_AUDIT_OCSF_S3_ENDPOINT`) | Endpoint if it differs from `--audit-s3-endpoint` (another account or region, S3-compatible store). Path-style addressing follows `--audit-s3-path-style`. |
| `--audit-ocsf-s3-flush` (`LIMEN_AUDIT_OCSF_S3_FLUSH`, default `60s`) | Close a batch after this long. |
| `--audit-ocsf-max-lag-bytes` (`LIMEN_AUDIT_OCSF_MAX_LAG_BYTES`, default 256 MiB) | See [when the SIEM is down](#when-the-siem-is-down). Must be below `--audit-spool-max-bytes`. |

The control plane refuses to start if the OCSF bucket or key looks like the audit one (same name, ignoring case and padding; a key id, alias or ARN written two ways), if the lag bound is not below the spool size, or if no native sink (`--audit-file`, an audit S3 bucket, or Datadog) is configured, because the OCSF sink can skip batches and something durable must hold them. The name check is a guard against mistakes; it cannot see an alias that points to the same key or an access point on the same bucket, so the IAM separation in the Terraform module is what keeps the SIEM out of the audit bucket. The reason is access: the audit bucket and its key also protect **session recordings**. The SIEM's collector gets the OCSF bucket and key and nothing of the audit bucket (`reader_policy_json` in the module does that).

Objects are named `<prefix>dt=YYYY-MM-DD/hour=HH/<control plane id>-<content hash>.jsonl.gz`, partitioned by the event's UTC hour (lines the export cannot read go under `dt=unknown/hour=00`). A retry writes the same key with the same bytes, including for unreadable lines. Delivery is at-least-once, like every sink, so a SIEM may see a record twice: `metadata.uid` is the same.

## What a record carries

Every record has the OCSF base attributes (`class_uid`, `category_uid`, `activity_id`, `type_uid`, `time` in milliseconds, `severity_id`, `metadata`) and:

- `metadata.uid`: the native `event_id`. This is how you get from a SIEM record to the original event in the audit trail (the S3 batch holding it is found by that id, for example with the Athena views).
- `metadata.version`: the OCSF version (1.9.0). `metadata.product`: Limen, its version, and the producing component.
- `unmapped.limen`: the native `kind`, `schema_version`, `producer` (`component`, `instance_id`, and `seq`: a gap in a producer's `seq` still means lost events), `session_id`, and the native `data` object.
- When the event has them: `actor.user` (and `user` on Authentication), `src_endpoint.ip` (only if the native address is a valid IP), `status_id`, and for HTTP `http_request.http_method` and `http_response.code`.

The chain position (the manifest sequence number of the S3 batch) is **not** in the record: the OCSF export reads the spool independently of the S3 sink and does not know it when it ships.

**Secrets.** Native events hold none in named fields. As a second lock, any field in `data` whose name says it is a secret (`password`, `passphrase`, `secret`, `api key`, `access key`, `private key`, `authorization`, `bearer`, `jwt`, `cookie`, `credential`, `dsn`, `otp`, `token`, and similar, however they are spelled: `Api-Key`, `api.key`) is replaced by `[redacted]`, at any depth. Ids and digests of a token (`token_id`, `…_sha256`) are kept. **Values are not scanned.** Free text that a user typed, such as an SSH command, a SQL statement, a search query or a web path, goes to the SIEM exactly as it is in the native trail, with the same redaction rules ([databases](databases.md)): a password typed into a command line is visible to whoever reads the SIEM. Treat the SIEM's access as you treat the audit bucket's for that data. The location of a recording (`recording_uri` of `session.recording`) is removed, so the feed does not name the audit bucket.

An event the export cannot read (a kind from a newer producer, say) is not dropped: it becomes a Base Event. If the line is JSON, its content goes through the same secret scrub and is kept under `unmapped.limen.raw` (over 32 KiB, only its `kind`, `event_id` and `producer`); if it is not JSON, only its length is kept. Its `time` is 0.

## Mapping

Generated from the code (`crates/limen-audit/src/ocsf.rs`), and a test fails if this table is out of date. Class and activity ids are from the OCSF 1.9.0 class pages. Where the table says an activity depends on the event, the class stays the same and the activity is picked from the event's `data`:

- HTTP Activity (`search.*`, `web.*`): the method (Get 3, Post 6, Put 7, Delete 2, Patch 9, Head 4, Options 5, Connect 1, Trace 8, else Other 99), and `status_id` from the response status.
- API Activity for `kube.request`: the Kubernetes verb (create → Create 1; get, list, watch → Read 2; update, patch → Update 3; delete, deletecollection → Delete 4; else Other 99).
- Datastore Activity for `db.query`: the statement class (select, show, describe → Query 4; insert, replace → Write 5; update, merge → Update 2; delete, truncate, drop → Delete 7; create → Create 6; else Other 99). `with`, `explain` and `copy` stay Other on purpose: a `WITH … DELETE`, an `EXPLAIN ANALYZE` of a write and a `COPY … TO` would otherwise look like reads.

An *Other* activity carries a readable `activity_name` (for example `access approve`).

<!-- BEGIN_OCSF_MAPPING -->
| Limen event | OCSF class (uid) | Activity (id) | Severity |
|---|---|---|---|
| `auth.login` | Authentication (3002) | Logon (1) | Informational |
| `auth.logout` | Authentication (3002) | Logoff (2) | Informational |
| `auth.denied` | Authentication (3002) | Logon (1) | Low |
| `session.start` | Network Activity (4001) | Open (1) | Informational |
| `session.end` | Network Activity (4001) | Close (2) | Informational |
| `ssh.exec` | SSH Activity (4007) | exec (99) | Informational |
| `db.query` | Datastore Activity (6005) | by statement class | Informational |
| `db.query.end` | Datastore Activity (6005) | Other (99) | Informational |
| `db.bootstrap` | Datastore Activity (6005) | Other (99) | Informational |
| `search.request` | HTTP Activity (4002) | by method | Informational |
| `search.response` | HTTP Activity (4002) | by method | Informational |
| `redis.command` | Datastore Activity (6005) | Other (99) | Informational |
| `mongo.command` | Datastore Activity (6005) | Other (99) | Informational |
| `mongo.command.end` | Datastore Activity (6005) | Other (99) | Informational |
| `mq.operation` | API Activity (6003) | Other (99) | Informational |
| `mq.summary` | API Activity (6003) | Other (99) | Informational |
| `kafka.request` | API Activity (6003) | Other (99) | Informational |
| `kafka.summary` | API Activity (6003) | Other (99) | Informational |
| `kube.request` | API Activity (6003) | by verb | Informational |
| `web.request` | HTTP Activity (4002) | by method | Informational |
| `web.response` | HTTP Activity (4002) | by method | Informational |
| `web.websocket` | HTTP Activity (4002) | by method | Informational |
| `policy.change` | Entity Management (3004) | Update (3) | Informational |
| `policy.shadow_deny` | Base Event (0) | shadow deny (99) | Medium |
| `policy.write_denied` | Base Event (0) | policy write denied (99) | Low |
| `policy.ownership_transfer` | Entity Management (3004) | Move (5) | Informational |
| `policy.change_pending` | Entity Management (3004) | policy change review (99) | Informational |
| `policy.change_decided` | Entity Management (3004) | policy change review (99) | Informational |
| `worker.enroll` | Entity Management (3004) | Enroll (6) | Informational |
| `join_token.create` | Entity Management (3004) | Create (1) | Informational |
| `session.recording` | API Activity (6003) | Create (1) | Informational |
| `user.lock` | Entity Management (3004) | Suspend (12) | Low |
| `user.unlock` | Entity Management (3004) | Resume (13) | Informational |
| `user.delete` | Entity Management (3004) | Delete (4) | Informational |
| `user.provision` | Entity Management (3004) | Create (1) | Informational |
| `user.groups_change` | Entity Management (3004) | Update (3) | Informational |
| `idp.offboard` | Entity Management (3004) | Suspend (12) | Low |
| `idp.check_failed` | Base Event (0) | idp check failed (99) | Medium |
| `session.kill` | Network Activity (4001) | Close (2) | Low |
| `component.revoke` | Entity Management (3004) | Unenroll (7) | Low |
| `access.request` | Entity Management (3004) | access request (99) | Informational |
| `access.approve` | Entity Management (3004) | access approve (99) | Informational |
| `access.deny` | Entity Management (3004) | access deny (99) | Informational |
| `access.grant` | Authorize Session (3003) | Assign Roles (3) | Informational |
| `access.revoke` | Entity Management (3004) | access revoke (99) | Informational |
| `access.expire` | Entity Management (3004) | access expire (99) | Informational |
| `access.break_glass` | Authorize Session (3003) | Assign Roles (3) | High |
| `access.cancel` | Entity Management (3004) | access cancel (99) | Informational |
| `audit.search` | API Activity (6003) | Read (2) | Informational |
| `audit.verify_access` | API Activity (6003) | Read (2) | Informational |
| `resource.discovered` | Entity Management (3004) | Create (1) | Informational |
| `resource.relabel` | Entity Management (3004) | Create (1) | Informational |
| `resource.review` | Entity Management (3004) | Other (99) | Informational |
| `resource.stale` | Entity Management (3004) | Other (99) | Informational |
| `review.start` | Entity Management (3004) | access review (99) | Informational |
| `review.decide` | Entity Management (3004) | access review (99) | Informational |
| `review.complete` | Entity Management (3004) | access review (99) | Informational |
| `access.deny_override` | Entity Management (3004) | access deny override (99) | Informational |
| `evidence.export` | API Activity (6003) | Create (1) | Informational |
| `session.watch.start` | Base Event (0) | session watch (99) | Informational |
| `session.watch.stop` | Base Event (0) | session watch (99) | Informational |
<!-- END_OCSF_MAPPING -->

## When the SIEM is down

The control plane keeps every audit event in a disk spool until all sinks have taken it. A SIEM bucket that stays unreachable would hold the spool back until it is full, and a full spool refuses logins and sessions (`audit.failure_mode: fail_closed`). A projection must not be able to do that.

So: while the OCSF sink is failing **and** it is strictly the slowest sink (every other sink has fewer records pending, so skipping frees segments) **and** the spool holds more than `--audit-ocsf-max-lag-bytes`, it skips its batch instead of retrying it. A skip leaves no marker in the SIEM; a gap shows only as missing `metadata.uid`s or a jump in a producer's `seq`. It also applies to a permanent fault (a denied key, a missing bucket): the export then does nothing once the spool is past the bound, which is why the skip counter needs an alert. Nothing else is affected, and the events are still in the S3 trail. Each skip is counted in `limen_audit_ocsf_skipped_total` and logged as an error; alert on any increase, because a SIEM missing events silently is its own risk. Below the bound, or while another sink is further behind, the sink retries and keeps its events, and delivers them when the bucket is back.

Metrics: `limen_audit_ocsf_events_total` (records written), `limen_audit_ocsf_skipped_total` (records skipped), and the usual `limen_audit_spool_pending{consumer="ocsf"}`, `limen_audit_shipped_total` and `limen_audit_ship_errors_total`. The console's Integrations page lists the export next to the other sinks.

## What is not built

- **Amazon Security Lake.** It takes Parquet, one class per source, and OCSF 1.3 or earlier for custom sources. This export is NDJSON at 1.9.0. A Security Lake path would be a later change (ADR-0049, Open for review).
- **An HTTPS push** to a SIEM's collector endpoint.
- **The manifest sequence number** in each record.
- **A gap marker** in the SIEM for skipped batches.
- **Dropping free-text fields** (`command`, `statement`, bodies) from the OCSF copy.
- **A Limen extension** for the fields that sit in `unmapped`.

## What was tried

Tested against the dev stack's SeaweedFS: every event of a control plane run arrives in the OCSF bucket with the required attributes and its native id; the audit bucket is untouched and still verifies; a down OCSF endpoint keeps its events and delivers them when it returns; a down endpoint that holds the spool back is skipped and counted. **Unverified:** no SIEM, no Security Lake, and no AWS account has read these files. The records carry the OCSF base attributes and the class-specific ones listed above, but they have **not** been validated against the full schema of each class (some classes require attributes Limen does not have, such as an authentication protocol). Check the first ingest in your SIEM before relying on it for detections.
