# ADR-0026: Searching audit events and recordings

- Status: Proposed (owner requested 2026-10-14; priority: **must have**)
- Date: 2026-10-14

## Context
Audit lives in S3 and Datadog, recordings in S3, and the console keeps a 30-day *summary* (ADR-0017 amendment) that deliberately excludes statements and payloads. When something goes wrong people ask "who ran that `DROP TABLE`?" or "what did anyone do on `orders-prod` last Tuesday?". Athena can answer, but only for people with AWS access and SQL, and not for text inside recordings.

## Decision
- **Search has two tiers.**
  1. **Recent, in the console and CLI** (default 30 days, configurable): a Postgres full-text and trigram index (`pg_trgm`, `tsvector`). No new infrastructure.
  2. **Full history:** stays in Athena and Datadog. The console links to the saved Athena query for the same filters when Athena is configured.
- **What is indexed.** Event metadata always. Command and statement text (`ssh.exec`, `db.query`, later Redis, Kubernetes, search and messaging events) by default, because SQL text is already audited in full (owner decision). **Text inside recordings is opt-in** (`--search-recordings`), because terminals echo whatever is on screen, including secrets. When on, the control plane extracts printable output when a recording is stored, caps it per session, and masks common secret shapes (AWS keys, bearer tokens, `password=`, private-key blocks) before indexing. The recording itself is unchanged.
- **Query syntax:** free text plus filters: `user:`, `resource:`, `kind:`, `session:`, `after:`, `before:`, `outcome:`, and quoted phrases. Results show a snippet, the session, and a **deep link into the recording at that moment**.
- **Who can search.** A new built-in role **`limen:auditor`** can search, read events, and play recordings, but cannot lock, kill, revoke, approve, or change anything. Admins can do all of it. Per-resource restrictions on what an auditor sees are a later extension.
- **Searches are audited.** Every query emits `audit.search` with the identity and the filters (not the results), so there is a record of who looked for what. Rate-limited per user.
- **Retention:** `--search-retention` (default 30 days) with a cleanup job; separate from the audit sinks, which remain the record.
- **Interfaces:** console search page, `limen audit search '<query>'` (JSON or table), and the same API.
- **Data:** `audit_search` (event id, time, kind, user, session, resource, text, `tsv`), with GIN indexes; recording text in `recording_text` (session id, `tsv`, bytes, truncated).

## Threats this design has to survive
- **Search as an exfiltration channel:** it exposes everything the auditors may see. Mitigations: the narrow `limen:auditor` role, audited queries, rate limits, retention limits, and an off-by-default recording index.
- **Secrets in recordings and statements:** masked at index time on a best-effort basis (documented as such, not a guarantee). The unmasked originals stay where they already are, under the sinks' controls.
- **Query injection or expensive queries:** the query is parsed into a typed filter set and a sanitized tsquery, always parameterized; statement timeouts and result limits apply.
- **Index diverging from the record:** the index is a copy built from the same events; the console says so, and verification (`limen-audit-verify`) stays the source of truth.

## Consequences
- Storage grows with text; sizing guidance and the retention setting are part of the work.
- A second built-in role appears in policy, mappings, and the console.
