# Searching the audit trail

"Who ran that `DROP TABLE`?" and "what did anyone do on `orders-prod` last Tuesday?" are answerable in a box ([ADR-0026](../adr/0026-audit-and-recording-search.md)).

```sh
limen audit search 'drop table user:alice@example.com after:7d'
limen audit search '"systemctl restart" resource:web-prod kind:ssh.exec' --json
```

In the console it is the search box on **Audit trail**.

## Syntax

Words must all appear (substring, any case); `"quoted phrases"` match as written. Filters:

| Filter | Meaning |
|---|---|
| `user:` | the user, any case; repeat for several |
| `resource:` | the resource name |
| `kind:` | an event kind: `ssh.exec`, `db.query`, `redis.command`, `kube.request`, `auth.denied`, `access.request`, ... |
| `session:` | one session id |
| `after:` `before:` | a date (`2026-10-01`), an instant, or an age (`90m`, `24h`, `7d`, `2w`) |
| `outcome:` | `ok` or `denied` |

Results show a snippet with the match marked, who and what, and a **link to the recording at that moment** (the session page opens the player at the offset, three seconds early). Hits inside recordings link the same way.

## What is searched

- **Event metadata** always, and **command and statement text** by default, because SQL text is already audited in full. Common secret shapes are masked before indexing: `password=...`, SQL `PASSWORD '...'`, bearer tokens, JWTs, AWS access keys, GitHub and Slack tokens, private-key blocks, and passwords in URLs. This is **best effort, not a guarantee**; the unmasked originals stay in the audit sinks under their own controls.
- **Text inside recordings is off.** A terminal echoes whatever is on screen, secrets included. Turn it on with `--search-recordings`: the control plane then reads each recording when it is stored, keeps the printable *output* (never input), reconstructs lines (backspaces and carriage returns applied), masks secret shapes, and keeps at most 256 KiB per session. The recording itself is never changed.
- **Recent history only:** 30 days by default (`--search-retention`). Older history is in S3 and Datadog. Set `--search-history-url` to a template with `{query}` `{user}` `{resource}` `{kind}` `{after}` `{before}` and results link to the same search there (a saved Athena query, a Grafana explore link).

## Who may search, and what it costs

Only `limen:admin` and the built-in **`limen:auditor`** role, which can search, read events, and play recordings, but cannot lock, kill, revoke, approve, or change policy. Map it like any role:

```yaml
kind: role_mapping
version: v1
metadata: { name: auditors }
spec:
  - { idp_group: auditors, roles: ["limen:auditor"] }
```

- **Every search is audited** (`audit.search`) with who looked for what: the query and its filters, never the results. A search that cannot be audited does not run. These events are not themselves indexed, so searching for a word does not find the searches for it.
- **Rate limited** to 30 a minute per person, bursts of 10.
- **Bounded:** at most 20 words and filters, 512 bytes, 200 hits; the query is parsed into a typed filter and every value is bound as a parameter; a search that takes more than 10 seconds is cancelled and asks you to narrow it.
- **The index is a copy.** It is built from the same events as the sinks; `limen-audit-verify` stays the source of truth.

Metrics: `limen_audit_searches_total`.
