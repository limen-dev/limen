# Search: OpenSearch and Elasticsearch

Connect with `curl`, or any Elasticsearch or OpenSearch client, through Limen. You never see a password or API key: the worker logs in to the engine as the engine role your role names, checks every request against your role (what it does, and which indices it names), and audits it. Design: [ADR-0036](../adr/0036-search-access.md).

## Connect

```sh
limen ls                                   # search-staging   ● elasticsearch   limen-read
limen search connect search-staging        # the role is picked from policy when there's only one
# Listening for search-staging as limen-read.
# Run: curl http://127.0.0.1:51234/
curl http://127.0.0.1:51234/app-orders/_search -H 'content-type: application/json' -d '{"query":{"match_all":{}}}'
```

Point a client at the same URL. It needs no credentials and no TLS settings (the listener is plain HTTP on loopback; the hop from your machine to Limen is mutual TLS):

```python
from elasticsearch import Elasticsearch          # or: from opensearchpy import OpenSearch
es = Elasticsearch("http://127.0.0.1:51234")
es.search(index="app-orders", query={"match_all": {}})
```

- Each connection to the listener is its own audited session. Clients that pool connections (all of them) open several: that is several sessions, each with its own session ID in the trail. Leave `limen search connect` running while you work; press Ctrl-C, or wait for it to stop after an hour with no connection (`--idle-timeout 30m`, `0` for never).
- `--role limen-write` picks the engine role when policy allows several. `--listen 127.0.0.1:9200` fixes the port (loopback only). `--socket ~/.limen/run/search.sock` uses a unix socket (mode 0600, in a directory only you can enter): `curl --unix-socket ~/.limen/run/search.sock http://localhost/`.
- Anyone who can reach the listener acts as you. That is why it binds loopback only and the socket is private. Don't forward the port.
- A refusal reaches your client as an Elasticsearch-shaped error: `403` or `400` with `{"error": {"type": "limen_security_exception", "reason": "Limen: ..."}}`, and an `x-limen-refused: true` header. The connection stays open after a refusal.
- Headers your client sends are not forwarded, except a short list of harmless ones (`Accept`, `Content-Type`, `Content-Encoding`, `User-Agent`, the Elastic client metadata headers, `traceparent`). `Authorization`, API keys, `es-security-runas-user`, `opensearch_security_impersonate_as`, and `x-forwarded-*` are dropped. The worker adds its own credential and `X-Opaque-Id: limen:<session id>`.

## What a role can do

A role grants engine roles with limits (`docs/policy.md` has the full syntax):

```yaml
- resources: { kind: [elasticsearch, opensearch], labels: { env: [staging] } }
  search:
    roles: [limen-read]                    # the engine-side login the worker uses
    classes: [read]                        # read | write | admin. Default: read
    indices: ["app-*", "logs-2026.*"]      # empty: any index that isn't hidden
```

Every request has a **class**:

| Class | What it covers |
|---|---|
| `read` | Searching and fetching: `_search`, `_count`, `_msearch`, `_mget`, `GET /{index}/_doc/{id}`, `_field_caps`, `_analyze`, scroll and point-in-time, SQL and PPL queries, `_cat` listings, `_cluster/health`, `_nodes/stats`, `GET /` |
| `write` | Changing documents: `_doc`, `_create`, `_update`, `_bulk`, `_delete_by_query`, `_update_by_query`, `_reindex` (to an index you may write) |
| `admin` | Everything else: creating, deleting, closing, and changing indices, mappings, settings, aliases, templates, ingest pipelines, snapshots, tasks, scripts, security APIs, cluster settings and state. **An API Limen doesn't recognise is `admin`**, on every index, so a new API stays closed until someone grants it |

Classes don't imply each other: `write` doesn't include `read`.

The **indices** a request names must each be covered by a pattern in the same grant (a session may do what any one grant allows, never a mix). `*` is the only wildcard. A request pattern is covered when a grant pattern matches it as text: `logs-a*` is covered by `logs-*`, but `log*` and `*` are not. A request that names no index (`/_search`, `/_all/_search`, `/*/_search`, `_cat/indices`) means *all indices* and needs a `*` grant. Limen finds the names in:

- the path (`/logs-1,logs-2/_search`);
- the body of `_bulk` (each action's `_index`, or the path's), `_msearch` (each header's `index`), `_mget` and `_mtermvectors` (`docs[]._index`), `_reindex` (`source.index` and `dest.index`), and `_aliases` (index and alias names);
- the body of a search, wherever it points at another index: `_index` anywhere (more-like-this, pinned queries), terms lookups, indexed shapes, and `percolate` by stored document. A body Limen can't read as JSON is refused.

**Hidden indices** (names starting with `.`: `.security`, `.kibana`, `.tasks`) are never covered by `*` or by an empty `indices`; only a pattern that itself starts with a dot opens them.

Refused outright, whatever the grant:

- paths that can be read two ways: `..`, `.` and empty segments, encoded `/` or `\`, control characters;
- index expressions Limen can't judge: date math (`<logs-{now/d}>`), cross-cluster names (`remote:logs`), uppercase or unusual characters;
- the `source` query parameter (it carries a query body) when `indices` is set;
- `expand_wildcards=all` or `hidden` unless a pattern starts with a dot;
- `_reindex` from a remote cluster;
- methods other than `GET`, `HEAD`, `POST`, `PUT`, `DELETE`.

**The engine's own role is the second layer.** Limen sees the names in the request, not what an alias or a data stream points to, and it cannot filter what a response contains. Give each engine role the narrowest privileges that serve the Limen roles that use it, and use the engine's document- and field-level security for anything finer. If the worker is ever wrong, the engine still refuses what its role forbids.

## What is audited

Two events per request on a session:

- `search.request`, written **before** the request is forwarded (if it can't be written, the request is refused with `503`): the user, session, resource, engine role, method, path, API name, class, the indices it names (`indices_all` for "every index"), the number of body bytes, the query parameter *names*, and for `_bulk` the operations per index (`bulk: {"app-orders": {"index": 2}}`).
- `search.response`, when the engine answers: the status, the time to the response head, the length if known, and for an error the engine's `error.type` (for example `index_not_found_exception` or `security_exception`; never its reason, which can echo data).

A refused request is an `auth.denied` event with `action: search` and the reason. `session.start` and `session.end` carry `kind: elasticsearch` or `opensearch`. Locking a user or killing a session ends the connection like any other.

**Bodies and query strings are not logged.** A resource can opt in:

```yaml
spec:
  elasticsearch:
    endpoint: "es.example.com:9200"
    audit:
      log_bodies: true     # first 16 KiB of the body, in the audit sinks only. Never for security APIs
      log_query: true      # query-string values, not just their names
      redact_ids: true     # hash document ids in the path (the same id gives the same hash)
```

Document ids are in the path, so by default they are in the trail; `redact_ids` replaces them with `h:` and 16 hex characters of SHA-256 over the resource name and the id. It is a plain hash: it stops casual reading, not a guess at a likely id.

**In the console**, a search session's page lists its requests (time, API, method and path, outcome), up to 500, including the ones policy refused. Search sessions have no terminal recording; this list is the record (owner decision: it needn't be video). It shows the method and path (ids hashed if the resource sets `redact_ids`) and, for each request, "ok", "error" (with the HTTP status and the engine's error type) or "refused" (with the reason). The console keeps this text in the control plane's database for 30 days (table `db_statements`, shared with SQL and Redis sessions), visible only to admins and to the session's own user. The complete trail stays in S3 and Datadog.

## Operating it

**Resources**

```yaml
kind: resource
version: v1
metadata: { name: logs-prod, labels: { env: prod } }
spec:
  opensearch:
    endpoint: "search-logs-abc.eu-west-1.es.amazonaws.com:443"
    region: eu-west-1
    aws: true               # SigV4 with the worker's AWS credentials
    audit: { redact_ids: true }
  worker_selector: { pool: prod-vpc }
---
kind: resource
version: v1
metadata: { name: catalog-search, labels: { env: staging } }
spec:
  elasticsearch:
    endpoint: "es.internal:9200"
    tls: true               # default; false is for local servers only
```

**Worker**

| Flag / variable | Purpose |
|---|---|
| `--search-ca-file` / `LIMEN_SEARCH_CA_FILE` | PEM bundle to verify the server. Required for any `tls: true` target (the default): for Amazon OpenSearch Service use the [Amazon bundle](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/encryption-at-rest.html), for Elastic Cloud or any public CA use the system bundle (`/etc/ssl/certs/ca-certificates.crt`) |
| `--search-credentials-file` / `LIMEN_SEARCH_CREDENTIALS_FILE` | JSON of the engine-side logins, below. Mount it as a secret, mode 0400. Never put these in policy |

```json
{
  "catalog-search": {
    "limen-read":  { "basic": { "username": "limen-read", "password": "..." } },
    "limen-write": { "api_key": "VnVhQ2ZHY0JDZGJrUW0tZTVhT3g6dWkybHAyYXhUTm1zeWFrdzl0dk5udw==" },
    "limen-batch": { "bearer": "<token>" },
    "limen-mtls":  { "client_cert_file": "/etc/limen/client.pem", "client_key_file": "/etc/limen/client.key" }
  }
}
```

Each entry has at most one of `basic`, `api_key` (the encoded key Elasticsearch shows, or `id:key`), and `bearer`; a client certificate pair can stand alone or be combined with one of them. The worker reads the file at start-up and refuses to start on a file it can't read. A role with no entry connects without a credential.

**Amazon OpenSearch Service** (`aws: true`): the worker signs each request with SigV4, service `es` (`serverless: true` for OpenSearch Serverless, service `aoss`), region from the resource, with its own AWS credentials (the SDK's usual chain). With fine-grained access control, map the worker's IAM role as a backend role to an OpenSearch role that has the privileges your Limen roles need. One IAM role means one engine-side identity: the Limen roles' classes and index patterns, not several OpenSearch roles, are what separate people. Every request is buffered (up to the body cap below) so that its body can be hashed for the signature. **Unverified against the real service:** the signature matches an independent implementation of the specification and AWS's published examples, but no AWS account has been available.

**Self-hosted Elasticsearch or OpenSearch:** create the engine users and roles in the engine (`deploy/compose/config/targets/search/provision.sh` shows both), and list the logins in the credentials file. The dev stack's OpenSearch is reached over TLS with its demo certificate, verified in full.

The engine sees `limen-read`, not the person. Every request carries `X-Opaque-Id: limen:<session id>`, so the engine's slow log, the tasks API, and deprecation logs join to Limen's audit.

**Metrics** (the worker's `/metrics`): `limen_search_requests_total{class, result}` (`result` is `ok`, `error`, `denied`, `upstream_error`, or `audit_failed`) and `limen_search_upstream_seconds` (time to the response head).

## Limits

- **HTTP/1.1 only**, one request at a time per connection. Websockets, `CONNECT`, and HTTP/2 are not supported.
- **Bodies the worker must read** (`_bulk`, `_msearch`, `_mget`, `_reindex`, `_aliases`, and every search body, and everything on an AWS target or a resource that logs bodies) are held in memory up to a cap, 32 MiB by default (`--search-max-body-bytes` / `LIMEN_SEARCH_MAX_BODY_BYTES`); a larger one is answered `413` and the connection closes. A busy worker can hold the cap times its session count (twice for gzip bodies), so size the worker's memory for `--max-sessions` of them or lower the cap. Other bodies stream. A gzip body is decoded to be read (and forwarded as sent); another `Content-Encoding` on a body that must be read is refused. Responses always stream.
- **Scroll and point-in-time.** A scroll ID or PIT ID names no index, so Limen can't check it; continuing and clearing a scroll are allowed to any role that may read, and the engine ties the context to the engine user that opened it. A search that uses a PIT names no index in its path, so an index-restricted grant can't use PITs (use scroll or `search_after` on the index).
- **Aliases and data streams.** Policy is on the names in the request. A grant for `logs-*` that lets someone search an alias called `logs-current` also lets them search whatever that alias points to. Keep aliases inside the pattern you grant, or rely on the engine's role.
- **No response filtering.** Index patterns bound what a request can name, not what a document, an aggregation, or a `_cat` row reveals. Use the engine's document- and field-level security.
- **SQL and PPL** (`_sql`, `_plugins/_sql`, `_ppl`) name their tables in the query text, which Limen doesn't parse, so they count as touching every index: they need a role with no `indices` limit (or `*`).
- **Audit comes first, so each request waits for it**, and the response event as well: about two audit fsyncs per request, a few milliseconds on a normal disk. A bulk indexing job pays that per request, not per document.
- **Credentials rotate with a worker restart.** The credentials file and the CA bundle are read at start-up; roll the workers (they drain) after changing either.
- **Slow uploads.** A client has 10 minutes to send a body the worker must read (then `408`); a response that stalls for 15 minutes ends the connection.
- **Idle:** a connection that has sent requests and then sends none for an hour (`--search-idle-timeout`) ends. One that has sent nothing yet (the command's own) lasts until the session time limit. A request or response head over 64 KiB is refused.
- Every session of one `limen search connect` run shares a group, so the console shows them as **one row**, with their requests together. The command also keeps one empty session open while it runs (it checks your login and the server at start): the row stays active until you stop the command, however briefly each client connection lasts.
- **Not supported:** Kibana and OpenSearch Dashboards (they are web apps; Phase 12), cross-cluster search, reindex from a remote cluster, and index expressions with date math.
- **Unverified against real services:** Amazon OpenSearch Service (SigV4 acceptance, fine-grained access control mapping), OpenSearch Serverless, Elastic Cloud API keys, and TLS with the Amazon bundle. Everything else was run against Elasticsearch 8.15 and OpenSearch 2.17 in `demos/demo-phase10.sh`. Elasticsearch 7 and 9 and OpenSearch 1 and 3 should work (the REST surface Limen reads has not changed in the parts it classifies) but were not run.
