# Search: OpenSearch and Elasticsearch

Connect with `curl` or any Elasticsearch or OpenSearch client. You never see a password or API key: the worker logs in to the engine as the engine role your role names, checks every request against your role (what it does and which indices it names), and audits it. Design: [ADR-0036](../adr/0036-search-access.md).

## Connect

```sh
limen ls                                   # search-staging   ● elasticsearch   read
limen search connect search-staging        # the role is picked from policy when there's only one
# Listening for search-staging as read.
# Run: curl http://127.0.0.1:51234/
curl http://127.0.0.1:51234/app-orders/_search -H 'content-type: application/json' -d '{"query":{"match_all":{}}}'
```

Point a client at the same URL. It needs no credentials and no TLS settings: the listener is plain HTTP on loopback, and the hop to Limen is mutual TLS.

```python
from elasticsearch import Elasticsearch          # or: from opensearchpy import OpenSearch
es = Elasticsearch("http://127.0.0.1:51234")
es.search(index="app-orders", query={"match_all": {}})
```

- Listener behaviour (loopback, one audited session per connection, idle timeout, `--listen`, `--socket`): [Using the CLI](cli.md#local-listeners). `--role write` picks the engine role when policy allows several. With a unix socket: `curl --unix-socket ~/.limen/run/search.sock http://localhost/`.
- A refusal reaches your client as an Elasticsearch-shaped error: `403` or `400` with `{"error": {"type": "limen_security_exception", "reason": "Limen: ..."}}` and an `x-limen-refused: true` header. The connection stays open.
- Client headers aren't forwarded, except `Accept`, `Content-Type`, `Content-Encoding`, `User-Agent`, the Elastic client metadata headers and `traceparent`. `Authorization`, API keys, `es-security-runas-user`, `opensearch_security_impersonate_as` and `x-forwarded-*` are dropped. The worker adds its own credential and `X-Opaque-Id: limen:<session id>`.

## What a role can do

```yaml
- resources: { kind: [elasticsearch, opensearch], labels: { env: [staging] } }
  search:
    roles: [read]                          # the engine-side login the worker uses
    classes: [read]                        # read | write | admin. Default: read
    indices: ["app-*", "logs-2026.*"]      # empty: any index that isn't hidden
```

Full syntax: [policy reference](../policy.md). Every request has a **class**:

| Class | Covers |
|---|---|
| `read` | `_search`, `_count`, `_msearch`, `_mget`, `GET /{index}/_doc/{id}`, `_field_caps`, `_analyze`, scroll and point-in-time, SQL and PPL queries, `_cat` listings, `_cluster/health`, `_nodes/stats`, `GET /` |
| `write` | `_doc`, `_create`, `_update`, `_bulk`, `_delete_by_query`, `_update_by_query`, `_reindex` (to an index you may write) |
| `admin` | Everything else: indices, mappings, settings, aliases, templates, ingest pipelines, snapshots, tasks, scripts, security APIs, cluster settings and state. **An API Limen doesn't recognise is `admin`** on every index, so a new API stays closed until granted |

Classes don't imply each other: `write` doesn't include `read`.

**Indices.** Each index a request names must be covered by a pattern in the same grant (a session may do what any one grant allows, never a mix). `*` is the only wildcard, and a request pattern is covered when a grant pattern matches it as text: `logs-a*` is covered by `logs-*`; `log*` and `*` are not. A request naming no index (`/_search`, `/_all/_search`, `/*/_search`, `_cat/indices`) means *all indices* and needs a `*` grant. Limen reads names from:

- the path (`/logs-1,logs-2/_search`);
- the body of `_bulk` (each action's `_index`, or the path's), `_msearch` (each header's `index`), `_mget` and `_mtermvectors` (`docs[]._index`), `_reindex` (`source.index`, `dest.index`) and `_aliases`;
- a search body wherever it points at another index: `_index` anywhere (more-like-this, pinned queries), terms lookups, indexed shapes, and `percolate` by stored document. A body that isn't JSON is refused.

**Hidden indices** (names starting with `.`, such as `.security`, `.kibana`, `.tasks`) are never covered by `*` or an empty `indices`; only a pattern that itself starts with a dot opens them.

**Refused whatever the grant:**

- paths that can be read two ways: `..`, `.` and empty segments, encoded `/` or `\`, control characters;
- index expressions Limen can't judge: date math (`<logs-{now/d}>`), cross-cluster names (`remote:logs`), uppercase or unusual characters;
- the `source` query parameter (it carries a query body) when `indices` is set;
- `expand_wildcards=all` or `hidden`, unless a pattern starts with a dot;
- `_reindex` from a remote cluster;
- methods other than `GET`, `HEAD`, `POST`, `PUT`, `DELETE`.

**The engine's own role is the second layer.** Limen sees names in the request, not what an alias or data stream points to, and can't filter responses. Give each engine role the narrowest privileges its Limen roles need, and use document- and field-level security for anything finer.

## What is audited

Two events per request:

- **`search.request`**, written *before* forwarding (if it can't be written, the request is refused with `503`): user, session, resource, engine role, method, path, API name, class, the indices named (`indices_all` for every index), body size, query parameter *names*, and for `_bulk` the operations per index (`bulk: {"app-orders": {"index": 2}}`).
- **`search.response`**: status, time to the response head, length if known, and on error the engine's `error.type` (such as `index_not_found_exception`; never its reason, which can echo data).

Refusals are `auth.denied` with `action: search` and the reason. `session.start` and `session.end` carry `kind: elasticsearch` or `opensearch`. Locking a user or killing a session ends the connection as usual.

**Bodies and query strings are not logged** unless a resource opts in:

```yaml
spec:
  elasticsearch:
    endpoint: "es.example.com:9200"
    audit:
      log_bodies: true     # first 16 KiB of the body, audit sinks only. Never for security APIs
      log_query: true      # query-string values, not just names
      redact_ids: true     # hash document ids in the path
```

Document ids are in the path, so by default they're in the trail. `redact_ids` replaces them with `h:` plus 16 hex characters of SHA-256 over the resource name and the id: a plain hash that stops casual reading, not a guess at a likely id.

The console session page lists requests ([command lists](console.md)): time, API, method, path (ids hashed if `redact_ids`), and "ok", "error" (HTTP status and engine error type) or "refused" (reason).

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
| `--search-ca-file` / `LIMEN_SEARCH_CA_FILE` | PEM bundle to verify the server. Required for any `tls: true` target (the default). Use the [Amazon bundle](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/encryption-at-rest.html) for Amazon OpenSearch Service, the system bundle (`/etc/ssl/certs/ca-certificates.crt`) for Elastic Cloud or any public CA |
| `--search-credentials-file` / `LIMEN_SEARCH_CREDENTIALS_FILE` | JSON of the engine-side logins, below. Mount as a secret, mode 0400. Never put these in policy |

```json
{
  "catalog-search": {
    "read":  { "basic": { "username": "read", "password": "..." } },
    "write": { "api_key": "VnVhQ2ZHY0JDZGJrUW0tZTVhT3g6dWkybHAyYXhUTm1zeWFrdzl0dk5udw==" },
    "batch": { "bearer": "<token>" },
    "mtls":  { "client_cert_file": "/etc/limen/client.pem", "client_key_file": "/etc/limen/client.key" }
  }
}
```

Each entry has at most one of `basic`, `api_key` (the encoded key Elasticsearch shows, or `id:key`) and `bearer`; a client certificate pair can stand alone or combine with one. The worker reads the file at start-up and refuses to start if it can't. A role with no entry connects without a credential.

**Amazon OpenSearch Service** (`aws: true`). The worker signs each request with SigV4 (service `es`; `serverless: true` for OpenSearch Serverless, service `aoss`) using its own AWS credentials from the SDK's usual chain. With fine-grained access control, map the worker's IAM role as a backend role to an OpenSearch role with the privileges your Limen roles need. One IAM role is one engine-side identity: the Limen roles' classes and index patterns separate people, not several OpenSearch roles. Every request is buffered (up to the body cap) so its body can be hashed. **Unverified against the real service:** the signature matches an independent implementation and AWS's published examples, but no AWS account has been available.

**Self-hosted.** Create the engine users and roles in the engine (`deploy/compose/config/targets/search/provision.sh` shows both) and list the logins in the credentials file.

The engine sees the engine role, not the person. `X-Opaque-Id: limen:<session id>` on every request joins the engine's slow log, tasks API and deprecation logs to Limen's audit.

**Metrics** (worker `/metrics`): `limen_search_requests_total{class, result}` (`result`: `ok`, `error`, `denied`, `upstream_error`, `audit_failed`) and `limen_search_upstream_seconds` (time to the response head).

## Limits

- **HTTP/1.1 only**, one request at a time per connection. No websockets, `CONNECT` or HTTP/2.
- **Body cap.** Bodies the worker must read (`_bulk`, `_msearch`, `_mget`, `_reindex`, `_aliases`, every search body, and everything on an AWS target or a resource that logs bodies) are held in memory up to 32 MiB by default (`--search-max-body-bytes` / `LIMEN_SEARCH_MAX_BODY_BYTES`). Larger gets `413` and the connection closes. A busy worker can hold the cap times its session count (twice for gzip), so size memory for `--max-sessions` of them or lower the cap. Other bodies stream, and so do responses. A gzip body is decoded to be read and forwarded as sent; any other `Content-Encoding` on a body that must be read is refused.
- **Scroll and point-in-time.** Their ids name no index, so Limen can't check them: continuing and clearing a scroll is allowed to any role that may read, and the engine ties the context to the user that opened it. A PIT search names no index in its path, so an index-restricted grant can't use PITs; use scroll or `search_after`.
- **Aliases and data streams.** Policy applies to the names in the request. A `logs-*` grant that lets someone search an alias called `logs-current` also lets them search whatever it points to. Keep aliases inside the granted pattern, or rely on the engine's role.
- **No response filtering.** Index patterns bound what a request can name, not what a document, aggregation or `_cat` row reveals. Use the engine's document- and field-level security.
- **SQL and PPL** (`_sql`, `_plugins/_sql`, `_ppl`) name tables in query text, which Limen doesn't parse. They count as touching every index and need a role with no `indices` limit (or `*`).
- **Audit comes first**, for the request and for the response: about two fsyncs per request, a few milliseconds on a normal disk. A bulk job pays that per request, not per document.
- **Credential rotation needs a worker restart.** The credentials file and CA bundle are read at start-up; roll the workers (they drain) after changing either.
- **Timeouts.** A client has 10 minutes to send a body the worker must read (then `408`); a response stalled for 15 minutes ends the connection. A connection that has sent requests and then none for an hour (`--search-idle-timeout`) ends; one that has sent nothing yet lasts until the session limit. Request or response heads over 64 KiB are refused.
- **One console row per run.** All sessions of one `limen search connect` share a group, so the console shows them as one row with their requests together. The command keeps one empty session open while it runs, so the row stays active until you stop it.
- **Not supported:** Kibana and OpenSearch Dashboards (use the [web-app integration](web-apps.md)), cross-cluster search, remote reindex, and date-math index expressions.
- **Unverified:** Amazon OpenSearch Service (SigV4 acceptance, fine-grained access mapping), OpenSearch Serverless, Elastic Cloud API keys, and TLS with the Amazon bundle. The rest ran against Elasticsearch 8.15 and OpenSearch 2.17 (`demos/demo-phase10.sh`). Elasticsearch 7 and 9 and OpenSearch 1 and 3 should work but weren't run.
