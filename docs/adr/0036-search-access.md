# ADR-0036: OpenSearch and Elasticsearch access

- Status: Accepted (the owner asked for the implementation on 2026-10-18; the open questions were settled as the recommendations below, see "As built")
- Date: 2026-10-18

## Context
`docs/design.md` §13 lists Phase 10 as "OpenSearch and Elasticsearch: `curl` and the official clients through `limen search connect`; requests audited with index and method class; policy by index pattern; SigV4 for OpenSearch Service tested against a signature fixture". ADR-0018 fixed the shape: HTTP(S) REST, SigV4 (service `es`) for Amazon OpenSearch Service, basic auth, API key, or mTLS for everything else, and "which index does this touch" answered from the path and the body.

The data side already exists as stubs: policy accepts `opensearch` and `elasticsearch` targets (`SearchTarget`) and a `search: { roles }` grant, the console lists them, and `limen search connect` answers "planned for Phase 10". No protocol is implemented.

The pattern from ADR-0002, ADR-0015 and ADR-0034 holds: the **worker terminates the protocol next to the target and holds the credential**; the proxy only authorizes and routes; the CLI opens a loopback listener so `curl` and the official clients work unchanged and never see a credential.

## Decision
1. **Targets.** Elasticsearch 7.x to 9.x, OpenSearch 1.x to 3.x, Amazon OpenSearch Service domains (SigV4, service `es`), and Elastic Cloud (API key over HTTPS). OpenSearch Serverless (`aoss`) is in the target schema (`serverless: true`) but unverified. Kibana and OpenSearch Dashboards are *not* in scope here: they are web apps (ADR-0022, Phase 12).
2. **Wire.** HTTP/1.1. The CLI listens on loopback (plain HTTP; the hop is local to the user, and the outer hop is mTLS, as for Redis). Each accepted connection is one Limen session over the proxy's `limen-search/1` ALPN. The worker is an HTTP server toward the client and an HTTP client toward the target (`hyper`, already in the tree), one connection each, so requests on a session are strictly in order.
3. **The worker parses every request** (it is the policy point). It refuses: `CONNECT`, absolute-form targets, dot segments, empty segments, encoded `/` or control characters in a path segment, methods other than `GET HEAD POST PUT DELETE`, `Expect` anything but `100-continue`, and the `source` query parameter on index-restricted grants (it carries a query body). Whatever it classified is exactly what it forwards.
4. **Credentials are the worker's.** The client's `Authorization`, `x-api-key`, `x-amz-*`, `es-security-runas-user`, `opensearch-security-impersonate-as`, `x-forwarded-*`, `x-proxy-user` and `x-proxy-roles` headers are dropped. The worker adds, per engine role named by the grant:
   - *basic*, *API key*, or *bearer* from the worker's `--search-credentials-file` (`{"<resource>": {"<engine role>": {"basic": {...}} }}`), held as `Secret<String>`;
   - *mTLS*: a client certificate and key named in the same file;
   - *SigV4* when the target has `aws: true`: the worker's own AWS credentials (default chain) sign each request (service `es`, or `aoss`), reusing the Phase 6 signer. With fine-grained access control, the backend role is the worker's IAM role.
   TLS toward the target is on by default, `verify-full` against `--search-ca-file` (or the system roots when it is not set and the target is AWS). `tls: false` is for local servers.
5. **Policy.** The grant gains two fields, in the style of ADR-0034:
   ```yaml
   search:
     roles: [limen-read]                    # engine role (credential selector), as before
     classes: [read]                        # read | write | admin. Default: [read]
     indices: ["logs-*", "metrics-2026.*"]  # empty: any non-hidden index
   ```
   - *Method classes.* **read**: searching and fetching (`_search`, `_count`, `_msearch`, `_mget`, `_doc` `GET`, `_field_caps`, `_analyze`, scroll and PIT, `_cat/*` and cluster/node health). **write**: changing documents (`_doc`, `_create`, `_update`, `_bulk`, `_delete_by_query`, `_update_by_query`, `_reindex`). **admin**: everything else (indices, mappings, settings, aliases, templates, ingest and pipelines, snapshots, tasks, scripts, security, cluster settings) and **anything the worker does not recognise**. Unknown means admin, so a new API is closed until someone grants it.
   - *Index patterns* use `*` only. The set of indices a request names (from the path, and for `_bulk`, `_msearch`, `_mget`, `_mtermvectors`, `_reindex`, `_aliases`, and the query body's `_index` and terms-lookup references, from the body) must **each be covered** by a pattern. A request pattern is covered by a grant pattern when the grant pattern matches it as text (`logs-a*` is covered by `logs-*`; `*` only by `*`). A request that names no index (`/_search`, `/_all`, `/*`) means *all* and needs a `*` grant. **Hidden/system indices** (names starting with `.`) match only a grant pattern that itself starts with `.`: `*` never opens `.security`, `.kibana`, or `.tasks`.
   - *Aliases.* Policy sees the name in the request, not what an alias points to. The engine-side role is the backstop (the same two-layer rule as Redis ACLs); the guide says so.
   - Roles are additive: a session may do what any one of its grants allows.
6. **Audit.** `search.request` is written **before** the request is forwarded; if it can't be written, the request is refused (fail closed). It holds the user, roles, resource, engine role, method, a normalised path, the API name, the class, the indices, and for `_bulk` the per-index operation counts. After the response, `search.response` records status, duration, bytes, and the engine's error `type` (not its reason, which can echo data). **Bodies are never logged** by default (`audit.log_bodies: true` per resource opts in, truncated at 16 KiB, and never for credential-bearing APIs such as `_security`/`_plugins/_security`). Query strings are logged by parameter name only (`audit.log_query: true` includes values). Document IDs are in the path; `audit.redact_ids: true` replaces them with a hash. A refused request writes `auth.denied` (`action: search`) with the reason.
7. **Recording.** As with databases and Redis, search sessions have no terminal recording. The record is the audit trail, and the console's session page lists each request of a search session (method and path, API, indices, status, duration), projected from `search.request` and `search.response` into the `db_statements` table; no new table. This is the "session recording" for the kind (owner decision 2026-10-18: it need not be a video).
8. **Attribution.** The worker sets `X-Opaque-Id: limen:<session id>` on every request (overriding the client's), so slow logs, the tasks API, and deprecation logs on both engines join to Limen sessions. The engine-side user is the role's, never the person's.
9. **Limits.** Request bodies of APIs the worker must read (`_bulk`, `_msearch`, `_mget`, `_reindex`, `_aliases`, searches by an index-restricted grant) are buffered up to a cap (32 MiB by default, `--search-max-body-bytes`); a larger one is answered `413`. Other bodies stream. Responses stream and are never inspected. A connection that sends nothing for an hour ends. A request header section over 64 KiB ends the connection.
10. **Tests and demo.** Unit tests for the classifier (a table of about 120 request shapes, including the evasions above), subsumption, header scrubbing, NDJSON handling, and SigV4 against an independent fixture; worker tests against an in-process fake engine (policy enforcement, audit-before-forward, fail closed, streaming, keep-alive, reconnect); policy and CLI tests; a console projection test; and a compose scenario suite against real Elasticsearch 8.x and OpenSearch 2.x (auth, TLS, `curl`, bulk, scroll, denied index, hidden index, alias bypass documented). Demo: `demos/demo-phase10.sh`.

## Exit criteria (from the milestone)
`curl` and an official client work through `limen search connect` against compose Elasticsearch and OpenSearch; each request is audited with its index and method class; policy by index pattern is enforced; SigV4 is checked against a signature fixture. Anything that needs the real service is labelled *unverified against real service*: Amazon OpenSearch Service SigV4 acceptance and fine-grained access control mapping, OpenSearch Serverless, Elastic Cloud API keys, and TLS with the AWS bundle.

## Dependencies
None new for the protocol: `hyper`, `hyper-util`, `http-body-util`, `rustls`, `tokio-rustls` are already direct workspace dependencies (ADR-0012), and the SigV4 signer is the Phase 6 one. `hyper` and `http-body-util` become direct dependencies of `limen-worker`; they gain a "used by" note in ADR-0012, no new row.

## Open questions (recommendations applied)
1. **Default class.** `read` only when `classes` is omitted (recommended), against `read` and `write`. Granting write must be a visible choice.
2. **Hidden indices.** `*` does not match names starting with `.` (recommended; mirrors the engines' hidden-index behaviour).
3. **Scroll and PIT.** A scroll id or PIT id names no index, so the worker can't check it. Continuation and clearing are allowed for any grant that may search (the engine ties the search context to the engine user that opened it), and `_search` with a PIT and no index is refused to index-restricted grants. The alternative, tracking ids in responses, would mean parsing every response.
4. **Response filtering.** None. Index patterns bound what a request can name, not what a document or a `_cat` row reveals; the engine's document- and field-level security is the control for that.
5. **Cross-cluster search.** `index` expressions with `:` (`remote:logs-*`) are refused to restricted grants and classified as admin otherwise.
6. **Kibana and Dashboards.** Out of scope (Phase 12).

## Consequences
- \+ `curl`, the Elastic and OpenSearch clients, and tools such as `elasticdump` work unchanged and never see a credential.
- \+ The same session, audit, lock, kill, and drain machinery as SSH, databases, and Redis applies.
- \+ Unknown APIs fail closed.
- − The worker has to understand enough of two engines' REST surfaces to classify them; the table is the part to keep current, and an unrecognised API costs the user an `admin` grant, not safety.
- − Policy is on the names in the request. Aliases, data streams, and `_resolve` can point elsewhere: the engine's own role is the backstop and must be configured.
- − A request body that the worker must read is held in memory (up to the cap per session, twice for a gzip body).
- Threat model: a new data-store connection (HTTP to the engine) and a new class of upstream credential (API key, bearer, client certificate, SigV4); `docs/threat-model.md` gets rows when the code lands.

## As built (2026-10-18)
The open questions were settled with the recommendations. Where this section and the text above differ, this section is right.

1. **Default class, hidden indices, scroll/PIT, response filtering, cross-cluster, Kibana:** as recommended (questions 1 to 6). `*` does not open dot-prefixed indices; a pattern that starts with a dot does. `expand_wildcards=all` or `hidden` is refused unless a pattern starts with a dot.
2. **Where the code is.** `limen-worker/src/search/`: `rules.rs` (classification, index scope, body inspection, grant matching: pure functions with about 30 tests), `target.rs` (credentials, TLS, the connection to the engine, `SigV4`), `audit.rs` (events), `mod.rs` (the HTTP server toward the client and the per-request flow). The CLI is `limen-cli/src/commands/search.rs` and reuses the SSH/Redis session opener. The proxy gained a `Protocol::Search` and the `limen-search/1` ALPN.
3. **Policy shape.** `SearchGrant { roles, classes, indices }`; `SearchTarget { endpoint, region, aws, serverless, tls, audit }`. The new fields are left out of the policy snapshot while they have their defaults, so proxies and workers from before Phase 10 (which reject unknown fields) still read a policy that holds a plain search resource. A grant that sets `classes` or `indices`, or a target that sets `tls: false`, `serverless` or `audit`, needs the components upgraded first: control plane, then proxies, then workers.
4. **Limits as built.** Bodies the worker must read: 32 MiB by default (not 64), `--search-max-body-bytes`. Idle connections end after an hour, `--search-idle-timeout`. A response body that sends nothing for 15 minutes ends the connection. The head of a response may take 15 minutes. These are constants except where a flag is named.
5. **What the worker adds to the plan.** It opens the engine connection and sends `GET /` with its credential when a session is admitted, so a refused credential (401) or an unreachable server fails the session at once with a clean error instead of on the first request (a 403 on `/` is accepted: a role may not read the root). A 401 later is answered `502` without the engine's text, and the worker logs it. A connection the engine closed is replaced; a request is replayed once only when its body is in hand and either nothing was sent or the method is idempotent.
6. **Audit as built.** `search.request` holds `method`, `path` (document ids hashed with `redact_ids`), `api`, `class`, `indices` (at most 100, then `indices_truncated`), `indices_all`, `query_params` (names) or `query` (values, with `log_query`), `body_bytes`, `items` and `bulk` for `_bulk`, `body` with `log_bodies` (16 KiB, never for security APIs). `search.response` holds `request_id`, `status`, `outcome`, `duration_ms` (to the response head), `content_length`, `error_type`, and `by_worker` when the worker answered. If the response event can't be written, the connection is closed after that response. The bytes of the response body are not in the event; the proxy's `session.end` has the totals.
7. **Console.** `search.request`, `search.response` and `auth.denied` (`action: search`) are projected into the existing `db_statements` table, with no migration: statement type is the API name, the text is `METHOD /path`, the outcome is `ok`, `error` (HTTP status and engine error type), or `denied` (the reason).
8. **Metrics.** `limen_search_requests_total{class, result}` and `limen_search_upstream_seconds`.
9. **CLI.** A refusal reaches the client as an HTTP error with an engine-shaped body: `403` for what policy refuses, `503` for what Limen could not open (no worker, no capacity, the engine unreachable), so client retry logic does the right thing.
10. **Dependencies.** None new; `hyper`, `hyper-util`, `http-body-util`, and `flate2` become direct dependencies of the worker (ADR-0012 note). `tempfile` becomes a dev-dependency of the CLI.
11. **Tests.** Classifier and grant tests (pure functions); session tests against an in-process engine (policy, scrubbing, audit-before-forward, fail closed, streaming, keep-alive, reconnect, caps, idle, `SigV4`); the signature fixture; a console projection test; an end-to-end test through the real control plane, proxy, and worker (`limen-e2e/tests/phase10.rs`); and `demos/demo-phase10.sh` against Elasticsearch 8.15 and OpenSearch 2.17.
12. **Not verified:** Amazon OpenSearch Service, OpenSearch Serverless, Elastic Cloud, TLS with the Amazon bundle. Elasticsearch 7 and 9 and OpenSearch 1 and 3 were not run.

## Review (2026-10-18, by the author, from an Elasticsearch/OpenSearch operator's and an SRE's side)
One reviewer, one pass, over the finished diff and the demo run.

**Fixed in this PR**
- A client that stalls halfway through a body the worker must buffer held its session slot and a buffer until the session's time limit. Now `408` after 10 minutes.
- (Found while building and already fixed: idle pooled connections never ended; a rejected worker credential surfaced as the engine's 401 with its realm; Limen's "can't open the session" answers used `403`, which clients don't retry and operators misread, so they are `503`; gzip-compressed engine errors lost their `error.type`; a stalled engine response held a session for hours.)

**Engine-side findings, accepted and documented (guide "Limits")**
1. *Aliases and data streams.* Policy sees names, not targets. The engine role must be the real boundary.
2. *Scroll, PIT, and async-search IDs* name no index and are bearer values. Users who share an engine role could continue each other's contexts if an ID were shared, even when their Limen index grants differ. Mitigation today: give roles with different index grants different engine roles. Follow-up: track IDs per session.
3. *Query cost.* Nothing limits `size`, aggregation buckets, scripts, leading wildcards, or regex. Rely on the engine's circuit breakers, `search.max_buckets`, and timeouts. Follow-up: a per-grant cap and an injected `timeout`.
4. *SQL and PPL* name tables in text, so they need an unrestricted grant.
5. *No response filtering*, and `_cat` and `_nodes/stats` (read class) show node details. Use document- and field-level security, and grant `read` only to people who may see cluster topology.
6. *Scripts* in `_update_by_query` and `script_fields` can't be inspected; `write` is the gate.
7. Unusual index characters (`@`, `+`, `#`) are refused rather than guessed at.

**SRE findings, accepted and documented**
1. *Sessions multiply.* Each client connection is a Limen session, one connection to the engine, and one `GET /` at start. A pool of 20 is 20 sessions against `--max-sessions` (default 200) and the engine's connection limits. Size both.
2. *Memory is bounded by `cap × sessions`* (twice for gzip), not by the cap. Lower `--search-max-body-bytes` on small workers.
3. *Credential and CA changes need a worker restart* (they drain).
4. *Audit cost* is about two fsyncs per request.
5. *Drain and lock cut a request in flight*, as for databases.
6. *No per-session rate limit.* The engine's own throttling applies.
7. *The real-engine demo is manual* (it pulls about 2.4 GB of images and takes minutes to start the engines). CI runs the unit, session, console, and end-to-end tests, which need no engine.

## Amendment: concise role selectors (2026-10-23)

`search.roles` selects an existing OpenSearch or Elasticsearch identity and does not require a Limen prefix. The guides and examples use `read` and `write` for these engine roles; the prefixed example in the original decision is historical, not a current requirement.
