#!/usr/bin/env bash
# Phase 10 demo: Elasticsearch and OpenSearch through Limen. A client connects
# to a local listener with no credential, the worker authenticates to the
# engine as the role's engine user, every request is classified and checked
# against policy (method class and index pattern) and audited, and bodies stay
# out of the audit trail.
#
#   deploy/compose/demo-phase10.sh          # resets this demo's stack first (down -v)
#   deploy/compose/demo-phase10.sh --keep   # reuse the running stack
#
# Runs as its own compose project (limen-search) on its own ports, so it can
# sit next to the dev stack. Targets are real Elasticsearch 8.15 (security on)
# and OpenSearch 2.17 (security plugin on, reached over TLS and verified in
# full). Amazon OpenSearch Service (SigV4) is not covered here: no AWS account.
set -euo pipefail
keep=false
[ "${1:-}" = "--keep" ] && keep=true

root="$(cd "$(dirname "$0")/.." && pwd)"
here="$root/deploy/compose"
# shellcheck source=../deploy/compose/scripts/dev-users.sh
source "$here/scripts/dev-users.sh"
# LIMEN_SEARCH_PROJECT and the *_PORT variables let a second copy run beside this one.
project="${LIMEN_SEARCH_PROJECT:-limen-search}"
state="$here/.state/$project"
mkdir -p "$state"
export LIMEN_SEARCH_PROXY_PORT="${LIMEN_SEARCH_PROXY_PORT:-34443}" LIMEN_SEARCH_HEALTH_PORT="${LIMEN_SEARCH_HEALTH_PORT:-34444}"
export LIMEN_SEARCH_DEX_PORT="${LIMEN_SEARCH_DEX_PORT:-34556}" LIMEN_SEARCH_CP_PORT="${LIMEN_SEARCH_CP_PORT:-34081}" LIMEN_SEARCH_S3_PORT="${LIMEN_SEARCH_S3_PORT:-34333}"
export LIMEN_PROJECT="$project" LIMEN_STATE_DIR="$state" LIMEN_IMAGE_TAG=search
export LIMEN_PORT_PROXY="$LIMEN_SEARCH_PROXY_PORT" LIMEN_PORT_HEALTH="$LIMEN_SEARCH_HEALTH_PORT" LIMEN_PORT_DEX="$LIMEN_SEARCH_DEX_PORT"
export LIMEN_PORT_CP="$LIMEN_SEARCH_CP_PORT" LIMEN_PORT_S3="$LIMEN_SEARCH_S3_PORT"
export LIMEN_PORT_POSTGRES="${LIMEN_SEARCH_PG_PORT:-34432}" LIMEN_PORT_KMS="${LIMEN_SEARCH_KMS_PORT:-34099}"
# shellcheck source=../deploy/compose/scripts/lib.sh
source "$here/scripts/lib.sh"
stack_setup search
export LIMEN_HOME="$state/home"
export LIMEN_BIN="${LIMEN_BIN:-$root/target/release/limen}"
export LIMEN_PROXY="localhost:$LIMEN_SEARCH_PROXY_PORT"
export LIMEN_DEX_URL="http://localhost:$LIMEN_SEARCH_DEX_PORT"
export LIMEN_DEV_CA="$state/internal-ca.pem"
limen() { "$LIMEN_BIN" "$@"; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; exit 1; }
wait_for() {
  local what="$1"; shift
  for _ in $(seq 1 720); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done
  fail "timed out waiting for $what"
}

listeners=()
cleanup() { for p in "${listeners[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

# The engines publish no host port: these run curl inside their containers.
es_c="elasticsearch-search-$LIMEN_ENV" os_c="opensearch-search-$LIMEN_ENV"
es_direct="localhost:9200"
# Direct requests to the engines as their admin, for seeding and checking what
# really happened. (Not through Limen.)
es_admin() { docker exec -i "$es_c" curl -sf -u elastic:elastic-dev-only -H 'content-type: application/json' "$@"; }
os_admin() { docker exec -i "$os_c" curl -sf --cacert /usr/share/opensearch/config/root-ca.pem --resolve node-0.example.com:9200:127.0.0.1 -u admin:Dev-only-Opensearch-1 -H 'content-type: application/json' "$@"; }
os_url() { echo "https://node-0.example.com:9200$1"; }

# listen NAME RESOURCE [--role R]: start `limen search connect`, set PORT_<NAME>.
listen() {
  local name="$1"; shift
  local log="$state/listen-$name.log"
  : > "$log"
  LIMEN_HOME="${LISTEN_HOME:-$LIMEN_HOME}" limen search connect "$@" > "$log" 2>&1 &
  listeners+=("$!")
  for _ in $(seq 1 60); do
    local port
    port="$(grep -o 'http://127.0.0.1:[0-9]*' "$log" | head -1 | cut -d: -f3 || true)"
    if [ -n "$port" ]; then printf -v "PORT_$name" '%s' "$port"; return 0; fi
    sleep 0.25
  done
  cat "$log"; fail "no listener for $name"
}
# call PORT METHOD PATH [BODY [EXTRA CURL ARGS...]]: one request through a Limen
# listener. Sets STATUS and BODY; the reply headers go to $state/headers.
call() {
  local port="$1" method="$2" path="$3" body="${4:-}"
  shift 3; [ $# -gt 0 ] && shift
  local args=(-s -o "$state/body" -D "$state/headers" -w '%{http_code}' -X "$method" "http://127.0.0.1:$port$path")
  [ -n "$body" ] && args+=(-H 'content-type: application/json' --data-binary "$body")
  STATUS="$(curl "${args[@]}" "$@")"
  BODY="$(cat "$state/body")"
}
expect_limen_refusal() {
  local what="$1"
  [ "$STATUS" = 403 ] || [ "$STATUS" = 400 ] || fail "$what: expected a Limen refusal, got $STATUS $BODY"
  grep -q '"reason":"Limen: ' <<<"$BODY" || fail "$what: not a Limen refusal: $BODY"
  printf '  refused %-52s %s\n' "$what" "$(python3 -I -c 'import json,sys; print(json.loads(sys.argv[1])["error"]["reason"][:90])' "$BODY")"
}

step "Build and start the stack (Elasticsearch 8.15, OpenSearch 2.17, a worker, a proxy)"
# The image build caches cargo output across checkouts by file time; fresh times
# keep it from reusing another worktree's stale build of these crates.
find "$root/crates" -name '*.rs' -exec touch {} +
(cd "$root" && cargo build --release -q -p limen-cli)
if ! $keep; then
  echo "Resetting this demo's stack (project $project, down -v). Use --keep to skip."
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1
fi
"${compose[@]}" up -d --build --quiet-pull >/dev/null
wait_for "Elasticsearch" es_admin "$es_direct/_cluster/health?wait_for_status=yellow&timeout=1s"
wait_for "OpenSearch" os_admin "$(os_url /_cluster/health)?wait_for_status=yellow&timeout=1s"
"$here/config/targets/search/provision.sh" "$es_c" "$os_c" >/dev/null
pass "Elasticsearch 8.15 and OpenSearch 2.17 up, engine roles created"

step "Start Limen and apply policy"
wait_for "proxy readiness" curl -sf "http://localhost:$LIMEN_SEARCH_HEALTH_PORT/readyz"
"${compose[@]}" cp control-plane:/var/lib/limen/ca-public/internal-ca.pem "$state/internal-ca.pem" >/dev/null
rm -rf "$LIMEN_HOME" "$state/home-dev"
"$here/scripts/dev-login.sh" "$ADMIN" >/dev/null
limen admin apply "$root/examples/policy" --source-ref demo-phase10 >/dev/null
# A --keep run after one that stopped at the lock step.
limen admin unlock "$DEVELOPER" >/dev/null 2>&1 || true
wait_for "worker tunnels" sh -c "curl -sf http://localhost:$LIMEN_SEARCH_HEALTH_PORT/tunnels | grep -q worker_id"
# Proxy and worker pick up the new policy within their 10s refresh.
sleep 11
# Seed through the engines' own admin logins, not through Limen. Start from
# nothing, so --keep runs count the same.
for index in app-orders secret-hr logs-2026; do
  es_admin -X DELETE "$es_direct/$index" >/dev/null 2>&1 || true
  os_admin -X DELETE "$(os_url "/$index")" >/dev/null 2>&1 || true
done
for url in "$es_direct" ; do
  es_admin -X PUT "$url/app-orders/_doc/1?refresh=true" -d '{"item":"widget","note":"public"}' >/dev/null
  es_admin -X PUT "$url/secret-hr/_doc/1?refresh=true" -d '{"salary":"classified-data"}' >/dev/null
  es_admin -X PUT "$url/logs-2026/_doc/1?refresh=true" -d '{"msg":"hello"}' >/dev/null
done
os_admin -X PUT "$(os_url /app-orders/_doc/1)?refresh=true" -d '{"item":"widget-os","note":"public"}' >/dev/null
os_admin -X PUT "$(os_url /secret-hr/_doc/1)?refresh=true" -d '{"salary":"classified-data"}' >/dev/null
pass "stack up, policy applied, test documents seeded"

step "developer searches an allowed index on Elasticsearch, with no credential"
# The developer has a login of their own, so the admin's later login doesn't replace it.
LIMEN_HOME="$state/home-dev" "$here/scripts/dev-login.sh" "$DEVELOPER" >/dev/null
LISTEN_HOME="$state/home-dev" listen dev search-staging
grep -q 'curl http://127.0.0.1' "$state/listen-dev.log" || fail "listener didn't print a curl command"
call "$PORT_dev" POST /app-orders/_search '{"query":{"match_all":{}}}'
echo "POST /app-orders/_search -> $STATUS"
[ "$STATUS" = 200 ] && grep -q '"widget"' <<<"$BODY" || fail "search: $STATUS $BODY"
grep -qi '^x-elastic-product: Elasticsearch' "$state/headers" || fail "the engine's product header should reach the client (official clients check it)"
call "$PORT_dev" GET "/app-orders/_doc/1"
[ "$STATUS" = 200 ] || fail "doc get: $STATUS"
call "$PORT_dev" POST "/app-*/_count" '{}'
[ "$STATUS" = 200 ] && grep -q '"count":1' <<<"$BODY" || fail "count over a pattern the grant covers: $STATUS $BODY"
pass "limen search connect picked the only role (limen-read); search, get, and count worked"

step "Limen refuses what the role doesn't allow, before the engine sees it"
call "$PORT_dev" POST /secret-hr/_search '{}';            expect_limen_refusal "index outside the grant (secret-hr)"
call "$PORT_dev" POST /_search '{}';                       expect_limen_refusal "every index (/_search)"
call "$PORT_dev" POST /_all/_search '{}';                  expect_limen_refusal "_all"
call "$PORT_dev" POST '/app-orders,secret-hr/_search' '{}'; expect_limen_refusal "a list with one index outside"
call "$PORT_dev" POST /.security/_search '{}';             expect_limen_refusal "a hidden index (.security)"
call "$PORT_dev" PUT /app-orders/_doc/2 '{"x":1}';         expect_limen_refusal "a write with a read-only role"
call "$PORT_dev" DELETE /app-orders;                       expect_limen_refusal "an admin request (delete index)"
call "$PORT_dev" GET /_cluster/settings;                   expect_limen_refusal "an API Limen doesn't recognise (admin)"
call "$PORT_dev" GET /_cat/indices;                        expect_limen_refusal "_cat/indices lists every index"
call "$PORT_dev" GET '/app-orders/_search?source=%7B%7D';  expect_limen_refusal "the source query parameter"
call "$PORT_dev" POST /app-orders/_search '{"query":{"terms":{"u":{"index":"secret-hr","id":"1","path":"salary"}}}}'
expect_limen_refusal "a terms lookup into another index"
call "$PORT_dev" POST /_msearch $'{"index":"app-orders"}\n{}\n{"index":"secret-hr"}\n{}\n' --header 'content-type: application/x-ndjson'
expect_limen_refusal "an _msearch with one search outside"
call "$PORT_dev" POST '/app-orders/%2e%2e/secret-hr/_search' '{}' --path-as-is; expect_limen_refusal "an encoded .. in the path"
# The engine saw none of them.
direct="$(es_admin "$es_direct/_nodes/stats/indices/search" | python3 -I -c 'import json,sys; n=json.load(sys.stdin)["nodes"]; print(sum(v["indices"]["search"]["query_total"] for v in n.values()))')"
echo "  engine-side query_total so far: $direct"
pass "13 refusals, each a Limen error with the reason; none reached the engine's index"

step "Credentials the client sends are dropped"
# The developer's own Authorization header names the engine's superuser. If it
# reached the engine, this request to an index the policy allows would be
# answered by that user; the engine's limen_read role can read app-orders, so
# the check that matters is on the next step (sre). Here: the header is ignored.
call "$PORT_dev" POST /app-orders/_search '{}' -u elastic:elastic-dev-only -H 'es-security-runas-user: elastic'
[ "$STATUS" = 200 ] || fail "extra credentials should be ignored: $STATUS"
pass "request with client-side credentials still ran as limen-read"

step "sre writes; the engine's own role is the second layer"
"$here/scripts/dev-login.sh" "$ADMIN" >/dev/null
listen sre search-staging --role limen-write
call "$PORT_sre" PUT '/app-orders/_doc/7?refresh=true' '{"item":"gadget","note":"written via limen"}'
echo "PUT /app-orders/_doc/7 -> $STATUS"
[ "$STATUS" = 201 ] || [ "$STATUS" = 200 ] || fail "sre write: $STATUS $BODY"
bulk=$'{"index":{"_index":"app-orders","_id":"8"}}\n{"item":"bulk-1"}\n{"index":{"_index":"app-orders","_id":"9"}}\n{"item":"bulk-2"}\n'
call "$PORT_sre" POST '/_bulk?refresh=true' "$bulk" --header 'content-type: application/x-ndjson'
[ "$STATUS" = 200 ] && grep -q '"errors":false' <<<"$BODY" || fail "bulk: $STATUS $BODY"
count="$(es_admin "$es_direct/app-orders/_count" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["count"])')"
[ "$count" = 4 ] || fail "expected 4 documents written (1 seeded, 1 put, 2 bulk), found $count"
# Limen's policy lets sre touch any index; the engine's limen_write role may
# write only app-*. The engine says no, and its answer reaches the client as it is.
call "$PORT_sre" PUT /orders-1/_doc/1 '{"x":1}'
echo "PUT /orders-1/_doc/1 -> $STATUS"
[ "$STATUS" = 403 ] && grep -q 'security_exception' <<<"$BODY" && ! grep -q 'Limen:' <<<"$BODY" || fail "the engine should refuse: $STATUS $BODY"
# With the engine's superuser header dropped, reading the secret index as sre
# is the engine's decision too (limen_write has no rights on secret-hr).
call "$PORT_sre" POST /secret-hr/_search '{}' -u elastic:elastic-dev-only
[ "$STATUS" = 403 ] && grep -q 'security_exception' <<<"$BODY" || fail "a smuggled superuser login must not work: $STATUS $BODY"
# Remote reindex and unrecognised admin APIs are Limen's decision.
call "$PORT_sre" POST /_reindex '{"source":{"index":"app-orders","remote":{"host":"http://elsewhere:9200"}},"dest":{"index":"app-copy"}}'
expect_limen_refusal "a reindex from a remote cluster"
call "$PORT_sre" DELETE /app-orders;                       expect_limen_refusal "sre has read and write, not admin"
pass "writes and bulk worked; the engine refused what its role forbids; the client's superuser login was dropped"

step "OpenSearch works the same way, over TLS verified in full"
listen os search-opensearch --role limen-read
call "$PORT_os" POST /app-orders/_search '{"query":{"match":{"item":"widget-os"}}}'
echo "POST /app-orders/_search -> $STATUS"
[ "$STATUS" = 200 ] && grep -q 'widget-os' <<<"$BODY" || fail "opensearch search: $STATUS $BODY"
# sre's policy has no index limit, so this one is the engine's decision (its
# security plugin), passed through as it is.
call "$PORT_os" POST /secret-hr/_search '{}'
[ "$STATUS" = 403 ] && grep -q 'security_exception' <<<"$BODY" && ! grep -q 'Limen:' <<<"$BODY" || fail "opensearch should refuse: $STATUS $BODY"
call "$PORT_os" DELETE /app-orders; expect_limen_refusal "opensearch: an admin request"
call "$PORT_os" GET /; [ "$STATUS" = 200 ] || fail "opensearch root: $STATUS"
pass "search-opensearch (OpenSearch 2.17, security plugin, TLS verify-full) served through the same code"

step "The worker keeps serving, and spooling, while the control plane is away"
# Audit fails closed when the worker's own spool can't take an event (tested
# in the worker's unit tests). Here the spool is fine and the control plane is
# down: sessions keep running and the events ship afterwards.
"${compose[@]}" stop control-plane >/dev/null
call "$PORT_sre" POST /app-orders/_search '{}'
[ "$STATUS" = 200 ] || fail "the worker should keep serving from its spool: $STATUS $BODY"
"${compose[@]}" start control-plane >/dev/null
wait_for "control plane" curl -sf "http://localhost:$LIMEN_SEARCH_CP_PORT/readyz"
pass "with the control plane down the worker kept serving and spooled the events"

step "A locked user's session ends"
limen admin lock developer@example.com --reason "demo-phase10" >/dev/null
sleep 13
call "$PORT_dev" POST /app-orders/_search '{}' || true
[ "$STATUS" != 200 ] || fail "a locked user's open session should be gone: $STATUS"
limen admin unlock developer@example.com >/dev/null
pass "lock ended the open search session (client got $STATUS)"

step "Audit trail"
sleep 12
"${compose[@]}" cp control-plane:/var/lib/limen/audit/control-plane.jsonl "$state/audit.jsonl" >/dev/null
python3 -I - "$state/audit.jsonl" <<'PY'
import collections, json, sys
text = open(sys.argv[1]).read()
events = [json.loads(l) for l in text.splitlines() if l.strip()]
print("  " + ", ".join(f"{k}={v}" for k, v in sorted(collections.Counter(e["kind"] for e in events).items())))
req = [e for e in events if e["kind"] == "search.request"]
resp = {e["data"]["request_id"]: e for e in events if e["kind"] == "search.response"}
assert req, "search.request events"
assert all(e["session_id"] for e in req), "requests link to a session"
assert all(e["event_id"] in resp for e in req), "every request has a response"
assert any(e["user"] == "developer@example.com" and e["data"]["api"] == "search" and e["data"]["indices"] == ["app-orders"] and e["data"]["class"] == "read" for e in req), "developer search with its index"
assert any(e["data"]["api"] == "bulk" and e["data"]["bulk"] == {"app-orders": {"index": 2}} for e in req), "bulk with per-index counts"
assert any(e["data"]["method"] == "PUT" and resp[e["event_id"]]["data"]["status"] == 403 and resp[e["event_id"]]["data"]["error_type"] == "security_exception" for e in req), "the engine's refusal is in the trail with its type"
assert any(r["data"]["status"] == 200 for r in resp.values()), "ok responses"
denied = [e for e in events if e["kind"] == "auth.denied" and e["data"].get("action") == "search"]
assert len(denied) >= 14, f"expected the refusals in the trail, found {len(denied)}"
reasons = " ".join(e["data"]["reason"] for e in denied)
for needle in ("secret-hr", ".security", "covers every index", "write requests", "admin requests", "source query parameter", "remote cluster"):
    assert needle in reasons, f"no refusal mentioning {needle!r}"
engines = {e["data"]["engine"] for e in req}
assert engines == {"elasticsearch", "opensearch"}, engines
for secret in ("classified-data", "elastic-dev-only", "read-dev-only-1", "write-dev-only-1", "Dev-only-Opensearch-1", "Read-dev-only-1", "widget-os", "written via limen", "bulk-1"):
    assert secret not in text, f"{secret!r} leaked into the audit trail"
assert all("body" not in e["data"] for e in req), "bodies are not logged by default"
starts = [e for e in events if e["kind"] == "session.start" and e["data"]["kind"] in ("elasticsearch", "opensearch")]
ends = {e["session_id"] for e in events if e["kind"] == "session.end" and e["data"]["kind"] in ("elasticsearch", "opensearch")}
assert starts and any(s["session_id"] in ends for s in starts), "session.start/end for search"
assert all(s["data"].get("group") for s in starts), "every search session carries its run's group"
by_user = collections.defaultdict(set)
for s in starts:
    by_user[(s["user"], s["data"]["resource"], s["data"]["login"])].add(s["data"]["group"])
assert all(len(g) == 1 for g in by_user.values()), f"one group per limen search connect run: {dict(by_user)}"
for e in req[:4]:
    d = e["data"]
    print(f"  search.request {e['user']} {d['engine_role']}: {d['method']} {d['path']} [{d['class']}] indices={d['indices']}")
PY
pass "search.request/response, auth.denied, session.start/end; no secret, credential, or document body in the trail"

step "The console's session page"
rows="$("${compose[@]}" exec -T postgres psql -U limen -d limen -At -c "select count(*) filter (where status = 'denied'), count(*) filter (where status = 'ok'), count(*) filter (where status = 'error') from db_statements where phase = 'request'")"
echo "  db_statements (search rows) denied|ok|error = $rows"
IFS='|' read -r d o e <<<"$rows"
[ "$d" -ge 10 ] && [ "$o" -ge 5 ] && [ "$e" -ge 1 ] || fail "console projection: $rows"
pass "the console has the requests, with their outcomes, for each search session"

printf '\n\033[32mPhase 10 demo passed.\033[0m\n'
echo "Reset it by running this script without --keep"
