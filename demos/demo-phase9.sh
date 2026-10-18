#!/usr/bin/env bash
# Phase 9 demo: MongoDB through Limen. `mongosh` connects to a local listener
# without a password, the worker logs in to the server (SCRAM-SHA-256 or
# X.509), every command is checked and audited with its values redacted, and
# the console lists the commands of each session in place of a recording.
#
#   demos/demo-phase9.sh          # resets this demo's stack first (down -v)
#   demos/demo-phase9.sh --keep   # reuse the running stack
#
# Runs as its own compose project (limen-mongo) on its own ports, so it can
# sit next to the dev stack. Needs mongosh on the PATH (mise installs it).
set -euo pipefail
keep=false
[ "${1:-}" = "--keep" ] && keep=true

root="$(cd "$(dirname "$0")/.." && pwd)"
here="$root/deploy/compose"
# shellcheck source=../deploy/compose/scripts/dev-users.sh
source "$here/scripts/dev-users.sh"
# LIMEN_MONGO_PROJECT and the *_PORT variables let a second copy run beside this one.
project="${LIMEN_MONGO_PROJECT:-limen-mongo}"
state="$here/.state/$project"
mkdir -p "$state"
export LIMEN_MONGO_PROXY_PORT="${LIMEN_MONGO_PROXY_PORT:-37443}" LIMEN_MONGO_HEALTH_PORT="${LIMEN_MONGO_HEALTH_PORT:-37444}"
export LIMEN_MONGO_DEX_PORT="${LIMEN_MONGO_DEX_PORT:-37556}" LIMEN_MONGO_CP_PORT="${LIMEN_MONGO_CP_PORT:-37081}" LIMEN_MONGO_S3_PORT="${LIMEN_MONGO_S3_PORT:-37333}"
export LIMEN_PROJECT="$project" LIMEN_STATE_DIR="$state" LIMEN_IMAGE_TAG=mongo
export LIMEN_PORT_PROXY="$LIMEN_MONGO_PROXY_PORT" LIMEN_PORT_HEALTH="$LIMEN_MONGO_HEALTH_PORT" LIMEN_PORT_DEX="$LIMEN_MONGO_DEX_PORT"
export LIMEN_PORT_CP="$LIMEN_MONGO_CP_PORT" LIMEN_PORT_S3="$LIMEN_MONGO_S3_PORT"
export LIMEN_PORT_POSTGRES="${LIMEN_MONGO_PG_PORT:-37432}" LIMEN_PORT_KMS="${LIMEN_MONGO_KMS_PORT:-37099}"
# shellcheck source=../deploy/compose/scripts/lib.sh
source "$here/scripts/lib.sh"
stack_setup mongo
export LIMEN_HOME="$state/home"
export LIMEN_BIN="${LIMEN_BIN:-$root/target/release/limen}"
export LIMEN_PROXY="localhost:$LIMEN_MONGO_PROXY_PORT"
export LIMEN_DEX_URL="http://localhost:$LIMEN_MONGO_DEX_PORT"
export LIMEN_DEV_CA="$state/internal-ca.pem"
limen() { "$LIMEN_BIN" "$@"; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; exit 1; }
wait_for() {
  local what="$1"; shift
  for _ in $(seq 1 240); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done
  fail "timed out waiting for $what"
}
command -v mongosh >/dev/null || fail "mongosh is required (mise install, or https://www.mongodb.com/docs/mongodb-shell/install/)"
command -v docker >/dev/null || fail "docker is required"

listeners=()
# shellcheck disable=SC2034  # set by listen() through printf -v
URI_dev="" URI_x509="" URI_sre="" URI_lock=""
cleanup() { for p in "${listeners[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

# listen NAME LIMEN-ARGS...: start `limen mongo connect`, set URI_<NAME>.
listen() {
  local name="$1"; shift
  local log="$state/listen-$name.log"
  : > "$log"
  limen mongo connect "$@" > "$log" 2>&1 &
  listeners+=("$!")
  for _ in $(seq 1 60); do
    local uri
    uri="$(grep -o 'mongodb://[^"]*' "$log" | head -1 || true)"
    if [ -n "$uri" ]; then printf -v "URI_$name" '%s' "$uri"; return 0; fi
    sleep 0.25
  done
  cat "$log"; fail "no listener for $name"
}
# ms NAME JS: run JavaScript in mongosh through a Limen listener.
ms() { local var="URI_$1"; mongosh "${!var}" --quiet --eval "$2" 2>&1; }

step "Build and start the stack (MongoDB 8 with TLS, SCRAM and X.509; a worker; a proxy)"
# The image build caches cargo output across checkouts by file time; fresh times
# keep it from reusing another worktree's stale build of these crates.
find "$root/crates" -name '*.rs' -exec touch {} +
(cd "$root" && cargo build --release -q -p limen-cli)
if ! $keep; then
  echo "Resetting this demo's stack (project $project, down -v). Use --keep to skip."
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1
fi
"${compose[@]}" up -d --build --quiet-pull >/dev/null
wait_for "proxy readiness" curl -sf "http://localhost:$LIMEN_MONGO_HEALTH_PORT/readyz"
"${compose[@]}" cp control-plane:/var/lib/limen/ca-public/internal-ca.pem "$state/internal-ca.pem" >/dev/null
rm -rf "$LIMEN_HOME"
"$here/scripts/dev-login.sh" "$ADMIN" >/dev/null
limen admin apply "$root/examples/policy" --source-ref demo-phase9 >/dev/null
wait_for "worker tunnels" sh -c "curl -sf http://localhost:$LIMEN_MONGO_HEALTH_PORT/tunnels | grep -q worker_id"
# Proxy and worker pick up the new policy within their 10s refresh.
sleep 11
wait_for "mongodb" "${compose[@]}" exec -T mongo-target mongosh --quiet --tls --tlsCAFile /tls/ca.pem --host localhost -u limen-read -p limen-read-dev-only --authenticationDatabase admin orders --eval 'db.customers.countDocuments()'
pass "stack up, policy applied, MongoDB seeded"

step "developer reads their database with mongosh and no password"
"$here/scripts/dev-login.sh" "$DEVELOPER" >/dev/null
listen dev catalog-staging
cat "$state/listen-dev.log"
out="$(ms dev 'db.customers.countDocuments()')"; echo "countDocuments -> $out"
[ "$out" = "3" ] || fail "unexpected count: $out"
out="$(ms dev 'db.customers.find({email: "ada@example.com"}).toArray().map(d => d.name).join()')"; echo "find by email -> $out"
[ "$out" = "Ada" ] || fail "unexpected find: $out"
out="$(ms dev 'db.runCommand({connectionStatus: 1}).authInfo.authenticatedUsers[0].user')"; echo "logged in as -> $out"
[ "$out" = "limen-read" ] || fail "the worker should have logged in as limen-read: $out"
pass "limen mongo connect picked the only allowed role (limen-read) and the default database (orders)"

step "The server's own grants are the second layer"
out="$(ms dev 'db.customers.insertOne({name: "Mallory"})' || true)"; echo "insertOne -> $out"
grep -qi "not authorized" <<<"$out" || fail "the server should refuse the write: $out"
pass "Limen let the command through; MongoDB's read role for limen-read refused the write"

step "Limen refuses a database policy does not grant, before the server sees it"
out="$(ms dev 'db.getSiblingDB("billing").ledger.find().toArray()' || true)"; echo "billing -> $out"
grep -q "not authorized on billing" <<<"$out" || fail "billing should be refused: $out"
out="$(ms dev 'db.getSiblingDB("admin").runCommand({createUser: "mallory", pwd: "x", roles: []})' || true)"; echo "createUser -> $out"
grep -qi "not authorized" <<<"$out" || fail "createUser on admin should be refused: $out"
pass "billing and admin changes refused"

step "A client cannot log in as someone else"
port="${URI_dev#mongodb://127.0.0.1:}"; port="${port%%/*}"
out="$(mongosh "mongodb://root:hunter2@127.0.0.1:$port/orders?directConnection=true&authSource=admin" --quiet --eval 'db.customers.countDocuments()' 2>&1 || true)"
echo "$out" | head -3
grep -q "Limen has already authenticated" <<<"$out" || fail "credentials in the URI should be refused: $out"
pass "saslStart refused; the session still acts as limen-read"

step "An unlisted role is refused at the door"
if limen mongo connect catalog-staging --role limen-rw >"$state/deny.out" 2>"$state/deny.err"; then fail "developer must not get limen-rw"; fi
grep -o "you may not use.*" "$state/deny.err" | head -1
pass "developer cannot act as limen-rw"

step "X.509: the worker logs in with a client certificate"
listen x509 catalog-x509
out="$(ms x509 'db.runCommand({connectionStatus: 1}).authInfo.authenticatedUsers[0].user')"; echo "logged in as -> $out"
[ "$out" = "CN=limen-x509,O=Limen" ] || fail "X.509 login: $out"
out="$(ms x509 'db.customers.countDocuments()')"; [ "$out" = "3" ] || fail "x509 count: $out"
pass "MONGODB-X509 through the same relay"

step "sre writes a value and can't drop the database"
"$here/scripts/dev-login.sh" "$ADMIN" >/dev/null
listen sre catalog-staging --role limen-rw
out="$(ms sre 'db.audit_demo.insertOne({token: "hunter2-demo-value"}).acknowledged')"; echo "insertOne -> $out"
[ "$out" = "true" ] || fail "sre insert: $out"
out="$(ms sre 'db.audit_demo.find({token: "hunter2-demo-value"}).toArray().length')"; [ "$out" = "1" ] || fail "sre find: $out"
out="$(ms sre 'db.dropDatabase()' || true)"; echo "dropDatabase -> $out"
grep -q "Limen policy does not allow the dropDatabase command" <<<"$out" || fail "dropDatabase should be denied by policy: $out"
ms sre 'db.audit_demo.drop()' >/dev/null
pass "limen-rw can write; dropDatabase is in the grant's deny_commands"

step "Locking a user ends their open session"
"$here/scripts/dev-login.sh" "$DEVELOPER" >/dev/null
listen lock catalog-staging
# The driver retries a dropped server for its server-selection timeout; keep it short.
( mongosh "$URI_lock&serverSelectionTimeoutMS=3000" --quiet --eval 'while (true) { db.runCommand({ping: 1}); sleep(500); }' >"$state/lock.out" 2>&1 || true ) &
locked=$!
sleep 3
# The admin signs in under another home: the listener reads the developer's
# credentials for every new connection, and the driver reconnects.
export LIMEN_HOME_DEV="$LIMEN_HOME" LIMEN_HOME="$state/home-admin"
"$here/scripts/dev-login.sh" "$ADMIN" >/dev/null
limen admin lock "$DEVELOPER" --reason "demo: laptop stolen" >/dev/null
for _ in $(seq 1 80); do kill -0 "$locked" 2>/dev/null || break; sleep 0.5; done
if kill -0 "$locked" 2>/dev/null; then
  kill "$locked" 2>/dev/null || true
  limen admin unlock "$DEVELOPER" >/dev/null || true
  fail "the open session survived the lock"
fi
limen admin unlock "$DEVELOPER" >/dev/null
export LIMEN_HOME="$LIMEN_HOME_DEV"
pass "the mongosh loop stopped within seconds of the lock"

step "Audit trail"
sleep 8
"${compose[@]}" cp control-plane:/var/lib/limen/audit/control-plane.jsonl "$state/audit.jsonl" >/dev/null
python3 -I - "$state/audit.jsonl" <<'PY'
import collections, json, sys
text = open(sys.argv[1]).read()
events = [json.loads(l) for l in text.splitlines() if l.strip()]
print("  " + ", ".join(f"{k}={v}" for k, v in sorted(collections.Counter(e["kind"] for e in events).items())))
cmds = [e for e in events if e["kind"] == "mongo.command"]
forwarded = [e for e in cmds if e["data"]["phase"] == "forward"]
refused = [e for e in cmds if e["data"]["phase"] == "refused"]
assert forwarded, "mongo.command events"
find = [e for e in forwarded if e["user"] == "developer@example.com" and e["data"]["command"] == "find" and e["data"]["collection"] == "customers"]
assert any(e["data"]["summary"] == '{"filter":{"email":"?"}}' for e in find), "developer find with a redacted filter"
assert all(e["data"]["redacted"] for e in forwarded), "values are redacted"
assert {e["data"]["mongo_role"] for e in cmds} >= {"limen-read", "limen-rw"}
reasons = {e["data"]["reason"] for e in refused}
assert reasons >= {"database_not_granted", "auth_command", "command_denied"}, reasons
ends = {e["data"]["command_id"]: e for e in events if e["kind"] == "mongo.command.end"}
assert any(ends.get(e["event_id"], {}).get("data", {}).get("status") == "ok" for e in forwarded), "end events link to commands"
assert any(e["data"].get("error_code_name") == "Unauthorized" for e in ends.values()), "the server's refusal is recorded"
for secret in ("ada@example.com", "hunter2-demo-value", "hunter2", "limen-read-dev-only", "limen-rw-dev-only", "Mallory"):
    assert secret not in text, f"{secret!r} leaked into the audit trail"
starts = [e for e in events if e["kind"] == "session.start" and e["data"]["kind"] == "mongodb"]
closed = {e["session_id"] for e in events if e["kind"] == "session.end" and e["data"]["kind"] == "mongodb"}
assert starts and any(s["session_id"] in closed for s in starts), "session.start/end for mongodb"
assert all(e["session_id"] for e in cmds), "commands link to a session"
for e in forwarded[:4]:
    d = e["data"]
    print(f"  mongo.command {e['user']} {d['mongo_role']}: {d['command']} {d['database']}.{d.get('collection','')} {d['summary']}")
PY
pass "mongo.command (shapes, no values), mongo.command.end, refusals, session.start/end; no secret in the trail"

step "The console's session page lists the same commands (there is no recording)"
sleep 2
"${compose[@]}" exec -T postgres psql -U limen -d limen -At -F ' | ' -c \
  "select statement_type, left(statement, 70), coalesce(status,'…') from db_statements s join sessions x using (session_id) where x.kind = 'mongodb' and s.statement like 'orders.%' order by at desc limit 8" | tee "$state/console.out"
grep -q '{"filter":{"email":"?"}}' "$state/console.out" || fail "the console should list the find with its redacted filter"
pass "db_statements has the MongoDB commands for the session page"

printf '\n\033[32mPhase 9 demo passed.\033[0m\n'
echo "Stop it with: docker compose -p $project down -v"
