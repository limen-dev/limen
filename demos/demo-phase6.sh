#!/usr/bin/env bash
# Phase 6 demo: `psql` and `mysql` through `limen db connect` to real
# PostgreSQL and MySQL servers, with no password, every statement audited,
# idempotent role bootstrap, and an open session ending when its user is locked
# (design.md section 13).
#
# Runs its own compose project (limen-dbdemo: the Limen core plus stacks/db.yml)
# with its own volumes, images and host ports; the dev stack is never touched. The database
# clients run in throwaway containers (postgres and mysql images) so nothing
# needs installing on the host; they reach the CLI's listener through
# host.docker.internal, which is why the listener here binds 0.0.0.0. On a real
# machine, bind the default 127.0.0.1 and use psql or mysql directly.
#
#   demos/demo-phase6.sh          # resets the demo stack first (down -v)
#   demos/demo-phase6.sh --keep   # reuse the running demo stack
set -euo pipefail
keep=false
[ "${1:-}" = "--keep" ] && keep=true

root="$(cd "$(dirname "$0")/.." && pwd)"
here="$root/deploy/compose"
# shellcheck source=../deploy/compose/.env
set -a; source "$here/.env"; set +a # image versions
# shellcheck source=../deploy/compose/scripts/dev-users.sh
source "$here/scripts/dev-users.sh"
state="$here/.state/db-demo"
export LIMEN_PROJECT=limen-dbdemo LIMEN_STATE_DIR="$state" LIMEN_IMAGE_TAG=dbdemo
# The CP, S3, Postgres and KMS ports are not default + 40000: that is where setup.sh moves a busy default.
export LIMEN_PORT_PROXY=43443 LIMEN_PORT_HEALTH=43444 LIMEN_PORT_DEX=45556 LIMEN_PORT_CP=49081
export LIMEN_PORT_S3=49333 LIMEN_PORT_POSTGRES=49432 LIMEN_PORT_KMS=49099
# shellcheck source=../deploy/compose/scripts/lib.sh
source "$here/scripts/lib.sh"
stack_setup db
export LIMEN_HOME="$state/home"
export LIMEN_BIN="${LIMEN_BIN:-$root/target/release/limen}"
export LIMEN_PROXY=localhost:43443
export LIMEN_DEV_CA="$state/internal-ca.pem"
export LIMEN_DEX_URL=http://localhost:45556
pg_port=55432
my_port=53306
limen() { "$LIMEN_BIN" "$@"; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; exit 1; }
wait_for() {
  local what="$1"; shift
  for _ in $(seq 1 240); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done
  fail "timed out waiting for $what"
}
psql_in() { docker run --rm "$POSTGRES_IMAGE" psql "host=host.docker.internal port=$pg_port user=${1} dbname=${2} sslmode=disable" "${@:3}"; }
# A named client container, so a signal can be sent to exactly this one.
psql_named() { local name="$1"; shift; docker run --rm --name "$name" "$POSTGRES_IMAGE" psql "host=host.docker.internal port=$pg_port user=${1} dbname=${2} sslmode=disable" "${@:3}"; }
mysql_in() { docker run --rm "$MYSQL_IMAGE" mysql -h host.docker.internal -P "$my_port" -u "${1}" --ssl-mode=DISABLED "${@:2}"; }
command -v docker >/dev/null || fail "docker is required"
listeners=()
cleanup() {
  for pid in ${listeners[@]+"${listeners[@]}"}; do kill "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT

step "Build and start the stack (PostgreSQL 18 and MySQL 8.4 with TLS, a worker, a proxy)"
(cd "$root" && cargo build --release -q -p limen-cli)
if ! $keep; then
  echo "Resetting the demo stack (docker compose down -v). Use --keep to skip."
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1
fi
"${compose[@]}" up -d --build --quiet-pull >/dev/null
wait_for "proxy readiness" curl -sf http://localhost:43444/readyz
mkdir -p "$state"
"${compose[@]}" cp control-plane:/var/lib/limen/ca-public/internal-ca.pem "$state/internal-ca.pem" >/dev/null
rm -rf "$LIMEN_HOME"
"$here/scripts/dev-login.sh" "$ADMIN" >/dev/null
limen admin apply "$root/examples/policy" --source-ref demo-phase6 >/dev/null
wait_for "worker tunnels" sh -c "curl -sf http://localhost:43444/tunnels | grep -q worker_id"
sleep 11   # proxy and worker pick up the policy within their 10 s refresh
wait_for "postgres-target" "${compose[@]}" exec -T postgres-target pg_isready -U postgres
wait_for "mysql-target" "${compose[@]}" exec -T mysql-target mysqladmin ping -h 127.0.0.1 -uroot -pmysql-target-dev-only --silent
pass "stack up, policy applied"

step "Role bootstrap: the databases have no limen_* roles yet"
set +e
"${compose[@]}" run --rm db-bootstrap --db-bootstrap-once --db-bootstrap-check >"$state/check1.log" 2>&1
rc=$?
set -e
grep -E "needed|nothing to change" "$state/check1.log" | sed 's/^/  /' | cut -c1-200 | head -8
[ "$rc" = 2 ] || { cat "$state/check1.log"; fail "check mode should exit 2 (differences), got $rc"; }
pass "check mode reports the missing roles and changes nothing (exit 2)"

step "Role bootstrap: create the roles, then run it again"
"${compose[@]}" run --rm db-bootstrap --db-bootstrap-once >"$state/apply1.log" 2>&1 || { cat "$state/apply1.log"; fail "bootstrap failed"; }
grep -E "\[done\]" "$state/apply1.log" | sed 's/^/  /' | cut -c1-200 | head -12
"${compose[@]}" run --rm db-bootstrap --db-bootstrap-once >"$state/apply2.log" 2>&1 || { cat "$state/apply2.log"; fail "second bootstrap failed"; }
grep -q "nothing to change" "$state/apply2.log" || { cat "$state/apply2.log"; fail "the second run must change nothing"; }
! grep -qE "\[done\]|FAILED" "$state/apply2.log" || fail "the second run changed something"
"${compose[@]}" run --rm db-bootstrap --db-bootstrap-once --db-bootstrap-check >/dev/null 2>&1 || fail "check mode must now exit 0"
pass "idempotent: the second run did nothing, check mode exits 0"

step "developer opens the PostgreSQL and MySQL listeners (limen db connect)"
"$here/scripts/dev-login.sh" "$DEVELOPER" >/dev/null
limen ls | sed 's/^/  /'
limen db connect orders-staging --listen "0.0.0.0:$pg_port" >"$state/db-pg.log" 2>&1 &
listeners+=($!)
limen db connect orders-mysql-staging --listen "0.0.0.0:$my_port" >"$state/db-my.log" 2>&1 &
listeners+=($!)
wait_for "the PostgreSQL listener" grep -q "Limen is ready" "$state/db-pg.log"
wait_for "the MySQL listener" grep -q "Limen is ready" "$state/db-my.log"
grep -A1 "ready for" "$state/db-pg.log" | sed 's/^/  /'
grep -A1 "ready for" "$state/db-my.log" | sed 's/^/  /'
pass "both listeners are up (the role was chosen from policy; no password anywhere)"

step "psql and mysql work, as the database role policy allows"
out="$(psql_in limen_read orders -At -c 'select count(*) from orders' -c "select current_user, current_database(), left(current_setting('application_name'), 6)")"
echo "$out" | sed 's/^/  postgres: /'
grep -q '^3$' <<<"$out" || fail "unexpected psql output: $out"
grep -q 'limen_read|orders|limen:' <<<"$out" || fail "the session isn't visible to the database: $out"
out="$(mysql_in limen_read orders -N -e 'select count(*) from orders; select current_user()' 2>/dev/null)"
echo "$out" | sed 's/^/  mysql:    /'
grep -q '^3$' <<<"$out" || fail "unexpected mysql output: $out"
grep -q 'limen_read@' <<<"$out" || fail "unexpected mysql user: $out"
pass "3 orders through each; the databases see the limen_read role and (PostgreSQL) the Limen session id"

step "The database's own grants decide what the role may do"
if psql_in limen_read orders -c "insert into orders (total_cents) values (1)" 2>"$state/pg-deny.err"; then fail "read-only role must not insert"; fi
grep -o "permission denied.*" "$state/pg-deny.err" | head -1 | sed 's/^/  postgres: /'
if mysql_in limen_read orders -e "insert into orders (total_cents) values (1)" 2>"$state/my-deny.err"; then fail "read-only user must not insert"; fi
grep -o "ERROR 1142.*" "$state/my-deny.err" | head -1 | sed 's/^/  mysql:    /'
pass "inserts are refused by PostgreSQL and MySQL themselves, and audited"

step "Denials at Limen"
if limen db connect orders-staging --db-role limen_write --listen 127.0.0.1:0 2>"$state/role.err"; then fail "developer must not get limen_write"; fi
grep -o "you may not use.*" "$state/role.err" | head -1 | sed 's/^/  /'
if limen db connect orders-prod 2>"$state/prod.err"; then fail "developer has no access to orders-prod"; fi
grep -o "you have no database access.*" "$state/prod.err" | head -1 | sed 's/^/  /'
if psql_in limen_write orders -c 'select 1' 2>"$state/user.err"; then fail "the session is for limen_read only"; fi
grep -o "this session is for.*" "$state/user.err" | head -1 | sed 's/^/  /'
pass "another role, another resource, and another login are all refused"

step "Cancel: a client's cancel request (Ctrl-C in psql) works through Limen"
docker rm -f limen-demo-sleep >/dev/null 2>&1 || true
( psql_named limen-demo-sleep limen_read orders -c 'select pg_sleep(60)' >"$state/sleep.out" 2>&1 || true ) &
sleeper=$!
sleep 4
docker kill --signal=INT limen-demo-sleep >/dev/null
wait "$sleeper" || true
grep -q "canceling statement" "$state/sleep.out" || { cat "$state/sleep.out"; fail "the sleeping query wasn't cancelled"; }
pass "the cancel reached the database: $(grep -o 'canceling statement[^.]*' "$state/sleep.out" | head -1)"

step "Locking the developer ends an open session at once"
docker rm -f limen-demo-lock >/dev/null 2>&1 || true
( psql_named limen-demo-lock limen_read orders -c 'select pg_sleep(120)' >"$state/lock.out" 2>&1 || true ) &
locked=$!
sleep 4
"$here/scripts/dev-login.sh" "$ADMIN" >/dev/null
limen admin lock "$DEVELOPER" --reason "demo: laptop stolen" >/dev/null
started=$SECONDS
while kill -0 "$locked" 2>/dev/null; do
  if [ $((SECONDS - started)) -ge 25 ]; then
    docker rm -f limen-demo-lock >/dev/null 2>&1 || true
    limen admin unlock "$DEVELOPER" >/dev/null
    fail "the open session survived the lock"
  fi
  sleep 1
done
limen admin unlock "$DEVELOPER" >/dev/null
pass "the open session ended $((SECONDS - started)) s after the lock"

step "Audit trail: sessions, every statement, errors, bootstrap; no secrets"
sleep 8   # components ship events through their spools
"${compose[@]}" cp control-plane:/var/lib/limen/audit/control-plane.jsonl "$state/audit.jsonl" >/dev/null
pw_pg="$(docker run --rm -v limen-dbdemo_db-secrets:/s "$ALPINE_IMAGE" cat /s/postgres/limen_read)"
pw_my="$(docker run --rm -v limen-dbdemo_db-secrets:/s "$ALPINE_IMAGE" cat /s/mysql/limen_read)"
python3 - "$state/audit.jsonl" "$DEVELOPER" "$pw_pg" "$pw_my" <<'PY'
import collections, json, sys
path, dev, pw_pg, pw_my = sys.argv[1:5]
raw = open(path).read()
events = [json.loads(l) for l in raw.splitlines()]
kinds = collections.Counter(e["kind"] for e in events)
print("  " + ", ".join(f"{k}={v}" for k, v in sorted(kinds.items())))
assert pw_pg not in raw and pw_my not in raw and "limen-admin-dev-only" not in raw, "a password is in the audit trail"
starts = [e for e in events if e["kind"] == "session.start" and e["data"]["kind"] in ("postgres", "mysql")]
assert {e["data"]["kind"] for e in starts} == {"postgres", "mysql"}, "both kinds of session"
ends = {e["session_id"] for e in events if e["kind"] == "session.end"}
queries = [e for e in events if e["kind"] == "db.query" and e["user"] == dev]
qends = [e for e in events if e["kind"] == "db.query.end"]
def stmt(text, proto):
    for e in queries:
        if e["data"]["protocol"] == proto and (e["data"].get("statement") or "").startswith(text):
            return e
    raise AssertionError(f"no {proto} statement {text!r}")
pg = stmt("select count(*) from orders", "postgres")
my = stmt("select count(*) from orders", "mysql")
session_ids = {e["session_id"] for e in starts}
assert pg["session_id"] in session_ids and my["session_id"] in session_ids, "statements link to proxy sessions"
assert pg["producer"]["component"] == "worker" and pg["data"]["db_role"] == "limen_read"
ok = [e for e in qends if e["data"]["query_id"] == pg["event_id"]]
assert ok and ok[0]["data"]["status"] == "ok" and ok[0]["data"]["rows"] == 1, "rows and status on the end event"
denied_pg = [e for e in qends if e["data"].get("error_code") == "42501"]
denied_my = [e for e in qends if e["data"].get("error_number") == 1142]
assert denied_pg and denied_my, "the refused inserts are audited with the database's error"
boot = [e for e in events if e["kind"] == "db.bootstrap"]
assert {e["data"]["action"] for e in boot} >= {"create_role", "ensure_user", "grant"}, "bootstrap changes are audited"
denials = [e for e in events if e["kind"] == "auth.denied" and e["data"].get("action") == "db"]
print(f"  db.query={len(queries)} db.query.end={len(qends)} db.bootstrap={len(boot)} auth.denied(db)={len(denials)}")
for e in (pg, my):
    print(f"  {e['data']['protocol']:8} {e['user']} {e['data']['db_role']}@{e['data']['database']}: {e['data']['statement']}")
PY
if "${compose[@]}" logs worker 2>&1 | grep -qF "$pw_pg"; then fail "a password is in the worker log"; fi
pass "sessions, statements, outcomes, and bootstrap changes are in the trail, linked by id; no password anywhere"

printf '\n\033[32mPhase 6 demo passed.\033[0m\n'
