#!/usr/bin/env bash
# Phase 7 demo: Redis and Valkey through Limen. A client connects to a local
# listener without a password, the worker logs in to the server as the role's
# ACL user, every command is checked and audited, and values stay out of the
# audit trail.
#
#   demos/demo-phase7.sh                          # resets this demo's stack first (down -v)
#   demos/demo-phase7.sh --keep                   # reuse the running stack
#   demos/demo-phase7.sh --scenarios              # then also run the 26 scenarios (below)
#   demos/demo-phase7.sh --scenarios NAME ...     # only the scenarios whose name contains NAME
#   demos/demo-phase7.sh --scenarios --down       # ... and remove the stack afterwards
#
# The scenarios are many ways to use, abuse and break Redis access through Limen, against
# Redis 7.4 and Valkey 8.0 and a TLS-only Redis (RESP3, 20 MiB values, 60,000-command
# pipelines, refusals inside pipelines and MULTI, Pub/Sub, key-limit escapes, malformed input,
# 16 parallel sessions, a target dying mid-session, a lock ending a session, a control plane
# outage, unix sockets, the idle timeout, secrets in logs and audit). They run on this same
# stack, after the walkthrough, with the TLS Redis, a second policy and one login profile per
# person added (config/targets/redis/).
#
# Runs as its own compose project (limen-redis) on its own ports, so it can
# sit next to the dev stack. redis-cli is used when installed; otherwise a
# small RESP client (config/targets/redis/resp-client.py) stands in for it.
set -euo pipefail
keep=false; down=false; scenarios=false; scn_args=()
while [ $# -gt 0 ]; do
  case "$1" in
    --keep) keep=true ;;
    --down) down=true ;;
    --scenarios) scenarios=true ;;
    -*) echo "usage: $0 [--keep] [--down] [--scenarios [NAME ...]]" >&2; exit 2 ;;
    *) scn_args+=("$1") ;;   # scenario names
  esac
  shift
done

root="$(cd "$(dirname "$0")/.." && pwd)"
here="$root/deploy/compose"
# shellcheck source=../deploy/compose/scripts/dev-users.sh
source "$here/scripts/dev-users.sh"
state="$here/.state/${LIMEN_REDIS_PROJECT:-limen-redis}"
mkdir -p "$state"
# LIMEN_REDIS_PROJECT and the *_PORT variables let a second copy run beside this one.
project="${LIMEN_REDIS_PROJECT:-limen-redis}"
export LIMEN_REDIS_PROXY_PORT="${LIMEN_REDIS_PROXY_PORT:-33443}" LIMEN_REDIS_HEALTH_PORT="${LIMEN_REDIS_HEALTH_PORT:-33444}"
export LIMEN_REDIS_DEX_PORT="${LIMEN_REDIS_DEX_PORT:-35556}" LIMEN_REDIS_CP_PORT="${LIMEN_REDIS_CP_PORT:-33081}" LIMEN_REDIS_S3_PORT="${LIMEN_REDIS_S3_PORT:-38333}"
export LIMEN_PROJECT="$project" LIMEN_STATE_DIR="$state" LIMEN_IMAGE_TAG=redis
export LIMEN_PORT_PROXY="$LIMEN_REDIS_PROXY_PORT" LIMEN_PORT_HEALTH="$LIMEN_REDIS_HEALTH_PORT" LIMEN_PORT_DEX="$LIMEN_REDIS_DEX_PORT"
export LIMEN_PORT_CP="$LIMEN_REDIS_CP_PORT" LIMEN_PORT_S3="$LIMEN_REDIS_S3_PORT"
export LIMEN_PORT_POSTGRES="${LIMEN_REDIS_PG_PORT:-35432}" LIMEN_PORT_KMS="${LIMEN_REDIS_KMS_PORT:-38099}"
# shellcheck source=../deploy/compose/scripts/lib.sh
source "$here/scripts/lib.sh"
stack_setup redis
export LIMEN_HOME="$state/home"
export LIMEN_BIN="${LIMEN_BIN:-$root/target/release/limen}"
export LIMEN_PROXY="localhost:$LIMEN_REDIS_PROXY_PORT"
export LIMEN_DEX_URL="http://localhost:$LIMEN_REDIS_DEX_PORT"
export LIMEN_DEV_CA="$state/internal-ca.pem"
limen() { "$LIMEN_BIN" "$@"; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; exit 1; }
wait_for() {
  local what="$1"; shift
  for _ in $(seq 1 120); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done
  fail "timed out waiting for $what"
}

listeners=()
cleanup() { for p in "${listeners[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

# rc PORT COMMAND...: one command through a Limen listener.
rc() {
  local port="$1"; shift
  if command -v redis-cli >/dev/null; then
    redis-cli -h 127.0.0.1 -p "$port" "$@" 2>&1
  else
    python3 -I "$here/config/targets/redis/resp-client.py" "$port" "$@" 2>&1
  fi
}
# listen NAME RESOURCE [--user U]: start `limen redis connect`, set PORT_<NAME>.
listen() {
  local name="$1"; shift
  local log="$state/listen-$name.log"
  : > "$log"
  limen redis connect "$@" > "$log" 2>&1 &
  listeners+=("$!")
  for _ in $(seq 1 60); do
    local port
    port="$(grep -o '\-p [0-9]*' "$log" | head -1 | cut -d' ' -f2 || true)"
    if [ -n "$port" ]; then printf -v "PORT_$name" '%s' "$port"; return 0; fi
    sleep 0.25
  done
  cat "$log"; fail "no listener for $name"
}
target() { "${compose[@]}" exec -T "$1" "$2" --user write --pass rw-dev-only --no-auth-warning "${@:3}"; }

step "Build and start the stack"
# The image build caches cargo output across checkouts by file time; fresh times
# keep it from reusing another worktree's stale build of these crates.
find "$root/crates" -name '*.rs' -exec touch {} +
(cd "$root" && cargo build --release -q -p limen-cli)
if ! $keep; then
  echo "Resetting this demo's stack (project $project, down -v). Use --keep to skip."
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1
fi
"${compose[@]}" up -d --build --quiet-pull >/dev/null
wait_for "proxy readiness" curl -sf http://localhost:$LIMEN_REDIS_HEALTH_PORT/readyz
"${compose[@]}" cp control-plane:/var/lib/limen/ca-public/internal-ca.pem "$state/internal-ca.pem" >/dev/null
rm -rf "$LIMEN_HOME"
"$here/scripts/dev-login.sh" "$ADMIN" >/dev/null
limen admin apply "$root/examples/policy" --source-ref demo-phase7 >/dev/null
wait_for "worker tunnels" sh -c "curl -sf http://localhost:$LIMEN_REDIS_HEALTH_PORT/tunnels | grep -q worker_id"
# Proxy and worker pick up the new policy within their 10s refresh.
sleep 11
wait_for "redis" "${compose[@]}" exec -T redis-target redis-cli --user write --pass rw-dev-only --no-auth-warning ping
wait_for "valkey" "${compose[@]}" exec -T valkey-target valkey-cli --user write --pass rw-dev-only --no-auth-warning ping
target redis-target redis-cli SET app:greeting hello >/dev/null
target redis-target redis-cli SET secret:1 classified-data >/dev/null
target valkey-target valkey-cli SET app:greeting hello-from-valkey >/dev/null
pass "stack up, policy applied, test keys seeded"

step "developer reads an allowed key on Redis, with no password"
"$here/scripts/dev-login.sh" "$DEVELOPER" >/dev/null
listen dev cache-staging
out="$(rc "$PORT_dev" GET app:greeting)"; echo "GET app:greeting -> $out"
[ "$out" = "hello" ] || fail "unexpected reply: $out"
pass "limen redis connect inferred the only allowed user (read) and GET worked"

step "Limen refuses what the role doesn't allow, before the server sees it"
for cmd in "GET secret:1" "KEYS *" "FLUSHALL" "CONFIG GET maxmemory" "EVAL return-1 0" "MONITOR"; do
  read -ra words <<<"$cmd"
  out="$(rc "$PORT_dev" "${words[@]}")"; echo "$cmd -> $out"
  grep -q "NOPERM Limen" <<<"$out" || fail "$cmd should be refused by Limen: $out"
done
pass "key pattern, KEYS, FLUSHALL, CONFIG, EVAL, MONITOR all refused"

step "The server's own ACL is the second layer"
out="$(rc "$PORT_dev" SET app:x 1)"; echo "SET app:x 1 -> $out"
grep -qi "NOPERM" <<<"$out" && ! grep -q "Limen" <<<"$out" || fail "the server should have refused the write: $out"
pass "Limen allowed the key; Redis' ACL for read refused the write"

step "Replies stay in order when a pipelined command is refused"
out="$(python3 -I "$here/config/targets/redis/resp-client.py" "$PORT_dev" --pipeline GET app:greeting \; FLUSHALL \; GET app:greeting)"
echo "$out"
[ "$(sed -n 1p <<<"$out")" = "hello" ] && grep -q "NOPERM Limen" <<<"$(sed -n 2p <<<"$out")" && [ "$(sed -n 3p <<<"$out")" = "hello" ] || fail "reply order: $out"
pass "hello, refused, hello"

step "The client's own AUTH is accepted and never reaches the server"
out="$(rc "$PORT_dev" AUTH default not-the-password)"; echo "AUTH -> $out"
[ "$out" = "OK" ] || fail "AUTH reply: $out"
out="$(rc "$PORT_dev" GET app:greeting)"
[ "$out" = "hello" ] || fail "still authenticated as read: $out"
pass "AUTH swallowed; the session still acts as the role's user"

step "Valkey works the same way"
listen valkey cache-valkey
out="$(rc "$PORT_valkey" GET app:greeting)"; echo "GET app:greeting -> $out"
[ "$out" = "hello-from-valkey" ] || fail "valkey: $out"
pass "cache-valkey (Valkey 8) served through the same code"

step "An unlisted Redis user is refused at the door"
if limen redis connect cache-staging --user write >"$state/deny.out" 2>"$state/deny.err"; then fail "developer must not get write"; fi
grep -o "access denied.*" "$state/deny.err" | head -1
pass "developer cannot act as write"

step "sre writes a secret value; it must stay out of the audit trail"
"$here/scripts/dev-login.sh" "$ADMIN" >/dev/null
listen sre cache-staging --user write
rc "$PORT_sre" SET app:token hunter2-demo-value | grep -q OK || fail "sre SET"
out="$(rc "$PORT_sre" GET app:token)"; [ "$out" = "hunter2-demo-value" ] || fail "sre GET: $out"
out="$(rc "$PORT_sre" FLUSHALL)"; echo "FLUSHALL -> $out"
grep -q "NOPERM Limen" <<<"$out" || fail "FLUSHALL should be denied even for sre"
pass "sre can write, and still can't FLUSHALL (default deny list)"

step "Audit trail"
sleep 8
"${compose[@]}" cp control-plane:/var/lib/limen/audit/control-plane.jsonl "$state/audit.jsonl" >/dev/null
python3 -I - "$state/audit.jsonl" <<'PY'
import collections, json, sys
text = open(sys.argv[1]).read()
events = [json.loads(l) for l in text.splitlines() if l.strip()]
print("  " + ", ".join(f"{k}={v}" for k, v in sorted(collections.Counter(e["kind"] for e in events).items())))
cmds = [e for e in events if e["kind"] == "redis.command"]
assert cmds, "redis.command events"
assert any(e["user"] == "developer@example.com" and e["data"]["command"] == "GET" and e["data"]["keys"] == ["app:greeting"] for e in cmds), "developer GET with its key"
assert any(e["data"]["command"] == "SET" and e["data"]["keys"] == ["app:token"] for e in cmds), "sre SET with its key"
assert all(e["data"]["redis_user"] in ("read", "write") for e in cmds)
denied = [e for e in events if e["kind"] == "auth.denied" and e["data"].get("action") == "redis"]
assert {e["data"].get("command") for e in denied} >= {"FLUSHALL", "KEYS", "CONFIG", "GET"}, "denied commands audited"
for secret in ("hunter2-demo-value", "classified-data", "not-the-password"):
    assert secret not in text, f"{secret!r} leaked into the audit trail"
starts = [e for e in events if e["kind"] == "session.start" and e["data"]["kind"] == "redis"]
ends = {e["session_id"] for e in events if e["kind"] == "session.end" and e["data"]["kind"] == "redis"}
assert starts and any(s["session_id"] in ends for s in starts), "session.start/end for redis"
assert all(e["session_id"] for e in cmds), "commands link to a session"
for e in cmds[:4]:
    print(f"  redis.command {e['user']} {e['data']['redis_user']}: {e['data']['command']} {e['data']['keys']}")
PY
pass "redis.command (keys, no values), auth.denied, session.start/end; no secret value in the trail"

printf '\n\033[32mPhase 7 demo passed.\033[0m\n'

status=0
if $scenarios; then
  step "Scenarios: a TLS-only Redis, a second policy, and a login profile per person"
  # The TLS Redis and the CA the worker trusts for it; the certificates are made here.
  mkdir -p "$state/tls"
  if [ ! -f "$state/tls/server.crt" ]; then
    (cd "$state/tls" \
      && openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 2 -subj "/CN=limen-scenario-ca" 2>/dev/null \
      && openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=redis-tls" 2>/dev/null \
      && printf 'subjectAltName=DNS:redis-tls\n' > san.cnf \
      && openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 2 -extfile san.cnf 2>/dev/null \
      && chmod 644 ./*.crt ./*.key)
  fi
  export LIMEN_REDIS_TLS_DIR="$state/tls"
  STACK_FLAGS+=(-f "$here/config/targets/redis/tls-overlay.yml")
  compose=(docker compose --progress=quiet "${STACK_FLAGS[@]}")
  "${compose[@]}" up -d --build --quiet-pull >/dev/null   # adds redis-tls, restarts the worker with its CA
  # Two profiles: LIMEN_HOME is per person.
  export HOME_ADMIN="$state/home-admin" HOME_DEV="$state/home-dev"
  rm -rf "$HOME_ADMIN" "$HOME_DEV"
  LIMEN_HOME="$HOME_ADMIN" "$here/scripts/dev-login.sh" "$ADMIN" >/dev/null
  LIMEN_HOME="$HOME_ADMIN" "$LIMEN_BIN" admin apply "$root/examples/policy" "$here/config/targets/redis/scenario-policy.yaml" --source-ref scenarios >/dev/null
  # Roles are fixed at login, so log in again now that policy maps groups to roles.
  LIMEN_HOME="$HOME_ADMIN" "$here/scripts/dev-login.sh" "$ADMIN" >/dev/null
  LIMEN_HOME="$HOME_DEV" "$here/scripts/dev-login.sh" "$DEVELOPER" >/dev/null
  wait_for "worker tunnels" sh -c "curl -sf http://localhost:$LIMEN_REDIS_HEALTH_PORT/tunnels | grep -q worker_id"
  sleep 11 # policy refresh
  for svc in "redis-target redis-cli" "valkey-target valkey-cli" "redis-tls redis-cli"; do
    read -r name cli <<<"$svc"
    extra=(); [ "$name" = redis-tls ] && extra=(--tls --cacert /tls/ca.crt)
    wait_for "$name" "${compose[@]}" exec -T "$name" "$cli" ${extra[@]+"${extra[@]}"} --user write --pass rw-dev-only --no-auth-warning ping
  done

  step "Scenarios"
  export SCN_STATE="$state" SCN_ROOT="$root" SCN_PROJECT="$project" SCN_FILES="${STACK_FLAGS[*]}"
  python3 -I "$here/config/targets/redis/scenarios.py" ${scn_args[@]+"${scn_args[@]}"} || status=$?
fi

if $down; then
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1
  echo "Removed the stack (project $project)."
else
  echo "Stop it with: docker compose -p $project down -v"
fi
exit "$status"
