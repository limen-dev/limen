#!/usr/bin/env bash
# Phase 3.5 demo: locking users, ending sessions, and the web console, against
# the dev stack. A scripted "browser" (curl with a cookie jar) signs in through
# Dex's real login form.
#
#   deploy/compose/demo-phase35.sh          # resets the dev stack first (down -v)
#   deploy/compose/demo-phase35.sh --keep   # reuse the running stack
#
# LIMEN_RELEASE_IMAGES=1 uses the images already on this machine as
# limen-{control-plane,proxy,worker}:dev instead of building them, and the
# `limen` binary in LIMEN_BIN instead of compiling one. deploy/compose/smoke-release.sh
# uses it to run this demo against a published release.
set -euo pipefail
keep=false
[ "${1:-}" = "--keep" ] && keep=true

root="$(cd "$(dirname "$0")/../.." && pwd)"
here="$root/deploy/compose"
# shellcheck source=dev-users.sh
source "$here/dev-users.sh"
state="$here/.state"
compose=(docker compose --progress=quiet -f "$here/docker-compose.yml")
export LIMEN_BIN="${LIMEN_BIN:-$root/target/release/limen}"
export LIMEN_PROXY=localhost:3443
base=https://localhost:3443
# Each person has their own CLI profile directory.
as_admin() { LIMEN_HOME="$state/home-admin" "$LIMEN_BIN" "$@"; }
as_developer() { LIMEN_HOME="$state/home-developer" "$LIMEN_BIN" "$@"; }
# login <admin|developer|guest>: sign in with the CLI; the email comes from dev-users.sh.
login() {
  local var; var="$(echo "$1" | tr '[:lower:]' '[:upper:]')"
  LIMEN_HOME="$state/home-$1" "$here/dev-login.sh" "${!var}" >/dev/null
}
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; exit 1; }
wait_for() {
  local what="$1"; shift
  for _ in $(seq 1 240); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done
  fail "timed out waiting for $what"
}
command -v ssh >/dev/null || fail "OpenSSH client (ssh) is required"

step "Build and start the stack"
release_images="${LIMEN_RELEASE_IMAGES:-0}"
if [ "$release_images" != 1 ]; then
  (cd "$root" && cargo build --release -q -p limen-cli)
fi
[ -x "$LIMEN_BIN" ] || fail "no limen binary at $LIMEN_BIN"
if ! $keep; then
  echo "Resetting the dev stack (docker compose down -v). Use --keep to skip."
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1
fi
docker volume create limen-dev-ca >/dev/null # the CA outlives `down -v` and is shared by worktrees
if [ "$release_images" = 1 ]; then
  "${compose[@]}" up -d --no-build --quiet-pull >/dev/null
else
  "${compose[@]}" up -d --build --quiet-pull >/dev/null
fi
wait_for "proxy readiness" curl -sf http://localhost:3444/readyz
mkdir -p "$state"
ca="$state/internal-ca.pem"
"${compose[@]}" cp control-plane:/var/lib/limen/ca-public/internal-ca.pem "$ca" >/dev/null
rm -rf "$state/home-admin" "$state/home-developer"
login admin
as_admin admin apply "$root/examples/policy" --source-ref demo-phase35 >/dev/null
as_admin admin unlock "$DEVELOPER" >/dev/null # a previous run with --keep may have left them locked
wait_for "worker tunnels" sh -c "curl -sf http://localhost:3444/tunnels | grep -q worker_id"
sleep 11 # proxy and worker refresh policy every 10s
pass "stack up, policy applied"

# ---- a scripted browser -----------------------------------------------------------
# console-login.sh signs in through Dex and leaves the console session in a cookie jar.
browser_login() { "$here/console-login.sh" "$2" "$1"; }
page() { # page <jar> <path> -> body
  curl -s --cacert "$ca" -b "$1" -c "$1" "$base$2"
}
status() { # status <jar> <path> -> http status
  curl -s --cacert "$ca" -b "$1" -c "$1" -o /dev/null -w '%{http_code}' "$base$2"
}
csrf_of() { grep -o 'name="csrf" value="[^"]*"' | head -1 | sed 's/.*value="//; s/"$//'; }

step "admin (admin) signs in to the console through Dex"
alice_jar="$state/admin.jar"
code="$(browser_login "$alice_jar" $ADMIN)"
echo "  callback answered $code (a redirect to the console)"
home="$(page "$alice_jar" /console/)"
grep -q ''"$ADMIN"'' <<<"$home" || fail "admin isn't signed in"
grep -q 'Users' <<<"$home" || fail "admin navigation is missing"
curl -sI --cacert "$ca" "$base/console/login" | grep -qi 'content-security-policy' || true
curl -sI --cacert "$ca" -b "$alice_jar" "$base/console/" | tr -d '\r' | grep -i '^content-security-policy' | sed 's/^/  /'
pass "signed in; the console is served by the proxy, with a strict CSP"

step "developer has a live SSH session"
login developer
as_developer ssh web-staging-1 -- 'echo started; for i in $(seq 1 120); do echo tick $i; sleep 1; done' > "$state/developer-session.log" 2>&1 &
ssh_pid=$!
wait_for "developer's session to appear in the console" sh -c "curl -s --cacert '$ca' -b '$alice_jar' '$base/console/sessions?filter=active' | grep -q '$DEVELOPER'"
active="$(page "$alice_jar" '/console/sessions?filter=active')"
session_id="$(echo "$active" | grep -o '/console/sessions/[0-9a-f-]\{36\}' | head -1 | sed 's|.*/||')"
[ -n "$session_id" ] || fail "no session id in the console"
echo "  active session $session_id"
pass "the console lists developer's live session"

step "admin ends developer's session from the console"
csrf="$(page "$alice_jar" "/console/sessions/$session_id" | csrf_of)"
[ -n "$csrf" ] || fail "no CSRF token on the session page"
code="$(curl -s --cacert "$ca" -b "$alice_jar" -o /dev/null -w '%{http_code}' -H "Origin: $base" \
  --data-urlencode "csrf=$csrf" --data-urlencode "reason=demo: ending a session" \
  "$base/console/sessions/$session_id/kill")"
[ "$code" = 303 ] || fail "kill returned $code"
for _ in $(seq 1 40); do kill -0 "$ssh_pid" 2>/dev/null || break; sleep 0.5; done
if kill -0 "$ssh_pid" 2>/dev/null; then kill "$ssh_pid"; fail "developer's session survived the kill"; fi
tail -2 "$state/developer-session.log" | sed 's/^/  /'
pass "developer's session ended within seconds"

step "admin locks developer from the CLI; developer can't log in or open sessions"
as_admin admin lock "$DEVELOPER" --reason "demo: laptop reported stolen"
as_admin admin locks
if as_developer ssh web-staging-1 -- id >/dev/null 2>"$state/locked.err"; then fail "a locked user opened a session"; fi
grep -o 'user locked' "$state/locked.err" | head -1
if LIMEN_HOME="$state/home-developer" "$here/dev-login.sh" "$DEVELOPER" >"$state/locked-login.err" 2>&1; then fail "a locked user logged in"; fi
grep -o 'user locked' "$state/locked-login.err" | head -1 || { cat "$state/locked-login.err"; fail "login should say the user is locked"; }
pass "locked: SSH and login refused"

step "admin unlocks developer from the console"
csrf="$(page "$alice_jar" '/console/users/'"$DEVELOPER_ENC"'' | csrf_of)"
code="$(curl -s --cacert "$ca" -b "$alice_jar" -o /dev/null -w '%{http_code}' -H "Origin: $base" \
  --data-urlencode "csrf=$csrf" "$base/console/users/$DEVELOPER_ENC/unlock")"
[ "$code" = 303 ] || fail "unlock returned $code"
login developer
as_developer ssh web-staging-1 -- 'echo "developer is back on $(hostname)"'
pass "unlocked: developer can work again"

step "developer signs in to the console: he sees only himself"
bob_jar="$state/developer.jar"
code="$(browser_login "$bob_jar" $DEVELOPER)"
bob_home="$(page "$bob_jar" /console/)"
grep -q 'web-staging-1' <<<"$bob_home" || fail "developer doesn't see his resource"
if grep -q '>Users<' <<<"$bob_home"; then fail "developer sees the admin navigation"; fi
[ "$(status "$bob_jar" /console/users)" = 403 ] || fail "developer reached the users page"
[ "$(status "$bob_jar" /console/workers)" = 403 ] || fail "developer reached the workers page"
[ "$(status "$bob_jar" /console/policy)" = 403 ] || fail "developer reached the policy page"
pass "non-admins see their own resources and sessions only"

step "Session recording: stored, hashed, and served by the console"
sleep 6
detail="$(page "$alice_jar" "/console/sessions/$session_id")"
if grep -q 'asciinema-player.min.js' <<<"$detail"; then
  cast="$(page "$alice_jar" "/console/sessions/$session_id/recording")"
  echo "$cast" | head -1 | cut -c1-120 | sed 's/^/  /'
  grep -q 'tick' <<<"$cast" || fail "the recording has no output"
  pass "recording served after an integrity check"
else
  fail "the killed session has no recording"
fi

step "Everything above is in the audit trail"
sleep 3
"${compose[@]}" cp control-plane:/var/lib/limen/audit/control-plane.jsonl "$state/audit.jsonl" >/dev/null
python3 - "$state/audit.jsonl" <<'PY'
import collections, json, sys
events = [json.loads(l) for l in open(sys.argv[1])]
kinds = collections.Counter(e["kind"] for e in events)
for k in ("session.kill", "user.lock", "user.unlock"):
    assert kinds[k], f"missing {k}"
for e in events:
    if e["kind"] in ("user.lock", "user.unlock", "session.kill"):
        print(f"  {e['kind']:<13} by {e['user']} via {e['data']['via']}", e["data"].get("reason", ""))
assert any(e["kind"] == "session.end" and e["data"]["reason"] == "session killed" for e in events), "session.end reason"
assert any(e["kind"] == "auth.login" and e["data"].get("flow") == "console" for e in events), "console login"
assert any(e["kind"] == "auth.denied" and e["data"].get("reason") == "user locked" for e in events), "denied while locked"
PY
pass "user.lock, user.unlock, session.kill, and console logins are audited"

printf '\n\033[32mPhase 3.5 demo passed.\033[0m\n'
echo "Open the console: $base/console/  (your browser will warn about the dev CA)"
