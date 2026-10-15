#!/usr/bin/env bash
# Phase 4 demo: machine identities (ADR-0019). A CI job logs in with the
# workload identity token its platform minted, and gets a short-lived,
# audited credential as `bot:<name>`. A stand-in for GitHub Actions' token
# service (fake-ci-issuer, development only) mints GitHub-shaped tokens.
#
#   deploy/compose/demo-phase4.sh          # resets the dev stack first (down -v)
#   deploy/compose/demo-phase4.sh --keep   # reuse the running stack
#
# Everything here is unverified against real GitHub or GitLab tokens.
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
issuer_url=http://localhost:8130
as_admin() { LIMEN_HOME="$state/home-admin" "$LIMEN_BIN" "$@"; }
as_developer() { LIMEN_HOME="$state/home-developer" "$LIMEN_BIN" "$@"; }
as_bot() { LIMEN_HOME="$state/home-bot" "$LIMEN_BIN" "$@"; }
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

# mint <repository> <ref> [environment] [run id]: a GitHub-shaped token.
mint() {
  curl -sf "$issuer_url/github?repository=$1&ref=$2${3:+&environment=$3}&run_id=${4:-424242}&actor=octocat"
}
# bot_login <token file> [extra limen args]
bot_login() {
  local file="$1"; shift
  as_bot --proxy "$LIMEN_PROXY" login --bot github_actions --token-file "$file" --ca-file "$ca" "$@"
}

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
if [ "$release_images" = 1 ]; then
  "${compose[@]}" up -d --no-build --quiet-pull >/dev/null
else
  "${compose[@]}" up -d --build --quiet-pull >/dev/null
fi
wait_for "proxy readiness" curl -sf http://localhost:3444/readyz
wait_for "the fake CI issuer" curl -sf "$issuer_url/.well-known/openid-configuration"
mkdir -p "$state"
ca="$state/internal-ca.pem"
"${compose[@]}" cp control-plane:/var/lib/limen/ca-public/internal-ca.pem "$ca" >/dev/null
rm -rf "$state/home-admin" "$state/home-developer" "$state/home-bot" "$state/phase4"
mkdir -p "$state/phase4"
login admin

# The demo bot: only the main branch of acme/infra, in the staging environment.
cat > "$state/phase4/demo-bot.yaml" <<'YAML'
kind: bot
version: v1
metadata:
  name: demo-deploy
  description: The demo deploy job (acme/infra, main, staging).
spec:
  join:
    method: github_actions
    issuer: http://fake-ci-issuer:8130
    match:
      repository: acme/infra
      ref: refs/heads/main
      environment: staging
  roles: [deployer]
  max_ttl: 15m
YAML
as_admin admin apply "$root/examples/policy" "$state/phase4/demo-bot.yaml" --source-ref demo-phase4 >/dev/null
as_admin admin unlock bot:demo-deploy >/dev/null 2>&1 || true # a previous run with --keep may have left it locked
wait_for "worker tunnels" sh -c "curl -sf http://localhost:3444/tunnels | grep -q worker_id"
sleep 11 # proxy and worker refresh policy every 10s
pass "stack up; the bot is in policy"

step "A bot rule that is too broad is refused when policy is applied"
cat > "$state/phase4/broad.yaml" <<'YAML'
kind: bot
version: v1
metadata: { name: too-broad }
spec:
  join:
    method: github_actions
    match: { repository: acme/infra }
  roles: [deployer]
YAML
if as_admin admin apply "$root/examples/policy" "$state/phase4/broad.yaml" --dry-run >/dev/null 2>"$state/phase4/broad.err"; then
  fail "a repository-only bot rule was accepted"
fi
grep -o 'repository alone[^"]*' "$state/phase4/broad.err" | head -1 | sed 's/^/  /'
pass "a repository alone is refused (every branch and fork would get in)"

step "The right CI job logs in with its identity token, and gets a bot credential"
mint acme/infra refs/heads/main staging > "$state/phase4/token-1.jwt"
echo "  token: $(wc -c < "$state/phase4/token-1.jwt" | tr -d ' ') bytes, never printed"
bot_login "$state/phase4/token-1.jwt"
as_bot --proxy "$LIMEN_PROXY" status | grep -q 'bot:demo-deploy' || fail "status doesn't show the bot"
pass "signed in as bot:demo-deploy, no secret configured anywhere"

step "The bot opens an SSH session, recorded and audited like anyone's"
as_bot ssh web-staging-1 -- 'echo "hello from the deploy job on $(hostname)"'
pass "the bot's session ran"

step "A token works once, and only the exact job gets in"
if bot_login "$state/phase4/token-1.jwt" >/dev/null 2>"$state/phase4/replay.err"; then fail "a token was used twice"; fi
grep -o 'token already used' "$state/phase4/replay.err" | head -1 | sed 's/^/  replay: /'
mint acme/infra refs/heads/feature staging 11 > "$state/phase4/token-branch.jwt"
if bot_login "$state/phase4/token-branch.jwt" >/dev/null 2>"$state/phase4/branch.err"; then fail "another branch logged in"; fi
grep -o 'no bot matches this token' "$state/phase4/branch.err" | head -1 | sed 's/^/  other branch: /'
mint acme/infra refs/pull/9/merge staging 12 > "$state/phase4/token-pr.jwt"
if bot_login "$state/phase4/token-pr.jwt" >/dev/null 2>"$state/phase4/pr.err"; then fail "a pull request ref logged in"; fi
grep -o 'no bot matches this token' "$state/phase4/pr.err" | head -1 | sed 's/^/  pull request: /'
curl -sf "$issuer_url/github?repository=acme/infra&ref=refs/heads/main&environment=staging&run_id=13&issued_secs_ago=1500" > "$state/phase4/token-old.jwt"
if bot_login "$state/phase4/token-old.jwt" >/dev/null 2>"$state/phase4/old.err"; then fail "a stale token logged in"; fi
grep -o 'invalid token' "$state/phase4/old.err" | head -1 | sed 's/^/  stale token: /'
pass "replays, other branches, pull requests, and stale tokens are refused"

step "People and bots look different in the console"
browser_jar="$state/admin.jar"
"$here/console-login.sh" "$ADMIN" "$browser_jar" >/dev/null
page() { curl -s --cacert "$ca" -b "$browser_jar" -c "$browser_jar" "$base$1"; }
for _ in $(seq 1 40); do page '/console/sessions' | grep -q 'bot:demo-deploy' && break; sleep 0.5; done
bots="$(page /console/bots)"
grep -q 'bot:demo-deploy' <<<"$bots" || fail "the Bots page doesn't list the bot"
grep -q 'acme/infra' <<<"$bots" || fail "the Bots page doesn't show the repository"
grep -q 'https://github.com/acme/infra/actions/runs/424242' <<<"$bots" || fail "no link to the run"
sessions="$(page '/console/sessions?user=bot%3Ademo-deploy')"
grep -q 'class="pill bot"' <<<"$sessions" || fail "the bot's session isn't marked"
session_id="$(grep -o '/console/sessions/[0-9a-f-]\{36\}' <<<"$sessions" | head -1 | sed 's|.*/||')"
[ -n "$session_id" ] || fail "no session for the bot"
page "/console/sessions/$session_id" | grep -q 'The CI run' || fail "the session page doesn't show the CI run"
if page /console/users | grep -q 'bot%3Ademo-deploy'; then fail "the bot is listed among people"; fi
page /console/dashboards | grep -q 'Bot sessions by repository' || fail "no bot panel on the dashboards"
dev_jar="$state/developer.jar"
"$here/console-login.sh" "$DEVELOPER" "$dev_jar" >/dev/null
code="$(curl -s --cacert "$ca" -b "$dev_jar" -o /dev/null -w '%{http_code}' "$base/console/bots")"
[ "$code" = 403 ] || fail "a non-admin got $code from the Bots page"
pass "Bots page, run link, CI card on the session, bot panel; non-admins don't see it"

step "No token reaches the audit trail or the logs"
sleep 3
"${compose[@]}" cp control-plane:/var/lib/limen/audit/control-plane.jsonl "$state/audit.jsonl" >/dev/null
python3 - "$state/audit.jsonl" "$state/phase4" <<'PY'
import collections, glob, json, sys
events = [json.loads(l) for l in open(sys.argv[1])]
raw = open(sys.argv[1]).read()
for path in glob.glob(sys.argv[2] + "/token-*.jwt"):
    token = open(path).read().strip()
    assert token not in raw, f"a token appears in the audit trail: {path}"
    assert token.split(".")[2] not in raw, "a token signature appears in the audit trail"
login = next(e for e in events if e["kind"] == "auth.login" and e["user"] == "bot:demo-deploy")
assert login["data"]["actor_type"] == "bot" and login["data"]["ci"]["repository"] == "acme/infra"
print("  auth.login   bot:demo-deploy", login["data"]["ci"]["provider"], login["data"]["ci"]["repository"], login["data"]["ci"]["ref"])
start = next(e for e in events if e["kind"] == "session.start" and e["user"] == "bot:demo-deploy")
assert start["data"]["actor_type"] == "bot" and start["data"]["ci"]["run_id"] == "424242"
print("  session.start run", start["data"]["ci"]["run_id"], "by", start["data"]["ci"]["actor"])
execs = [e for e in events if e["kind"] == "ssh.exec" and e["user"] == "bot:demo-deploy"]
assert execs and execs[0]["data"]["actor_type"] == "bot", "the bot's command is audited as a bot's"
reasons = collections.Counter(e["data"]["reason"] for e in events if e["kind"] == "auth.denied" and e["data"].get("action") == "bot_login")
for reason in ("token already used", "no bot matches this token", "invalid token"):
    assert reasons[reason], f"missing denial: {reason}"
print("  denials:", dict(reasons))
denied = next(e for e in events if e["kind"] == "auth.denied" and e["data"].get("reason") == "no bot matches this token" and e["data"]["ci"].get("ref") == "refs/heads/feature")
print("  the refused run is recorded:", denied["data"]["ci"]["repository"], denied["data"]["ci"]["ref"])
PY
for f in "$state"/phase4/token-*.jwt; do
  if "${compose[@]}" logs --no-color control-plane proxy worker 2>&1 | grep -qF "$(cat "$f")"; then fail "a token appears in the service logs: $f"; fi
done
pass "audited with the CI run; no token in the trail or in the logs"

step "Locking the bot stops it, like locking a person"
as_admin admin lock bot:demo-deploy --reason "demo: suspicious run"
if as_bot ssh web-staging-1 -- id >/dev/null 2>"$state/phase4/locked.err"; then fail "a locked bot opened a session"; fi
grep -o 'user locked' "$state/phase4/locked.err" | head -1 | sed 's/^/  existing credential: /'
mint acme/infra refs/heads/main staging 14 > "$state/phase4/token-after-lock.jwt"
if bot_login "$state/phase4/token-after-lock.jwt" >/dev/null 2>"$state/phase4/locked-login.err"; then fail "a locked bot logged in"; fi
grep -o 'bot locked' "$state/phase4/locked-login.err" | head -1 | sed 's/^/  new login: /'
as_admin admin unlock bot:demo-deploy >/dev/null
pass "a locked bot can neither use its credential nor log in again"

rm -f "$state"/phase4/token-*.jwt
printf '\n\033[32mPhase 4 demo passed.\033[0m\n'
echo "Open the console: $base/console/bots  (your browser will warn about the dev CA)"
