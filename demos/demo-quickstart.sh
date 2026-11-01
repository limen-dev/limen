#!/usr/bin/env bash
# Quickstart check: every command in the published quickstart
# (website/src/content/docs/docs/quickstart.md) runs against a compose stack, so
# the page cannot rot (#135). It runs in its own compose project and ports, so a
# dev stack already running is left alone.
#
#   demos/demo-quickstart.sh          # resets this check's own stack first
#   demos/demo-quickstart.sh --keep   # reuse it
#
# Three things differ from what a person types, because there is no person:
#   - there is no clone (this is the checkout), and setup.sh gets --yes --stacks
#     instead of answering its questions;
#   - the browser sign-in is played by dev-login.sh against Dex's password form;
#   - `limen ssh` gets a command to run, and `limen db connect` is stopped after
#     it prints its address.
# The check fails if the page gains, loses or changes a command, so the script
# and the page are edited together.
set -euo pipefail
keep=false
[ "${1:-}" = "--keep" ] && keep=true

root="$(cd "$(dirname "$0")/.." && pwd)"
here="$root/deploy/compose"
page="$root/website/src/content/docs/docs/quickstart.md"
# shellcheck source=../deploy/compose/scripts/dev-users.sh
source "$root/deploy/compose/scripts/dev-users.sh"
project="${LIMEN_QUICKSTART_PROJECT:-limen-quickstart}"
state="$here/.state/$project"
mkdir -p "$state"
export LIMEN_PROJECT="$project" LIMEN_STATE_DIR="$state" LIMEN_IMAGE_TAG=quickstart LIMEN_SUFFIX=-quickstart
export LIMEN_PORT_PROXY="${LIMEN_QUICKSTART_PROXY_PORT:-39443}"
export LIMEN_PORT_HEALTH="${LIMEN_QUICKSTART_HEALTH_PORT:-39444}"
export LIMEN_PORT_DEX="${LIMEN_QUICKSTART_DEX_PORT:-39556}"
export LIMEN_PORT_CP="${LIMEN_QUICKSTART_CP_PORT:-39081}"
export LIMEN_PORT_S3="${LIMEN_QUICKSTART_S3_PORT:-39333}"
export LIMEN_PORT_POSTGRES="${LIMEN_QUICKSTART_PG_PORT:-39432}"
export LIMEN_PORT_KMS="${LIMEN_QUICKSTART_KMS_PORT:-39099}"
export LIMEN_PROXY="localhost:$LIMEN_PORT_PROXY"
export LIMEN_DEX_URL="http://localhost:$LIMEN_PORT_DEX"

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; exit 1; }
wait_for() {
  local what="$1"; shift
  for _ in $(seq 1 240); do "$@" >/dev/null 2>&1 && return 0; sleep 0.5; done
  fail "timed out waiting for $what"
}
command -v ssh >/dev/null || fail "OpenSSH client (ssh) is required"

step "The commands on the page are the ones this check runs"
# The commands of every ```sh block, without trailing comments and spacing.
found=()
while IFS= read -r line; do found+=("$line"); done < <(awk '/^```sh$/{on=1; next} /^```$/{on=0} on' "$page" | sed -E 's/[[:space:]]+#.*$//; s/[[:space:]]+$//' | grep -v '^$')
expected=(
  'git clone https://github.com/limen-dev/limen && cd limen'
  'deploy/compose/setup.sh'
  'scripts/install-cli.sh'
  'limen --proxy localhost:3443 login --ca-file deploy/compose/.state/internal-ca.pem'
  'limen status'
  'limen ls'
  'limen ssh ubuntu@web-staging-1'
  'limen db connect orders-staging --db-role limen_read'
  'limen explain orders-prod'
)
# `limen login --device` and the dev-users table are prose, not in a block.
if [ "${found[*]}" != "${expected[*]}" ]; then
  printf 'page:     %s\n' "${found[@]}"; printf 'expected: %s\n' "${expected[@]}"
  fail "the quickstart's commands changed: update this script and the page together"
fi
pass "${#found[@]} commands"

step "1. Start it (setup.sh, with its questions answered)"
$keep || { echo "Resetting this check's stack (project $project, down -v). Use --keep to skip."; docker compose -p "$project" down -v --remove-orphans >/dev/null 2>&1 || true; }
if $keep && curl -sf "http://localhost:$LIMEN_PORT_HEALTH/readyz" >/dev/null 2>&1; then
  echo "The stack is already up (--keep): setup.sh is not run again."
else
  "$here/setup.sh" --yes --stacks ssh,db >"$state/setup.log" 2>&1 || { tail -40 "$state/setup.log"; fail "setup.sh failed"; }
fi
pass "setup.sh finished"

step "2. Install the CLI (scripts/install-cli.sh) and sign in"
PREFIX="$state/prefix" "$root/scripts/install-cli.sh" >"$state/install.log" 2>&1 || { tail -20 "$state/install.log"; fail "install-cli.sh failed"; }
export LIMEN_BIN="$state/prefix/bin/limen"
limen() { LIMEN_HOME="$state/home" "$LIMEN_BIN" "$@"; }
rm -rf "${state:?}/home"
LIMEN_HOME="$state/home" LIMEN_DEV_CA="$state/internal-ca.pem" "$here/scripts/dev-login.sh" "$ADMIN" >/dev/null
status="$(limen status)"; echo "$status"
grep -q "$ADMIN" <<<"$status" || fail "limen status does not show $ADMIN"
pass "signed in as $ADMIN"

step "limen ls matches the page"
# The page's first text block is the sample output of `limen ls`: every resource it shows (name and
# kind) must be in the real output. Extra real rows are fine, so adding a resource to a stack does
# not break the page.
want="$(awk '/^```text$/{on=1; next} /^```$/{if (on) exit} on' "$page" | awk 'NR>1 && $3 ~ /^(ssh|postgres|mysql|redshift)$/ {print $1, $3}' | sort)"
got="$(limen ls | awk 'NR>1 && $3 ~ /^(ssh|postgres|mysql|redshift)$/ {print $1, $3}' | sort)"
[ -n "$want" ] || fail "no sample rows found on the page"
missing="$(comm -23 <(printf '%s\n' "$want") <(printf '%s\n' "$got"))"
[ -z "$missing" ] || { printf 'the page shows, limen ls does not:\n%s\nactual:\n%s\n' "$missing" "$got"; fail "limen ls differs from the page's sample"; }
pass "limen ls lists every resource the page shows"

step "3. Use it"
# shellcheck disable=SC2016 # the command is for the remote shell
out="$(limen ssh ubuntu@web-staging-1 -- 'echo ok-from-$(hostname)')"
grep -q '^ok-from-' <<<"$out" || fail "limen ssh: $out"
pass "limen ssh ran a command on web-staging-1"

# The binary itself, so the PID is the listener's and kill stops it.
LIMEN_HOME="$state/home" "$LIMEN_BIN" db connect orders-staging --db-role limen_read >"$state/db-connect.log" 2>&1 &
db_pid=$!
wait_for "limen db connect to print its address" grep -Eq 'host=127\.0\.0\.1 port=[0-9]+ user=limen_read' "$state/db-connect.log"
kill "$db_pid" 2>/dev/null || true
wait "$db_pid" 2>/dev/null || true
pass "limen db connect printed a local address"

explain="$(limen explain orders-prod 2>&1)" || fail "limen explain failed: $explain"
echo "$explain" | head -5
pass "limen explain answered"

step "4. The other users"
for u in "$DEVELOPER" "$AUDITOR"; do
  LIMEN_HOME="$state/home-$u" LIMEN_DEV_CA="$state/internal-ca.pem" "$here/scripts/dev-login.sh" "$u" >/dev/null || fail "$u could not sign in"
done
if out="$(LIMEN_HOME="$state/home-guest" LIMEN_DEV_CA="$state/internal-ca.pem" "$here/scripts/dev-login.sh" "$GUEST" 2>&1)"; then
  fail "$GUEST must be denied, as the page says"
fi
grep -q "no roles are mapped" <<<"$out" || fail "the guest was refused for another reason: $out"
pass "developer and auditor sign in, guest is denied"

if ! $keep; then
  step "Clean up"
  docker compose -p "$project" down -v --remove-orphans >/dev/null 2>&1 || true
fi
printf '\n\033[32mQuickstart check passed.\033[0m\n'
