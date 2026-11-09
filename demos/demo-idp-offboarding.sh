#!/usr/bin/env bash
# IdP-driven onboarding and offboarding (ADR-0047, #111) against a real Dex.
#
# Needs: Docker, and the dev database from deploy/compose
# (`docker compose -f deploy/compose/docker-compose.yml up -d postgres`).
# Starts the Dex fixture (deploy/compose/stacks/dex-refresh.yml: Dex on its own
# PostgreSQL, port 5558, project limen-dex-refresh), then runs
#   - dex_offboarding: sign-in through Dex (authorization code, PKCE), groups
#     become roles, Dex rotates the refresh token on every check, a token Dex
#     refuses ends the login and locks the person until they sign in again;
#   - idp_offboarding: the same rules against the mock IdP, plus the failure
#     rules (IdP down fails open, or closed after the grace period).
# Not the dev stack's Dex: its built-in password users cannot refresh (a Dex
# v2.46.0 deadlock), so the dev stack keeps the check off.
#
#   demos/demo-idp-offboarding.sh          # leaves the fixture running
#   demos/demo-idp-offboarding.sh --down   # removes it afterwards
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
stack=(docker compose --project-directory "$root/deploy/compose" -f "$root/deploy/compose/stacks/dex-refresh.yml")
export LIMEN_TEST_DATABASE_URL="${LIMEN_TEST_DATABASE_URL:-postgres://limen:limen-dev-only@localhost:5432/limen}"
export LIMEN_TEST_DEX_REFRESH_URL="http://localhost:${LIMEN_PORT_DEX_REFRESH:-5558}"
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; exit 1; }

step "Start Dex with refresh tokens"
"${stack[@]}" up -d --force-recreate --quiet-pull >/dev/null
for _ in $(seq 1 60); do
  curl -sf "$LIMEN_TEST_DEX_REFRESH_URL/dex/.well-known/openid-configuration" >/dev/null && break
  sleep 1
done
curl -sf "$LIMEN_TEST_DEX_REFRESH_URL/dex/.well-known/openid-configuration" >/dev/null || fail "Dex did not come up"
pass "Dex is up at $LIMEN_TEST_DEX_REFRESH_URL"

step "Offboarding and onboarding against Dex"
cd "$root"
out="$(cargo test -p limen-control-plane --test dex_offboarding --test idp_offboarding 2>&1)" || { echo "$out"; fail "tests failed"; }
echo "$out" | grep -E '^test |test result'
echo "$out" | grep -q '^SKIPPED' && fail "a test was skipped"
pass "groups became roles; a revoked session ended the login and locked the person; signing in lifted the lock"

if [ "${1:-}" = "--down" ]; then "${stack[@]}" down -v >/dev/null; fi
