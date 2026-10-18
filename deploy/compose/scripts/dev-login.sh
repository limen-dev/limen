#!/usr/bin/env bash
# Log in to the local dev stack as a Dex static user, without a browser.
# It runs `limen login --no-browser`, then plays the browser's part against
# Dex's password form. Dev only: Dex static users all have password "password".
#
#   deploy/compose/scripts/dev-login.sh admin@example.com
set -euo pipefail

email="${1:?usage: dev-login.sh <email> [password]}"
password="${2:-password}"
limen="${LIMEN_BIN:-limen}"
proxy="${LIMEN_PROXY:-localhost:3443}"
here="$(cd "$(dirname "$0")/.." && pwd)"
ca="${LIMEN_DEV_CA:-$here/.state/internal-ca.pem}"
# Where the browser reaches Dex (the scale stack publishes it on another port).
dex="${LIMEN_DEX_URL:-http://localhost:5556}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

"$limen" --proxy "$proxy" login --no-browser --ca-file "$ca" >"$work/out" 2>&1 &
pid=$!

url=""
for _ in $(seq 1 100); do
  url="$(grep -o "$dex/dex/auth[^ ]*" "$work/out" || true)"
  [ -n "$url" ] && break
  if ! kill -0 "$pid" 2>/dev/null; then cat "$work/out" >&2; exit 1; fi
  sleep 0.1
done
[ -n "$url" ] || { echo "limen login did not print a login URL" >&2; cat "$work/out" >&2; kill "$pid" 2>/dev/null; exit 1; }

curl -sf -c "$work/jar" -b "$work/jar" -L -o "$work/form.html" "$url"
action="$(grep -o 'action="[^"]*"' "$work/form.html" | head -1 | sed 's/^action="//; s/"$//; s/&amp;/\&/g')"
curl -s -c "$work/jar" -b "$work/jar" -L -o /dev/null \
  --data-urlencode "login=$email" --data-urlencode "password=$password" \
  "$dex$action"

status=0
wait "$pid" || status=$?
cat "$work/out" | grep -v "^Opening your browser\|^  $dex\|^\$" || true
exit "$status"
