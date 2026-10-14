#!/usr/bin/env bash
# Sign in to the dev console without a browser: play the browser's part against
# Dex's password form, and leave the console session cookie in a curl cookie jar.
# Dev only: Dex static users all have password "password".
#
#   deploy/compose/console-login.sh admin@example.com /tmp/admin.jar
#   curl --cacert deploy/compose/.state/internal-ca.pem -b /tmp/admin.jar https://localhost:3443/console/
set -euo pipefail
email="${1:?usage: console-login.sh <email> <cookie-jar> [password]}"
jar="${2:?usage: console-login.sh <email> <cookie-jar> [password]}"
password="${3:-password}"
here="$(cd "$(dirname "$0")" && pwd)"
ca="${LIMEN_DEV_CA:-$here/.state/internal-ca.pem}"
base="${LIMEN_CONSOLE_URL:-https://localhost:3443}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
: > "$jar"
# Start: the console redirects to Dex.
dex_url="$(curl -s --cacert "$ca" -c "$jar" -b "$jar" -o /dev/null -w '%{redirect_url}' "$base/console/login")"
[ -n "$dex_url" ] || { echo "the console didn't redirect to the identity provider" >&2; exit 1; }
# Dex shows its password form; fill it in.
curl -sf -c "$work/dex" -b "$work/dex" -L -o "$work/form.html" "$dex_url"
action="$(grep -o 'action="[^"]*"' "$work/form.html" | head -1 | sed 's/^action="//; s/"$//; s/&amp;/\&/g')"
back="$(curl -s -c "$work/dex" -b "$work/dex" -o /dev/null -w '%{redirect_url}' \
  --data-urlencode "login=$email" --data-urlencode "password=$password" "http://localhost:5556$action")"
# Dex may bounce through an approval step; follow its redirects until we leave it.
while [[ "$back" == http://localhost:5556/* ]]; do
  back="$(curl -s -c "$work/dex" -b "$work/dex" -o /dev/null -w '%{redirect_url}' "$back")"
done
# Back at the console's callback, with the code.
code="$(curl -s --cacert "$ca" -c "$jar" -b "$jar" -o /dev/null -w '%{http_code}' "$back")"
echo "$code"
[ "$code" = 303 ] || { echo "sign-in failed (callback answered $code)" >&2; exit 1; }
