#!/usr/bin/env bash
# Docs phase demo: builds the documentation site and homepage, runs its checks, serves
# the result the way GitHub Pages will (under /limen/), and fetches what a visitor sees.
# Needs mise (for Node), python3 and curl. Starts nothing but a local static server.
#
#   demos/demo-website.sh          # build, check, serve on a free port, fetch, stop
#   demos/demo-website.sh --keep   # leave the server running until Ctrl-C
#
# Verified with a local server only. Nothing is published until the repository is
# public (#138), and there is no CI for the site yet: this demo is the check.
set -euo pipefail
keep=false
for arg in "$@"; do
  case "$arg" in
    --keep) keep=true ;;
    *) echo "unknown option $arg" >&2; exit 2 ;;
  esac
done

root="$(cd "$(dirname "$0")/.." && pwd)"
site="$root/website"
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

step "Build (sync docs, build, check links, check site rules) under /limen/"
(cd "$site" && mise exec -- npm ci --silent && SITE_BASE=/limen/ mise exec -- npm run build 2>&1 | tail -n 4)
pass "build and checks"

step "Serve dist/ at /limen/ the way Pages does"
serve="$(mktemp -d)"
ln -s "$site/dist" "$serve/limen"
port="${LIMEN_DEMO_PORT:-$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')}"
python3 -m http.server "$port" --bind 127.0.0.1 --directory "$serve" >/dev/null 2>&1 &
server=$!
trap 'kill "$server" 2>/dev/null || true; wait "$server" 2>/dev/null || true; rm -rf "$serve"' EXIT
base="http://127.0.0.1:$port/limen"
curl -fs --retry 20 --retry-connrefused --retry-delay 1 -o /dev/null "$base/" || fail "server did not start"

step "Fetch what a visitor sees"
page() { curl -fsS "$base/$1"; }
page "" | grep -q "Access you can" || fail "homepage headline"
pass "homepage"
page "" | grep -q "not yet been verified against real AWS" || fail "homepage honesty statement"
pass "homepage says what is unverified"
for p in docs/ docs/quickstart/ docs/concepts/ docs/status/ docs/guides/databases/ docs/guides/access-requests/ \
         docs/runbooks/audit-verify/ docs/architecture/threat-model/ docs/architecture/adr/ docs/reference/policy/ pagefind/pagefind.js; do
  page "$p" >/dev/null || fail "$p"
done
pass "docs pages, guides, ADRs and the search index"
page docs/guides/databases/ | grep -qi "unverified" || fail "the databases guide lost its unverified note"
pass "guides keep their unverified labels"

echo
echo "Homepage: $base/"
if $keep; then
  echo "Serving. Ctrl-C to stop."
  wait "$server"
fi
