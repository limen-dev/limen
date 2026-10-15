#!/usr/bin/env bash
# Starts the local dev stack in one step, ready to use with the CLI.
#
#   deploy/compose/up.sh          # build and start; keeps the database, the CA and the recordings
#   deploy/compose/up.sh --reset  # same, after `docker compose down -v` (fresh database; the CA stays)
#
# It creates the CA volume (limen-dev-ca) if it's missing, waits until the
# control plane answers, and copies the dev CA certificate to
# deploy/compose/.state/internal-ca.pem for `limen login --ca-file`.
# DEVELOPMENT ONLY. See deploy/compose/README.md.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
compose=(docker compose --progress=quiet -f "$here/docker-compose.yml")

if [ "${1:-}" = "--reset" ]; then
  echo "Resetting the stack (docker compose down -v). The CA is kept."
  "${compose[@]}" down -v --remove-orphans >/dev/null
fi

# The CA lives in an external volume so `down -v` doesn't remove it.
docker volume inspect limen-dev-ca >/dev/null 2>&1 || docker volume create limen-dev-ca >/dev/null

"${compose[@]}" up -d --build

# curl retries itself (no sleep loop here): the proxy and control plane take a while to start.
curl -sf --retry 120 --retry-delay 1 --retry-all-errors http://localhost:3081/readyz >/dev/null
curl -sf --retry 120 --retry-delay 1 --retry-all-errors http://localhost:3444/readyz >/dev/null

mkdir -p "$here/.state"
"${compose[@]}" cp control-plane:/var/lib/limen/ca-public/internal-ca.pem "$here/.state/internal-ca.pem" >/dev/null

cat <<TEXT
The stack is up.
  Console:  https://localhost:3443/console/   (your browser warns until you trust the dev CA, see deploy/compose/README.md)
  CA file:  $here/.state/internal-ca.pem

Sign in from the CLI (admin@example.com / password):
  limen --proxy localhost:3443 login --ca-file $here/.state/internal-ca.pem
TEXT
