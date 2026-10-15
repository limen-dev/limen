#!/usr/bin/env bash
# The dev stack's CA, kept the same across resets and worktrees.
#
# The CA *keys* live in ~/.limen-dev/ca (outside every compose volume and every
# checkout), so `docker compose down -v` and a different worktree get a CA with
# the same key. This script keeps one public copy of the CA certificate at a
# fixed path, ~/.limen-dev/internal-ca.pem, for you to trust once. After a
# reset the CA certificate is re-issued with the same key, so a trust you gave
# that file keeps working.
#
#   deploy/compose/dev-ca.sh           # print the path (creating the copy if needed)
#   deploy/compose/dev-ca.sh --trust   # print how to trust it, without doing anything
#
# This script never changes any trust setting. DEVELOPMENT ONLY: anyone who can
# read ~/.limen-dev/ca can sign certificates your browser would accept if you
# trust the CA, so keep that folder private, and consider trusting the CA only
# in a separate browser profile.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
state="${LIMEN_DEV_STATE:-$HOME/.limen-dev}"
stable="$state/internal-ca.pem"
compose=(docker compose --progress=quiet -f "$here/docker-compose.yml")

mkdir -p "$state"
chmod 700 "$state" 2>/dev/null || true
if [ ! -s "$stable" ]; then
  "${compose[@]}" cp control-plane:/var/lib/limen/ca-public/internal-ca.pem "$stable" >/dev/null \
    || { echo "dev-ca.sh: the stack isn't running (start it first)" >&2; exit 1; }
fi

if [ "${1:-}" = "--trust" ]; then
  fingerprint="$(openssl x509 -in "$stable" -noout -fingerprint -sha256 | cut -d= -f2)"
  cat <<TEXT
The dev CA is $stable
  SHA-256 $fingerprint

Nothing has been changed. To trust it yourself:
  macOS (system-wide, asks for your password):
    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$stable"
  Firefox: Settings > Privacy & Security > Certificates > View Certificates > Authorities > Import.
  To remove it later: delete it in Keychain Access (or Firefox), or
    sudo security delete-certificate -c "Limen Internal CA" /Library/Keychains/System.keychain

It is a development CA whose key is in ${state}/ca. Trusting it makes your browser
accept anything that key signs. Prefer a separate browser profile, and remove it when done.
TEXT
  exit 0
fi
echo "$stable"
