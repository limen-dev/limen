#!/usr/bin/env bash
# Public certificate demo (ADR-0043): the proxy shows an operator-supplied certificate to the CLI
# and browsers, and keeps showing the internal-CA one to workers and peers.
#
#   demos/demo-public-cert.sh          # starts its own stack (project limen-pubcert) and removes it after
#   demos/demo-public-cert.sh --keep   # leaves that stack running, and reuses it next time
#
# Needs docker, openssl, curl and cargo. The "public CA" is a throwaway one (stacks/public-cert.yml),
# and the system trust store is never touched: the CLI container is pointed at the throwaway CA
# with SSL_CERT_FILE, which is how the platform verifier finds roots on Linux. What that cannot
# show (macOS Keychain, Windows, a real public CA, browsers) stays `unverified`.
set -euo pipefail
keep=false
[ "${1:-}" = "--keep" ] && keep=true

root="$(cd "$(dirname "$0")/.." && pwd)"
here="$root/deploy/compose"
# shellcheck source=../deploy/compose/scripts/dev-users.sh
source "$here/scripts/dev-users.sh"
export LIMEN_PROJECT="${LIMEN_PROJECT:-limen-pubcert}" LIMEN_IMAGE_TAG="${LIMEN_IMAGE_TAG:-pubcert}"
export LIMEN_STATE_DIR="${LIMEN_STATE_DIR:-$here/.state/pubcert}"
export LIMEN_PORT_PROXY="${LIMEN_PORT_PROXY:-53443}" LIMEN_PORT_HEALTH="${LIMEN_PORT_HEALTH:-53444}"
export LIMEN_PORT_DEX="${LIMEN_PORT_DEX:-55556}" LIMEN_PORT_CP="${LIMEN_PORT_CP:-53081}"
export LIMEN_PORT_POSTGRES="${LIMEN_PORT_POSTGRES:-55432}" LIMEN_PORT_S3="${LIMEN_PORT_S3:-58333}"
export LIMEN_PORT_KMS="${LIMEN_PORT_KMS:-58099}"
state="$LIMEN_STATE_DIR"
pub="$state/public-cert"
export LIMEN_BIN="${LIMEN_BIN:-$root/target/release/limen}"
export LIMEN_SERVER="localhost:$LIMEN_PORT_PROXY" LIMEN_DEX_URL="http://localhost:$LIMEN_PORT_DEX"
export LIMEN_HOME="$state/home"
proxy_container="limen-proxy-${LIMEN_PROJECT#limen-}"
limen() { "$LIMEN_BIN" "$@"; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; exit 1; }
for tool in docker openssl curl cargo; do command -v "$tool" >/dev/null || fail "$tool is required"; done
cleanup() { $keep || "$here/setup.sh" down >/dev/null 2>&1 || true; }
trap cleanup EXIT

# The certificate the proxy presents to a client offering these protocols: "<field>= value" with
# the field name cut off, so two can be compared.
presented() { # presented <field: issuer|serial> <alpn list>
  # s_client exits non-zero when the server closes first, which is expected here.
  { openssl s_client -connect "localhost:$LIMEN_PORT_PROXY" -servername localhost -alpn "$2" </dev/null 2>/dev/null || true; } \
    | openssl x509 -noout "-$1" | sed 's/^[^=]*= *//'
}
# Fail instead of waiting forever (macOS has no `timeout`).
within() { local secs="$1"; shift; perl -e 'alarm shift; exec @ARGV' "$secs" "$@"; }
subject_of() { openssl x509 -in "$1" -noout -subject | sed 's/^[^=]*= *//'; }

step "Build the CLI and start the stack with a stand-in public certificate"
(cd "$root" && cargo build --release -q -p limen-cli)
if $keep && curl -sf "http://localhost:$LIMEN_PORT_HEALTH/readyz" >/dev/null; then
  echo "Reusing the running $LIMEN_PROJECT stack."
else
  "$here/setup.sh" --yes --stacks public-cert || fail "setup.sh"
fi
internal_ca="$state/internal-ca.pem"
[ -f "$internal_ca" ] || fail "no internal CA at $internal_ca"
pass "stack up on $LIMEN_SERVER"

step "On the wire: each kind of client gets its own certificate"
want_public="$(subject_of "$pub/ca.pem")"
want_internal="$(subject_of "$internal_ca")"
[ "$want_public" != "$want_internal" ] || fail "the two CAs have the same name"
for offer in h2 "h2,http/1.1" limen-ssh/1 limen-db/1; do
  got="$(presented issuer "$offer")"
  [ "$got" = "$want_public" ] || fail "offering $offer got issuer '$got', want the public CA '$want_public'"
done
for offer in limen-tunnel/1 limen-peer/1 "limen-worker-api/1,h2"; do
  got="$(presented issuer "$offer")"
  [ "$got" = "$want_internal" ] || fail "offering $offer got issuer '$got', want the internal CA '$want_internal'"
done
pass "CLI, browser, ssh and db clients get the public certificate; tunnel, peer and worker API get the internal one"

step "Workers still enroll and tunnel through the same listener"
curl -sf "http://localhost:$LIMEN_PORT_HEALTH/tunnels" | grep -q worker_id || fail "no worker tunnel is up"
pass "a worker is connected (enrolled and tunnelling with the internal CA)"

step "The CLI works, pinned to the stand-in CA (no internal CA anywhere)"
rm -rf "$LIMEN_HOME"
LIMEN_DEV_CA="$pub/ca.pem" "$here/scripts/dev-login.sh" "$ADMIN" >/dev/null || fail "login as $ADMIN"
limen status || fail "limen status"
limen ls >/dev/null || fail "limen ls"
profile="$(echo "$LIMEN_HOME"/profiles/*/proxy-ca.pem)"
cmp -s "$profile" "$pub/ca.pem" || fail "the pinned CA isn't the stand-in public CA"
pass "logged in and listing, with the public CA pinned"

step "No pinned CA and a CA the system doesn't know: refused, with the fix"
nopin="$state/home-nopin"
rm -rf "$nopin"
cp -R "$LIMEN_HOME" "$nopin"
rm -f "$nopin"/profiles/*/proxy-ca.pem
out="$(LIMEN_HOME="$nopin" limen doctor 2>&1)" && fail "doctor trusted a certificate the system has never heard of"
echo "$out" | grep -E "ca|tls"
grep -q "system trust store" <<<"$out" || fail "doctor should say it is using the system trust store: $out"
grep -q "isn't trusted" <<<"$out" || fail "the untrusted certificate isn't reported: $out"
grep -q -- "--ca-file" <<<"$out" || fail "the fix should name --ca-file: $out"
pass "no trust-on-first-use: an unknown issuer is refused"

step "No pinned CA, with the CA in the system trust store: connects"
img="limen-cli:$LIMEN_IMAGE_TAG"
envval() { sed -n "s/^$1=//p" "$here/.env"; }
docker build -q -f "$root/deploy/docker/Dockerfile" --target cli -t "$img" \
  --build-arg "RUST_IMAGE=$(envval RUST_IMAGE)" --build-arg "DISTROLESS_IMAGE=$(envval DISTROLESS_IMAGE)" \
  "$root" >/dev/null || fail "building the CLI image"
net="${LIMEN_PROJECT}_default"
run_cli() { # run_cli [docker args...] -- cli args...
  local dargs=()
  while [ "$1" != -- ]; do dargs+=("$1"); shift; done
  shift
  docker run --rm --network "$net" --tmpfs /tmp -e LIMEN_HOME=/tmp/home ${dargs[@]+"${dargs[@]}"} "$img" "$@" 2>&1
}
out="$(run_cli -v "$pub/ca.pem:/etc/test-roots.pem:ro" -e SSL_CERT_FILE=/etc/test-roots.pem -- --server proxy:3443 doctor)" || true
echo "$out" | grep -E "server|ca|network|tls|clock"
grep -q "✔ tls" <<<"$out" || fail "TLS should pass against the system roots: $out"
grep -q "✔ clock" <<<"$out" || fail "an API call over that connection should work: $out"
out="$(run_cli -- --server proxy:3443 doctor)" && fail "doctor passed without the CA in the roots"
grep -q "isn't trusted" <<<"$out" || fail "without the CA the certificate must be untrusted: $out"
pass "the CLI trusted the proxy by system roots alone, and not without them"

step "Every existing user has the internal CA pinned: refused, with the way out"
# The old CLI would not connect without a CA, so everyone has one pinned, and a pinned CA wins.
stale="$state/home-stale"
rm -rf "$stale"
out="$(LIMEN_HOME="$stale" limen login --no-browser --ca-file "$internal_ca" 2>&1)" && fail "login should be refused: the pinned internal CA did not issue the public certificate"
grep -q "isn't trusted" <<<"$out" || fail "the refusal should say the certificate isn't trusted: $out"
grep -q -- "--system-roots" <<<"$out" || fail "the way out isn't named: $out"
pass "a pinned internal CA is refused, and the message names --system-roots"
# Now as that user would be after upgrading: an old pin on disk, the system trusting the public CA.
home="$state/home-container"
rm -rf "$home"
mkdir -p "$home/profiles/proxy_3443"
cp "$internal_ca" "$home/profiles/proxy_3443/proxy-ca.pem"
chmod -R a+rwX "$home"
stale_cli() { run_cli -u "$(id -u):$(id -g)" -v "$home:/stale-home" -e LIMEN_HOME=/stale-home -v "$pub/ca.pem:/etc/test-roots.pem:ro" -e SSL_CERT_FILE=/etc/test-roots.pem -- "$@"; }
out="$(stale_cli --server proxy:3443 doctor)" && fail "doctor passed with a stale pin"
grep -q "✖ tls" <<<"$out" || fail "the stale pin should fail the TLS check: $out"
grep -q -- "--system-roots" <<<"$out" || fail "doctor should name the way out: $out"
# The login itself fails afterwards (this container cannot reach the identity provider); what counts
# is that the pin is dropped and the server is reached.
out="$(within 90 docker run --rm --network "$net" --tmpfs /tmp -u "$(id -u):$(id -g)" -v "$home:/stale-home" -e LIMEN_HOME=/stale-home -v "$pub/ca.pem:/etc/test-roots.pem:ro" -e SSL_CERT_FILE=/etc/test-roots.pem "$img" --server proxy:3443 login --device --system-roots 2>&1)" || true
grep -q "Forgot the CA pinned" <<<"$out" || fail "--system-roots should say it dropped the pin: $out"
grep -q "isn't trusted" <<<"$out" && fail "the server should be trusted after --system-roots: $out"
[ ! -e "$home/profiles/proxy_3443/proxy-ca.pem" ] || fail "the old pin is still on disk"
out="$(stale_cli --server proxy:3443 doctor)" || true
grep -q "✔ tls" <<<"$out" || fail "after --system-roots the CLI should trust the server: $out"
pass "login --system-roots dropped the old pin; the same CLI now trusts the server by system roots"

step "Renewal: a new certificate is picked up on SIGHUP, with no restart"
before="$(presented serial h2)"
"$here/scripts/gen-public-cert.sh" "$pub" --renew
docker kill -s HUP "$proxy_container" >/dev/null
for _ in $(seq 1 30); do [ "$(presented serial h2)" != "$before" ] && break; sleep 1; done
after="$(presented serial h2)"
[ "$after" != "$before" ] || fail "the proxy kept the old certificate after SIGHUP"
[ "$(presented issuer h2)" = "$want_public" ] || fail "the renewed certificate has the wrong issuer"
limen status >/dev/null || fail "the CLI should still work after the swap (same CA)"
pass "serial $before became $after; the CLI is unaffected"

step "A broken replacement is refused and the last good certificate stays"
good_key="$(cat "$pub/key.pem")"
printf 'not a key\n' >"$pub/key.pem"
docker kill -s HUP "$proxy_container" >/dev/null
for _ in $(seq 1 30); do docker logs "$proxy_container" 2>&1 | grep -q "public certificate not reloaded" && break; sleep 1; done
docker logs "$proxy_container" 2>&1 | grep -q "public certificate not reloaded" || fail "no warning about the bad key"
[ "$(presented serial h2)" = "$after" ] || fail "the certificate changed even though the key was bad"
limen status >/dev/null || fail "the CLI should still work"
curl -sf "http://localhost:$LIMEN_PORT_HEALTH/metrics" | grep -q "limen_proxy_public_cert_reload_failures_total" || fail "no failure counter"
curl -sf "http://localhost:$LIMEN_PORT_HEALTH/metrics" | grep -q "limen_proxy_public_cert_expiry_timestamp_seconds" || fail "no expiry gauge"
printf '%s\n' "$good_key" >"$pub/key.pem"
docker kill -s HUP "$proxy_container" >/dev/null
pass "bad key: warning and counter, same certificate; expiry gauge present"

printf '\n\033[32mAll public-certificate checks passed.\033[0m\n'
