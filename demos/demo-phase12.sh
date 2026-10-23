#!/usr/bin/env bash
# Phase 12 end-to-end demo: browser SSO, request policy/audit, WebSockets, and TCP.
#
#   demos/demo-phase12.sh          # resets this demo's own stack first
#   demos/demo-phase12.sh --keep   # reuse the running stack
set -euo pipefail

keep=false
[ "${1:-}" = "--keep" ] && keep=true

root="$(cd "$(dirname "$0")/.." && pwd)"
here="$root/deploy/compose"
# shellcheck source=../deploy/compose/scripts/dev-users.sh
source "$here/scripts/dev-users.sh"
project="${LIMEN_PHASE12_PROJECT:-limen-phase12}"
state="$here/.state/$project"
mkdir -p "$state"
export LIMEN_PROJECT="$project" LIMEN_STATE_DIR="$state" LIMEN_IMAGE_TAG=phase12
export LIMEN_PORT_PROXY="${LIMEN_PHASE12_PROXY_PORT:-39443}"
export LIMEN_PORT_HEALTH="${LIMEN_PHASE12_HEALTH_PORT:-39444}"
export LIMEN_PORT_DEX="${LIMEN_PHASE12_DEX_PORT:-39556}"
export LIMEN_PORT_CP="${LIMEN_PHASE12_CP_PORT:-39081}"
export LIMEN_PORT_S3="${LIMEN_PHASE12_S3_PORT:-39333}"
export LIMEN_PORT_POSTGRES="${LIMEN_PHASE12_PG_PORT:-39432}"
export LIMEN_PORT_KMS="${LIMEN_PHASE12_KMS_PORT:-39099}"
# shellcheck source=../deploy/compose/scripts/lib.sh
source "$here/scripts/lib.sh"
stack_setup tcp web

export LIMEN_BIN="${LIMEN_BIN:-$root/target/release/limen}"
export LIMEN_PROXY="localhost:$LIMEN_PORT_PROXY"
export LIMEN_DEX_URL="http://localhost:$LIMEN_PORT_DEX"
export LIMEN_DEV_CA="$state/internal-ca.pem"
app_host=app.apps.test
other_host=other.apps.test
forward_pid=""
step() { printf '\n== %s\n' "$*"; }
pass() { printf 'PASS %s\n' "$*"; }
fail() { echo "FAIL $*" >&2; exit 1; }
cleanup() {
  if [ -n "$forward_pid" ]; then
    kill "$forward_pid" 2>/dev/null || true
    wait "$forward_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT
wait_for() {
  local what="$1"
  shift
  for _ in $(seq 1 240); do
    "$@" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  fail "timed out waiting for $what"
}
app_curl() {
  curl -sS --cacert "$LIMEN_DEV_CA" \
    --resolve "$app_host:$LIMEN_PORT_PROXY:127.0.0.1" "$@"
}
other_curl() {
  curl -sS --cacert "$LIMEN_DEV_CA" \
    --resolve "$other_host:$LIMEN_PORT_PROXY:127.0.0.1" "$@"
}

step "Build and start the full Phase 12 compose stack ($project)"
(cd "$root" && cargo build --release -q -p limen-cli)
$keep || { echo "Resetting this demo's stack (project $project, down -v). Use --keep to skip."; "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1; }
"${compose[@]}" up -d --build --quiet-pull >/dev/null
wait_for "proxy readiness" curl -sf "http://localhost:$LIMEN_PORT_HEALTH/readyz"
wait_for "web target" "${compose[@]}" exec -T web-target python -c \
  "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=1)"
wait_for "TCP target" "${compose[@]}" exec -T tcp-target python -c \
  "import socket; socket.create_connection(('127.0.0.1', 8080), timeout=1).close()"
"${compose[@]}" cp control-plane:/var/lib/limen/ca-public/internal-ca.pem "$state/internal-ca.pem" >/dev/null

step "Apply the web and TCP policy"
home_admin="$state/home-admin"
home_dev="$state/home-developer"
rm -rf "$home_admin" "$home_dev"
LIMEN_HOME="$home_admin" "$here/scripts/dev-login.sh" "$ADMIN" >/dev/null
LIMEN_HOME="$home_admin" "$LIMEN_BIN" admin apply \
  "$root/examples/policy" \
  "$here/config/targets/tcp/policy.yaml" \
  "$here/config/targets/web/policy.yaml" \
  --source-ref demo-phase12 >/dev/null
LIMEN_HOME="$home_dev" "$here/scripts/dev-login.sh" "$DEVELOPER" >/dev/null
wait_for "worker tunnels" sh -c "curl -sf http://localhost:$LIMEN_PORT_HEALTH/tunnels | grep -q worker_id"
sleep 11
pass "stack up, web/TCP policy applied, developer logged in"

web_sign_in() {
  local email="$1" jar="$2" expected="$3"
  local work dex_url action back callback_status handoff_status handoff_url
  work="$(mktemp -d)"
  : >"$jar"
  : >"$work/other-browser.jar"
  : >"$work/dex.jar"

  local initial_status
  initial_status="$(app_curl -b "$jar" -c "$jar" -o /dev/null -D "$work/app.hdr" \
    -w '%{http_code}' "https://$app_host:$LIMEN_PORT_PROXY/allowed?phase12_query_secret=omit-me")"
  [ "$initial_status" = 303 ] || { rm -rf "$work"; fail "$email app request did not redirect to sign-in ($initial_status)"; }
  local login_url
  login_url="$(grep -i '^location:' "$work/app.hdr" | head -1 | cut -d' ' -f2- | tr -d '\r')"
  [ -n "$login_url" ] || { rm -rf "$work"; fail "app sign-in URL missing"; }

  dex_url="$(curl -sS --cacert "$LIMEN_DEV_CA" -b "$jar" -c "$jar" \
    -o /dev/null -w '%{redirect_url}' "$login_url")"
  [ -n "$dex_url" ] || { rm -rf "$work"; fail "web sign-in did not redirect to Dex"; }
  curl -sf -c "$work/dex.jar" -b "$work/dex.jar" -L -o "$work/form.html" "$dex_url"
  action="$(grep -o 'action="[^"]*"' "$work/form.html" | head -1 | sed 's/^action="//; s/"$//; s/&amp;/\&/g')"
  [ -n "$action" ] || { rm -rf "$work"; fail "Dex sign-in form action missing"; }
  back="$(curl -sS -c "$work/dex.jar" -b "$work/dex.jar" -o /dev/null -w '%{redirect_url}' \
    --data-urlencode "login=$email" --data-urlencode "password=$DEV_PASSWORD" \
    "http://localhost:$LIMEN_PORT_DEX$action")"
  while [[ "$back" == "http://localhost:$LIMEN_PORT_DEX/"* ]]; do
    back="$(curl -sS -c "$work/dex.jar" -b "$work/dex.jar" -o /dev/null -w '%{redirect_url}' "$back")"
  done
  callback_status="$(curl -sS --cacert "$LIMEN_DEV_CA" -b "$jar" -c "$jar" \
    -o "$work/callback.out" -D "$work/callback.hdr" -w '%{http_code}' "$back")"
  if [ "$expected" = allow ]; then
    [ "$callback_status" = 303 ] || { rm -rf "$work"; fail "$email web SSO callback returned $callback_status"; }
    local callback_url
    callback_url="$(grep -i '^location:' "$work/callback.hdr" | head -1 | cut -d' ' -f2- | tr -d '\r')"
    [[ "$callback_url" == "https://$app_host:$LIMEN_PORT_PROXY/.limen/callback?handoff="* ]] || {
      rm -rf "$work"
      fail "web SSO did not redirect to the app's one-use handoff"
    }
    local other_browser_status
    other_browser_status="$(app_curl -b "$work/other-browser.jar" -o /dev/null -w '%{http_code}' \
      "$callback_url")"
    [ "$other_browser_status" = 403 ] || {
      rm -rf "$work"
      fail "handoff was not bound to the browser that completed OIDC ($other_browser_status)"
    }
    handoff_status="$(app_curl -b "$jar" -c "$jar" -o /dev/null -D "$work/handoff.hdr" \
      -w '%{http_code}' "$callback_url")"
    [ "$handoff_status" = 303 ] || { rm -rf "$work"; fail "app handoff returned $handoff_status"; }
  else
    [ "$callback_status" = 403 ] || { rm -rf "$work"; fail "$email should be refused but callback returned $callback_status"; }
  fi
  rm -rf "$work"
}

step "Exercise browser SSO and host-only app cookies"
app_jar="$state/web-developer.cookies"
web_sign_in "$DEVELOPER" "$app_jar" allow
grep -q 'app.apps.test.*__Host-limen_app' "$app_jar" || fail "app session cookie was not scoped to the app host"
! grep -q 'localhost.*__Host-limen_app' "$app_jar" || fail "app session cookie was shared with the console host"
pass "developer received an app-host-only session cookie"

other_status="$(other_curl -b "$app_jar" -o /dev/null -w '%{http_code}' \
  "https://$other_host:$LIMEN_PORT_PROXY/allowed")"
[ "$other_status" = 303 ] || fail "app cookie crossed to a different host ($other_status)"
app_cookie="$(awk -F '\t' '$6 == "__Host-limen_app" { print $7; exit }' "$app_jar")"
[ -n "$app_cookie" ] || fail "could not read the test app cookie"
cross_host_status="$(other_curl -H "Cookie: __Host-limen_app=$app_cookie" -o /dev/null \
  -w '%{http_code}' "https://$other_host:$LIMEN_PORT_PROXY/allowed")"
[ "$cross_host_status" = 403 ] || fail "app session was not bound to its configured host ($cross_host_status)"
pass "browser cookie isolation and signed host binding enforced"

step "Verify request policy, trusted headers, and SNI/authority binding"
response_status="$(app_curl -b "$app_jar" -H 'X-Limen-User: spoofed-user' \
  -o "$state/web-response.txt" -w '%{http_code}' \
  "https://$app_host:$LIMEN_PORT_PROXY/allowed?phase12_query_secret=omit-me")"
[ "$response_status" = 200 ] || fail "allowed web request returned $response_status"
grep -q '^user=developer@example.com$' "$state/web-response.txt" || fail "upstream did not receive the verified user"
grep -q '^roles=.*phase12-web' "$state/web-response.txt" || fail "upstream did not receive the verified role"
grep -q '^cookie=$' "$state/web-response.txt" || fail "Limen's app cookie reached the upstream"
grep -q '^assertion=eyJ' "$state/web-response.txt" || fail "signed identity assertion missing"
curl -sS --cacert "$LIMEN_DEV_CA" -o "$state/web-jwks.json" \
  "https://localhost:$LIMEN_PORT_PROXY/console/web/jwks.json"
python3 - "$state/web-response.txt" "$state/web-jwks.json" <<'PY'
import base64
import json
import pathlib
import subprocess
import tempfile

lines = pathlib.Path(__import__("sys").argv[1]).read_text().splitlines()
token = next(line.removeprefix("assertion=") for line in lines if line.startswith("assertion="))
jwks = json.loads(pathlib.Path(__import__("sys").argv[2]).read_text())
header_text, payload_text, signature_text = token.split(".")
decode = lambda part: base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
header = json.loads(decode(header_text))
claims = json.loads(decode(payload_text))
jwk = next(key for key in jwks["keys"] if key["kid"] == header["kid"])
assert header["alg"] == "ES256" and header["typ"] == "JWT"
assert claims["iss"] == "urn:limen:control-plane"
assert claims["sub"] == "developer@example.com" and claims["aud"] == "app.apps.test"
assert claims["exp"] > claims["iat"]
x = decode(jwk["x"])
y = decode(jwk["y"])
assert jwk["kty"] == "EC" and jwk["crv"] == "P-256" and len(x) == len(y) == 32
spki = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004") + x + y
pem = "-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(spki).decode() + "\n-----END PUBLIC KEY-----\n"

def der_integer(value):
    value = value.lstrip(b"\0") or b"\0"
    if value[0] & 0x80:
        value = b"\0" + value
    return b"\x02" + bytes([len(value)]) + value

raw_signature = decode(signature_text)
assert len(raw_signature) == 64
sequence = der_integer(raw_signature[:32]) + der_integer(raw_signature[32:])
der_signature = b"\x30" + bytes([len(sequence)]) + sequence
with tempfile.TemporaryDirectory() as directory:
    root = pathlib.Path(directory)
    key_file, signature_file, message_file = (root / name for name in ("key.pem", "sig.der", "message"))
    key_file.write_text(pem)
    signature_file.write_bytes(der_signature)
    message_file.write_text(f"{header_text}.{payload_text}")
    checked = subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", str(key_file), "-signature", str(signature_file), str(message_file)],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "Verified OK" in checked.stdout, checked.stdout
print("identity assertion verified against the published JWKS")
PY
post_status="$(app_curl -b "$app_jar" -X POST --data 'not-forwarded' -o /dev/null -w '%{http_code}' \
  "https://$app_host:$LIMEN_PORT_PROXY/allowed")"
path_status="$(app_curl -b "$app_jar" -o /dev/null -w '%{http_code}' \
  "https://$app_host:$LIMEN_PORT_PROXY/private")"
sni_status="$(app_curl -H "Host: $other_host:$LIMEN_PORT_PROXY" -o /dev/null -w '%{http_code}' \
  "https://$app_host:$LIMEN_PORT_PROXY/allowed")"
[ "$post_status" = 403 ] || fail "POST was not denied by the web method grant ($post_status)"
[ "$path_status" = 403 ] || fail "ungranted path was not denied ($path_status)"
[ "$sni_status" = 421 ] || fail "SNI/authority mismatch was not rejected ($sni_status)"
pass "verified identity forwarding, method/path policy, and host/SNI matching"

step "Verify streaming and WebSocket forwarding"
python3 - "$LIMEN_PORT_PROXY" "$LIMEN_DEV_CA" "$app_host" "$app_jar" <<'PY'
import base64
import http.client
import json
import pathlib
import socket
import ssl
import sys
import time

port = int(sys.argv[1])
ca_file, host, jar_path = sys.argv[2:]

def app_cookie():
    for line in pathlib.Path(jar_path).read_text().splitlines():
        fields = line.split("\t")
        if len(fields) >= 7 and fields[5] == "__Host-limen_app":
            return fields[6]
    raise AssertionError("app cookie not found in curl cookie jar")

cookie = app_cookie()
context = ssl.create_default_context(cafile=ca_file)

sock = socket.create_connection(("127.0.0.1", port), timeout=10)
sock = context.wrap_socket(sock, server_hostname=host)
sock.sendall(
    f"GET /stream HTTP/1.1\r\nHost: {host}:{port}\r\nCookie: __Host-limen_app={cookie}\r\n"
    "Connection: close\r\n\r\n".encode()
)
response = http.client.HTTPResponse(sock)
response.begin()
assert response.status == 200, response.status
started = time.monotonic()
first = response.readline()
first_elapsed = time.monotonic() - started
second = response.readline()
second_elapsed = time.monotonic() - started
assert first == b"chunk-one\n" and second == b"chunk-two\n", (first, second)
assert first_elapsed < 0.7, f"first chunk was buffered ({first_elapsed:.3f}s)"
assert second_elapsed - first_elapsed >= 0.25, "upstream chunks were not observed as a stream"
sock.close()

sock = context.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=10), server_hostname=host)
key = base64.b64encode(b"phase12-websocket").decode()
sock.sendall(
    f"GET /ws HTTP/1.1\r\nHost: {host}:{port}\r\nCookie: __Host-limen_app={cookie}\r\n"
    "Upgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    f"Sec-WebSocket-Key: {key}\r\n\r\n".encode()
)
reader = sock.makefile("rb")
status_line = reader.readline().decode().strip()
headers = {}
while True:
    line = reader.readline()
    if line in (b"\r\n", b"\n", b""):
        break
    name, value = line.decode().split(":", 1)
    headers[name.lower()] = value.strip()
assert " 101 " in status_line, status_line
assert headers.get("sec-websocket-accept") == base64.b64encode(
    __import__("hashlib").sha1(
        (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
    ).digest()
).decode(), headers
payload = b"phase12-websocket-roundtrip"
mask = b"\x12\x34\x56\x78"
masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
sock.sendall(bytes([0x81, 0x80 | len(payload)]) + mask + masked)
frame = reader.read(2)
assert len(frame) == 2 and frame[0] == 0x81 and frame[1] == len(payload), frame
assert reader.read(frame[1]) == payload, "WebSocket payload did not round-trip"
sock.close()
print("HTTP response streamed incrementally; WebSocket upgraded and echoed")
PY
pass "streaming HTTP and WebSocket tunnel verified"

step "Round-trip raw TCP through the fixed resource"
LIMEN_HOME="$home_dev" "$LIMEN_BIN" tcp tcp-echo >"$state/tcp.log" 2>&1 &
forward_pid=$!
wait_for "local TCP listener" grep -q 'Connect with:' "$state/tcp.log"
tcp_port="$(sed -nE 's/.*Connect with: nc 127\.0\.0\.1 ([0-9]+).*/\1/p' "$state/tcp.log" | head -1)"
[ -n "$tcp_port" ] || fail "could not find the local TCP listener port"
python3 - "$tcp_port" <<'PY'
import socket
import sys

payload = b"phase12-compose-tcp-roundtrip"
with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10) as client:
    client.settimeout(10)
    client.sendall(payload)
    client.shutdown(socket.SHUT_WR)
    received = bytearray()
    while chunk := client.recv(4096):
        received.extend(chunk)
assert received == payload, received
print("raw TCP payload round-tripped")
PY
kill "$forward_pid"
wait "$forward_pid" 2>/dev/null || true
forward_pid=""
pass "fixed-target TCP relay round-tripped"

step "Verify denied human/bot sign-in and full audit projection"
web_sign_in "$GUEST" "$state/web-guest.cookies" deny
web_sign_in "bot:phase12@example.com" "$state/web-bot.cookies" deny
pass "unmapped users and bot identities were refused by browser SSO"

copy_audit() {
  "${compose[@]}" cp control-plane:/var/lib/limen/audit/control-plane.jsonl "$state/control-plane.jsonl" >/dev/null 2>&1 &&
    grep -q '"kind":"web.request"' "$state/control-plane.jsonl" &&
    grep -q '"kind":"web.response"' "$state/control-plane.jsonl" &&
    grep -q '"kind":"web.websocket"' "$state/control-plane.jsonl" &&
    grep -q '"kind":"session.end"' "$state/control-plane.jsonl"
}
wait_for "web and TCP audit events" copy_audit
projection_ready() {
  "${compose[@]}" exec -T postgres psql -U limen -d limen -Atqc \
    "SELECT count(*) FROM web_requests WHERE resource = 'web-demo' AND path = '/allowed' AND status = 200" |
    grep -q '[1-9]'
}
wait_for "console web request projection" projection_ready
python3 - "$state/control-plane.jsonl" <<'PY'
import json
import pathlib
import sys

raw = pathlib.Path(sys.argv[1]).read_text()
events = [json.loads(line) for line in raw.splitlines() if line]
requests = [event for event in events if event["kind"] == "web.request"]
responses = [event for event in events if event["kind"] == "web.response"]
denials = [
    event
    for event in events
    if event["kind"] == "auth.denied" and event["data"].get("action") == "web"
]
websocket_ends = [event for event in events if event["kind"] == "web.websocket"]
assert any(
    event["data"].get("resource") == "web-demo"
    and event["data"].get("method") == "GET"
    and event["data"].get("path") == "/allowed"
    for event in requests
)
allowed_ids = {
    event.get("session_id")
    for event in requests
    if event["data"].get("resource") == "web-demo"
    and event["data"].get("path") == "/allowed"
}
assert any(
    event.get("session_id") in allowed_ids
    and event["data"].get("status") == 200
    and event["data"].get("bytes_out", 0) > 0
    for event in responses
)
assert len(denials) >= 4, f"expected policy, authority, guest, and bot denials; got {len(denials)}"
assert websocket_ends and websocket_ends[-1]["data"].get("bytes_in", 0) > 0
tcp_start = next(
    event
    for event in events
    if event["kind"] == "session.start"
    and event["data"].get("kind") == "tcp"
    and event["data"].get("resource") == "tcp-echo"
)
tcp_end = next(
    event
    for event in events
    if event["kind"] == "session.end"
    and event.get("session_id") == tcp_start.get("session_id")
)
assert tcp_end["data"]["bytes_in"] > 0 and tcp_end["data"]["bytes_out"] > 0
for secret in (
    "phase12_query_secret",
    "omit-me",
    "spoofed-user",
    "not-forwarded",
    "phase12-websocket-roundtrip",
    "__Host-limen_app",
):
    assert secret not in raw, f"sensitive request content entered audit: {secret}"
print(
    f"{len(requests)} web requests, {len(responses)} responses, "
    f"{len(denials)} denials, WebSocket end, and TCP byte counts audited; "
    "query values and payloads absent"
)
PY
pass "audit events and the console request projection verified"
printf '\nPhase 12 end-to-end demo passed.\n'
