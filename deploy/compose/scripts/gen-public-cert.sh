#!/usr/bin/env bash
# Make a throwaway CA and a server certificate from it, to stand in for a public CA's certificate
# in the dev stack (stacks/public-cert.yml). Dev only: the key is world-readable so the proxy's
# non-root user can read it.
#
#   gen-public-cert.sh <dir>            # writes ca.pem, cert.pem, key.pem; keeps what is there
#   gen-public-cert.sh <dir> --renew    # a new server certificate from the same CA
set -euo pipefail

dir="${1:?usage: gen-public-cert.sh <dir> [--renew]}"
renew=false
[ "${2:-}" = --renew ] && renew=true
mkdir -p "$dir"
chmod 755 "$dir"

# A P-256 key that names its curve. macOS's LibreSSL otherwise writes the curve's full parameters
# into the key and the certificate, which no public CA does and which rustls cannot match to the
# certificate (the proxy refuses such a pair as a key mismatch).
named_curve_key() {
  openssl ecparam -name prime256v1 -genkey -noout -out "$1" 2>/dev/null
}

if [ ! -f "$dir/ca.pem" ] || [ ! -f "$dir/ca.key" ]; then
  cat >"$dir/ca.cnf" <<'CNF'
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = Limen dev stand-in public CA
[ext]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
CNF
  named_curve_key "$dir/ca.key"
  openssl req -x509 -new -sha256 -key "$dir/ca.key" -days 30 -config "$dir/ca.cnf" -out "$dir/ca.pem" 2>/dev/null
  chmod 600 "$dir/ca.key"
  renew=true
fi

if $renew || [ ! -f "$dir/cert.pem" ] || [ ! -f "$dir/key.pem" ]; then
  cat >"$dir/leaf.cnf" <<'CNF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = localhost
[ext]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,DNS:proxy,DNS:app.apps.test,DNS:other.apps.test,IP:127.0.0.1
CNF
  named_curve_key "$dir/key.pem.new"
  openssl req -new -key "$dir/key.pem.new" -config "$dir/leaf.cnf" -out "$dir/leaf.csr" 2>/dev/null
  openssl x509 -req -sha256 -in "$dir/leaf.csr" -CA "$dir/ca.pem" -CAkey "$dir/ca.key" \
    -set_serial "0x$(openssl rand -hex 8)" -days 30 -extfile "$dir/leaf.cnf" -extensions ext \
    -out "$dir/cert.pem.new" 2>/dev/null
  chmod 644 "$dir/key.pem.new" "$dir/cert.pem.new"
  # Move the pair into place together so a reader never sees a certificate with the old key.
  mv "$dir/key.pem.new" "$dir/key.pem"
  mv "$dir/cert.pem.new" "$dir/cert.pem"
  rm -f "$dir/leaf.csr"
fi
