#!/bin/sh
# Makes a throwaway CA, a MongoDB server certificate, and one client
# certificate for X.509 login (Phase 9). Development only: the keys are
# regenerated whenever the output directory is empty.
# Output in /tls: ca.pem, mongo.pem (server cert + key, as mongod wants it),
# client.pem (worker's X.509 identity: cert + key).
set -eu
cd /tls
if [ -f ca.pem ]; then echo "certificates exist"; exit 0; fi
command -v openssl >/dev/null || apk add --no-cache openssl >/dev/null
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
  -subj "/CN=Limen local MongoDB CA" -keyout ca.key -out ca.pem 2>/dev/null
issue() { # name subject ext-file-content
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -subj "$2" -keyout "$1.key" -out "$1.csr" 2>/dev/null
  printf '%s\n' "$3" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -days 3650 \
    -extfile "$1.ext" -out "$1.crt" 2>/dev/null
  cat "$1.crt" "$1.key" > "$1.pem"
}
issue mongo "/CN=mongo-target" "subjectAltName=DNS:mongo-target,DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth,clientAuth"
issue client "/O=Limen/CN=limen-x509" "extendedKeyUsage=clientAuth"
chmod 644 ca.pem mongo.pem client.pem
chown 999:999 mongo.pem 2>/dev/null || true
rm -f ca.key ./*.csr ./*.ext ca.srl ./*.crt ./*.key
echo "certificates written"
