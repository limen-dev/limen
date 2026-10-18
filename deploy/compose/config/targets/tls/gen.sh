#!/bin/sh
# Makes a throwaway CA and server certificates for the local database targets
# (Phase 6). Development only: the keys are regenerated whenever the volume is
# empty. Output in /tls: ca.pem, pg.crt/pg.key, my.crt/my.key.
set -eu
cd /tls
if [ -f ca.pem ]; then echo "certificates exist"; exit 0; fi
apk add --no-cache openssl >/dev/null
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
  -subj "/CN=Limen local database CA" -keyout ca.key -out ca.pem 2>/dev/null
for pair in "pg:postgres-target" "my:mysql-target"; do
  prefix="${pair%%:*}"; host="${pair##*:}"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -subj "/CN=$host" -keyout "$prefix.key" -out "$prefix.csr" 2>/dev/null
  printf "subjectAltName=DNS:%s,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n" "$host" > "$prefix.ext"
  openssl x509 -req -in "$prefix.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -days 3650 \
    -extfile "$prefix.ext" -out "$prefix.crt" 2>/dev/null
done
chmod 644 ca.pem pg.crt my.crt
chown 70:70 pg.key; chmod 600 pg.key      # postgres (alpine)
chown 999:999 my.key; chmod 600 my.key    # mysql (debian)
rm -f ca.key ./*.csr ./*.ext ca.srl
echo "certificates written"
