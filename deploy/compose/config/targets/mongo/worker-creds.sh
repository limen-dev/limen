#!/bin/sh
# Lays out what the worker holds for the MongoDB target (Phase 9): the CA that
# signs the server's certificate, one password file per SCRAM role, and the
# client certificate for X.509 login. The server's own key stays in the
# mongo-tls volume; the worker never sees it. Development only.
# Reads /tls (from gen-tls.sh); writes /worker.
set -eu
umask 022
mkdir -p /worker/catalog-staging /worker/x509
cp /tls/ca.pem /worker/ca.pem
# The role name picks the certificate: limen-read acts as the X.509 user.
cp /tls/client.pem /worker/x509/limen-read.pem
printf 'limen-read-dev-only\n' > /worker/catalog-staging/limen-read
printf 'limen-rw-dev-only\n' > /worker/catalog-staging/limen-rw
echo "worker credentials written"
