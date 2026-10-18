#!/usr/bin/env bash
# Starts (or stops) the PostgreSQL, MySQL, and MongoDB targets for the database
# integration tests (Phase 6, ADR-0033; Phase 9, ADR-0035), with plain
# `docker run` so a CI runner needs only Docker. The same servers, TLS, seed
# data and pg_hba.conf as stacks/db.yml (MongoDB: stacks/mongo.yml).
#
#   scripts/ci-db-targets.sh start    # then use the variables it prints
#   scripts/ci-db-targets.sh stop
#
# Under GitHub Actions the variables go to $GITHUB_ENV; otherwise they are
# printed as `export` lines.
set -euo pipefail
here="$(cd "$(dirname "$0")/../deploy/compose" && pwd)"
# shellcheck source=../deploy/compose/.env
set -a; source "$here/.env"; set +a # image versions
work="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/limen-db-targets"
pg=limen-ci-pg-target
my=limen-ci-mysql-target
mongo=limen-ci-mongo-target

stop() { docker rm -f "$pg" "$my" "$mongo" >/dev/null 2>&1 || true; }

case "${1:-}" in
  stop) stop; exit 0 ;;
  start) ;;
  *) echo "usage: $0 start|stop" >&2; exit 2 ;;
esac

stop
rm -rf "$work"; mkdir -p "$work/tls" "$work/mongo-tls"
# A throwaway CA and server certificates (the script chowns the keys for the
# postgres and mysql users).
docker run --rm -v "$work/tls:/tls" -v "$here/config/targets/tls/gen.sh:/gen.sh:ro" "$ALPINE_IMAGE" /bin/sh /gen.sh >/dev/null

docker run --rm -v "$work/mongo-tls:/tls" -v "$here/config/targets/mongo/gen-tls.sh:/gen.sh:ro" alpine:3.22 /bin/sh /gen.sh >/dev/null

# 127.0.0.1 only; the tests name the certificates' host (postgres-target,
# mysql-target) with tls_server_name.
docker run -d --name "$pg" -p 127.0.0.1:15432:5432 \
  -e POSTGRES_PASSWORD=postgres-target-dev-only \
  -v "$here/config/targets/postgres/init.sql:/docker-entrypoint-initdb.d/10-init.sql:ro" \
  -v "$here/config/targets/postgres/pg_hba.conf:/etc/limen/pg_hba.conf:ro" \
  -v "$work/tls:/tls:ro" \
  "$POSTGRES_IMAGE" postgres -c ssl=on -c ssl_cert_file=/tls/pg.crt -c ssl_key_file=/tls/pg.key \
  -c hba_file=/etc/limen/pg_hba.conf >/dev/null

# Small on purpose: the self-hosted runners have 8 GiB, shared with the build.
docker run -d --name "$my" -p 127.0.0.1:13306:3306 \
  -e MYSQL_ROOT_PASSWORD=mysql-target-dev-only \
  -v "$here/config/targets/mysql/init.sql:/docker-entrypoint-initdb.d/10-init.sql:ro" \
  -v "$work/tls:/tls:ro" \
  "$MYSQL_IMAGE" mysqld --ssl-ca=/tls/ca.pem --ssl-cert=/tls/my.crt --ssl-key=/tls/my.key \
  --performance-schema=OFF --innodb-buffer-pool-size=64M >/dev/null

# MongoDB with TLS, SCRAM, and X.509 (Phase 9); small for the same reason.
docker run -d --name "$mongo" -p 127.0.0.1:17017:27017 \
  -e MONGO_INITDB_ROOT_USERNAME=limen_admin -e MONGO_INITDB_ROOT_PASSWORD=limen-admin-dev-only \
  -v "$here/config/targets/mongo/init.js:/docker-entrypoint-initdb.d/10-init.js:ro" \
  -v "$work/mongo-tls:/tls:ro" \
  mongo:8.0 mongod --auth --tlsMode requireTLS --tlsCertificateKeyFile /tls/mongo.pem \
  --tlsCAFile /tls/ca.pem --tlsAllowConnectionsWithoutCertificates \
  --setParameter authenticationMechanisms=SCRAM-SHA-256,SCRAM-SHA-1,MONGODB-X509 \
  --wiredTigerCacheSizeGB 0.25 >/dev/null

# The image's init runs a temporary server first, so wait for the real one to
# answer as the seeded admin.
ready=false
for _ in $(seq 1 120); do
  if docker exec "$pg" psql -U limen_admin -d orders -tAc 'select 1' >/dev/null 2>&1 \
    && docker exec "$my" mysql -ulimen_admin -plimen-admin-dev-only orders -e 'select 1' >/dev/null 2>&1 \
    && docker exec "$mongo" mongosh --quiet --tls --tlsCAFile /tls/ca.pem --host localhost -u limen-read -p limen-read-dev-only --authenticationDatabase admin orders --eval 'db.customers.countDocuments()' >/dev/null 2>&1; then
    ready=true; break
  fi
  sleep 1
done
if ! $ready; then
  docker logs "$pg" 2>&1 | tail -5; docker logs "$my" 2>&1 | tail -5; docker logs "$mongo" 2>&1 | tail -5
  echo "the database targets did not come up" >&2; exit 1
fi

vars=(
  "LIMEN_TEST_PG_TARGET=localhost:15432"
  "LIMEN_TEST_MYSQL_TARGET=localhost:13306"
  "LIMEN_TEST_PG_CA_FILE=$work/tls/ca.pem"
  "LIMEN_TEST_MONGO_TARGET=localhost:17017"
  "LIMEN_TEST_MONGO_CA_FILE=$work/mongo-tls/ca.pem"
  "LIMEN_TEST_MONGO_CLIENT_PEM=$work/mongo-tls/client.pem"
)
if [ -n "${GITHUB_ENV:-}" ]; then
  printf '%s\n' "${vars[@]}" >> "$GITHUB_ENV"
else
  printf 'export %s\n' "${vars[@]}"
fi
