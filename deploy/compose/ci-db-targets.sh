#!/usr/bin/env bash
# Starts (or stops) the PostgreSQL and MySQL targets for the database
# integration tests (Phase 6, ADR-0033), with plain `docker run` so a CI runner
# needs only Docker. The same servers, TLS, seed data and pg_hba.conf as
# docker-compose.db-targets.yml.
#
#   deploy/compose/ci-db-targets.sh start    # then use the variables it prints
#   deploy/compose/ci-db-targets.sh stop
#
# Under GitHub Actions the variables go to $GITHUB_ENV; otherwise they are
# printed as `export` lines.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
work="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/limen-db-targets"
pg=limen-ci-pg-target
my=limen-ci-mysql-target

stop() { docker rm -f "$pg" "$my" >/dev/null 2>&1 || true; }

case "${1:-}" in
  stop) stop; exit 0 ;;
  start) ;;
  *) echo "usage: $0 start|stop" >&2; exit 2 ;;
esac

stop
rm -rf "$work"; mkdir -p "$work/tls"
# A throwaway CA and server certificates (the script chowns the keys for the
# postgres and mysql users).
docker run --rm -v "$work/tls:/tls" -v "$here/targets/tls/gen.sh:/gen.sh:ro" alpine:3.22 /bin/sh /gen.sh >/dev/null

# 127.0.0.1 only; the tests name the certificates' host (postgres-target,
# mysql-target) with tls_server_name.
docker run -d --name "$pg" -p 127.0.0.1:15432:5432 \
  -e POSTGRES_PASSWORD=postgres-target-dev-only \
  -v "$here/targets/postgres/init.sql:/docker-entrypoint-initdb.d/10-init.sql:ro" \
  -v "$here/targets/postgres/pg_hba.conf:/etc/limen/pg_hba.conf:ro" \
  -v "$work/tls:/tls:ro" \
  postgres:18-alpine postgres -c ssl=on -c ssl_cert_file=/tls/pg.crt -c ssl_key_file=/tls/pg.key \
  -c hba_file=/etc/limen/pg_hba.conf >/dev/null

# Small on purpose: the self-hosted runners have 8 GiB, shared with the build.
docker run -d --name "$my" -p 127.0.0.1:13306:3306 \
  -e MYSQL_ROOT_PASSWORD=mysql-target-dev-only \
  -v "$here/targets/mysql/init.sql:/docker-entrypoint-initdb.d/10-init.sql:ro" \
  -v "$work/tls:/tls:ro" \
  mysql:8.4 mysqld --ssl-ca=/tls/ca.pem --ssl-cert=/tls/my.crt --ssl-key=/tls/my.key \
  --performance-schema=OFF --innodb-buffer-pool-size=64M >/dev/null

# The image's init runs a temporary server first, so wait for the real one to
# answer as the seeded admin.
ready=false
for _ in $(seq 1 120); do
  if docker exec "$pg" psql -U limen_admin -d orders -tAc 'select 1' >/dev/null 2>&1 \
    && docker exec "$my" mysql -ulimen_admin -plimen-admin-dev-only orders -e 'select 1' >/dev/null 2>&1; then
    ready=true; break
  fi
  sleep 1
done
if ! $ready; then
  docker logs "$pg" 2>&1 | tail -5; docker logs "$my" 2>&1 | tail -5
  echo "the database targets did not come up" >&2; exit 1
fi

vars=(
  "LIMEN_TEST_PG_TARGET=localhost:15432"
  "LIMEN_TEST_MYSQL_TARGET=localhost:13306"
  "LIMEN_TEST_PG_CA_FILE=$work/tls/ca.pem"
)
if [ -n "${GITHUB_ENV:-}" ]; then
  printf '%s\n' "${vars[@]}" >> "$GITHUB_ENV"
else
  printf 'export %s\n' "${vars[@]}"
fi
