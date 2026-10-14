#!/bin/sh
# Create the audit table, then keep its partitions in sync with the bucket
# (Athena uses partition projection instead). Development only.
set -u
until trino --server http://trino:8080 --execute 'SELECT 1' >/dev/null 2>&1; do sleep 2; done
until trino --server http://trino:8080 --file /init/init.sql; do sleep 5; done
echo "audit table ready"
while :; do
  trino --server http://trino:8080 --execute \
    "CALL audit.system.sync_partition_metadata('limen', 'events_raw', 'FULL')" >/dev/null \
    || echo "partition sync failed; retrying"
  sleep "${SYNC_INTERVAL:-60}"
done
