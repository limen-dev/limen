# Audit pipeline backlog / spool full

Every component writes audit events to a local spool before anything else (ADR-0009). A sink (S3, Datadog, the JSONL file) or the link to the control plane being down fills it. **Nothing is lost while the spool has room.** When it's full, the default is fail closed: new sessions and logins are refused.

## Detect
- Metric `limen_audit_spool_pending{consumer}`: events not yet shipped. `limen_audit_spool_bytes`: disk used.
- `limen_audit_ship_errors_total{consumer}` rising: that consumer is failing.
- Datadog monitors "audit spool backlog" and "audit shipping failing" (`deploy/terraform/modules/datadog`).
- Control plane log: `audit sink failing` with the cause.

## Fix
1. Find which consumer is behind (the `consumer` label: `s3`, `datadog`, `jsonl`) and read its error in the control plane log.
2. Restore the dependency, usually one of:
   - S3: IAM (the writer policy), KMS key access, bucket policy, network.
   - Datadog: API key (`DD_API_KEY`), intake URL, a 4xx other than 408/429. 401/403 are retried because a rotated key may be coming.
   - Proxy or worker: connectivity to the control plane, certificate expiry.
3. Don't delete spool files. The spool drains by itself once the sink recovers; watch `limen_audit_spool_pending` fall to 0.

## If the spool is full
Sessions are refused with an audit-unavailable error. Free the cause above first. If you need more room while you fix it, raise `--audit-spool-max-bytes` and restart the component: the spool survives restarts and picks up where it left off. Don't turn off fail-closed to get around an outage unless the owner accepts losing audit completeness.

## Check afterwards
Run [the chain verification](audit-verify.md), and look at the "Missing events" panel in Grafana: it should be zero.
