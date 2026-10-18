<img src="../../assets/logo-mark.svg" alt="Limen" width="64">

# dashboards/grafana

The Limen audit dashboard and alert rules (ADR-0014). They query the audit events the control plane writes to S3 (ADR-0009). Production uses Athena over the Glue table from `deploy/terraform/modules/audit`. The dev stack uses Trino over the same files: Athena's engine is Trino, so the SQL is identical.

| Path | What |
|---|---|
| `generate.py` | The one definition of every panel and alert. |
| `dashboards/athena/`, `dashboards/trino/` | Generated dashboards, one per data source. |
| `alerting/athena/`, `alerting/trino/` | Generated Grafana alert rules (file provisioning). |
| `queries.json` | Every query with the Grafana macros filled in, for running by hand or in the demo. |

The generated files are committed. After changing `generate.py`, run `python3 dashboards/grafana/generate.py`. CI fails if the output is stale.

## Panels

- Logins and denials over time
- Active sessions
- Access by resource type
- Who accessed what (user, resource, login, last access)
- Failed and denied attempts, with the reason
- Top users
- Privileged commands (root logins, `sudo`, `su`, `chown`, and similar)
- Ingestion lag per producer
- Missing events: gaps in each producer's sequence numbers (should always be 0)
- Policy changes

Delivery is at least once, so every count uses `count(DISTINCT event_id)` rather than counting rows. Each query also filters on the `dt` partition, so Athena only scans the days in the selected range.

## Alerts

| Rule | Fires when |
|---|---|
| Spike in denied access | More than 20 `auth.denied` events in 10 minutes |
| Audit events missing | Any producer's sequence has a gap |
| Audit ingestion stalled | No event has arrived in over an hour |

Add contact points in Grafana to route them. The Datadog equivalents, plus metric-based monitors, are in `deploy/terraform/modules/datadog`.

## Local (Trino)

`docker compose -f deploy/compose/docker-compose.yml up -d` starts Trino and Grafana with everything provisioned. Grafana is at http://localhost:3000; anonymous users get viewer access, and the admin login is `admin` / `limen-dev-only`. New events appear within about a minute: the control plane flushes to S3 every 10 s, and `trino-init` syncs partitions every 60 s.

## Production (Athena)

*Unverified against real AWS.* Install `grafana-athena-datasource` (tested version: 3.3.9). Then provision it with the outputs of the audit module and the `reader_policy_json` permissions on Grafana's task role:

```yaml
apiVersion: 1
datasources:
  - name: Limen audit (Athena)
    uid: limen-athena          # the generated dashboards refer to this uid
    type: grafana-athena-datasource
    jsonData:
      authType: default        # the ECS task role
      defaultRegion: eu-west-1
      catalog: AwsDataCatalog
      database: limen_prod_audit   # module output glue_database
      workgroup: limen-prod-audit  # module output athena_workgroup
```

Mount `dashboards/athena` as a dashboard provider and `alerting/athena` under `provisioning/alerting`.

## Branding

Grafana OSS can't replace its login-page logo. Custom branding (`[white_labeling]`) is a Grafana Enterprise and Grafana Cloud Pro feature. The only OSS options are patching the image's static assets or rewriting responses in a reverse proxy, and both break on upgrade, so we use stock Grafana. The web console (ADR-0017) has its own built-in dashboards, covering the last 30 days from its tables. These Grafana dashboards are the optional extra for full history.
