# Datadog monitors for Limen (ADR-0009, ADR-0011). Log monitors read the
# audit events the control plane ships (source:limen); metric monitors read
# Limen's Prometheus metrics through the Agent's OpenMetrics check.
#
# Unverified against real Datadog: checked with `terraform validate` only.

locals {
  notify = join(" ", var.notify)
  logs   = "source:limen env:${var.environment}"
  metrics = var.metrics_namespace == null ? {} : {
    spool_backlog = {
      name     = "Limen: audit spool backlog (${var.environment})"
      query    = "max(last_15m):max:${var.metrics_namespace}.limen_audit_spool_pending{env:${var.environment}} by {host,consumer} > ${var.spool_pending_threshold}"
      critical = var.spool_pending_threshold
      message  = "Audit events are piling up in the {{consumer.name}} spool on {{host.name}}: a sink is failing. If the spool fills, the component refuses new sessions (fail closed). Runbook: docs/runbooks/audit-spool-full.md"
    }
    ship_errors = {
      name     = "Limen: audit shipping failing (${var.environment})"
      query    = "sum(last_10m):sum:${var.metrics_namespace}.limen_audit_ship_errors_total.count{env:${var.environment}} by {consumer}.as_count() > 10"
      critical = 10
      message  = "Shipping audit events to {{consumer.name}} keeps failing. Events are safe in the spool until it fills. Runbook: docs/runbooks/audit-spool-full.md"
    }
    policy_stale = {
      name     = "Limen: cached policy getting stale (${var.environment})"
      query    = "max(last_5m):max:${var.metrics_namespace}.limen_policy_snapshot_age_seconds{env:${var.environment}} by {host} > 240"
      critical = 240
      message  = "{{host.name}} can't refresh its signed policy from the control plane. Database, Redis, and Kubernetes access stops after the 5-minute grace period; SSH already fails closed."
    }
    ca_errors = {
      name     = "Limen: CA signing errors (${var.environment})"
      query    = "sum(last_10m):sum:${var.metrics_namespace}.limen_ca_sign_errors_total.count{env:${var.environment}} by {kind}.as_count() > 0"
      critical = 0
      message  = "The CA failed to sign {{kind.name}} certificates. Logins and new sessions fail while signing is down. With KMS, check the key, its policy and AWS availability."
    }
    worker_disconnected = {
      name     = "Limen: worker without a tunnel (${var.environment})"
      query    = "max(last_5m):max:${var.metrics_namespace}.limen_worker_tunnels_up{env:${var.environment}} by {host} < 1"
      critical = 1
      message  = "Worker {{host.name}} has no tunnel to any proxy: its targets are unreachable."
    }
    no_workers = {
      name     = "Limen: no worker tunnels (${var.environment})"
      query    = "max(last_5m):sum:${var.metrics_namespace}.limen_proxy_tunnels{env:${var.environment}} < 1"
      critical = 1
      message  = "No worker has a tunnel to any proxy: no target is reachable."
    }
  }
}

resource "datadog_monitor" "denied_spike" {
  name    = "Limen: spike in denied access (${var.environment})"
  type    = "log alert"
  query   = "logs(\"${local.logs} event_kind:auth.denied\").index(\"*\").rollup(\"count\").last(\"10m\") > ${var.denied_threshold}"
  message = "More than ${var.denied_threshold} denied logins or sessions in 10 minutes. Check the \"Failed and denied attempts\" panel in Grafana. ${local.notify}"
  monitor_thresholds {
    critical = var.denied_threshold
  }
  tags = var.tags
}

resource "datadog_monitor" "audit_silent" {
  name    = "Limen: no audit events (${var.environment})"
  type    = "log alert"
  query   = "logs(\"${local.logs}\").index(\"*\").rollup(\"count\").last(\"1h\") < 1"
  message = "No Limen audit event has reached Datadog in an hour. Either nothing is happening or the Datadog sink is down. ${local.notify}"
  monitor_thresholds {
    critical = 1
  }
  notify_no_data    = true
  no_data_timeframe = 120
  tags              = var.tags
}

resource "datadog_monitor" "policy_change" {
  name    = "Limen: policy changed (${var.environment})"
  type    = "log alert"
  query   = "logs(\"${local.logs} event_kind:policy.change\").index(\"*\").rollup(\"count\").last(\"5m\") > 0"
  message = "Access policy was changed by {{log.attributes.user}}. Confirm it was expected. ${local.notify}"
  monitor_thresholds {
    critical = 0
  }
  tags = var.tags
}

resource "datadog_monitor" "metric" {
  for_each = local.metrics
  name     = each.value.name
  type     = "query alert"
  query    = each.value.query
  message  = "${each.value.message} ${local.notify}"
  monitor_thresholds {
    critical = each.value.critical
  }
  require_full_window = false
  tags                = var.tags
}
