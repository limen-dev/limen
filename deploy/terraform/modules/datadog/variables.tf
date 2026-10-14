variable "environment" {
  description = "The control plane's --environment; logs are tagged env:<environment>."
  type        = string
}

variable "notify" {
  description = "Notification handles appended to every monitor message, e.g. [\"@slack-security\", \"@pagerduty-limen\"]."
  type        = list(string)
  default     = []
}

variable "metrics_namespace" {
  description = <<-EOT
    Namespace the Datadog Agent's OpenMetrics check gives Limen's /metrics,
    so `limen_audit_spool_pending` arrives as `<namespace>.limen_audit_spool_pending`.
    Set to null to skip the metric monitors (log monitors only).
  EOT
  type        = string
  default     = "limen"
}

variable "denied_threshold" {
  description = "Denied logins/sessions in 10 minutes that trigger an alert."
  type        = number
  default     = 20
}

variable "spool_pending_threshold" {
  description = "Unshipped events in any spool, sustained for 15 minutes."
  type        = number
  default     = 10000
}

variable "tags" {
  type    = list(string)
  default = ["service:limen"]
}
