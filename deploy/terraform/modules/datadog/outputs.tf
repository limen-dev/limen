output "monitor_ids" {
  value = merge(
    {
      denied_spike  = datadog_monitor.denied_spike.id
      audit_silent  = datadog_monitor.audit_silent.id
      policy_change = datadog_monitor.policy_change.id
    },
    { for k, m in datadog_monitor.metric : k => m.id },
  )
}
