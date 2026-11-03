# Limen datadog

Datadog monitors for Limen: log monitors on the audit events the control plane ships, and metric monitors on its Prometheus metrics through the Agent's OpenMetrics check.

```hcl
module "datadog" {
  source = "github.com/limen-dev/limen//deploy/terraform/modules/datadog?ref=vX.Y.Z"

  environment = "prod"
  notify      = ["@slack-security"]
}
```

Unverified: validated with `terraform validate`, never applied to AWS (#123).

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
| ---- | ------- |
| terraform | >= 1.6 |
| datadog | >= 4.0, < 5.0 |



## Resources

| Name | Type |
| ---- | ---- |
| [datadog_monitor.audit_silent](https://registry.terraform.io/providers/DataDog/datadog/latest/docs/resources/monitor) | resource |
| [datadog_monitor.denied_spike](https://registry.terraform.io/providers/DataDog/datadog/latest/docs/resources/monitor) | resource |
| [datadog_monitor.metric](https://registry.terraform.io/providers/DataDog/datadog/latest/docs/resources/monitor) | resource |
| [datadog_monitor.policy_change](https://registry.terraform.io/providers/DataDog/datadog/latest/docs/resources/monitor) | resource |

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| environment | The control plane's --environment; logs are tagged env:<environment>. | `string` | n/a | yes |
| denied\_threshold | Denied logins/sessions in 10 minutes that trigger an alert. | `number` | `20` | no |
| metrics\_namespace | Namespace the Datadog Agent's OpenMetrics check gives Limen's /metrics,<br/>so `limen_audit_spool_pending` arrives as `<namespace>.limen_audit_spool_pending`.<br/>Set to null to skip the metric monitors (log monitors only). | `string` | `"limen"` | no |
| notify | Notification handles appended to every monitor message, e.g. ["@slack-security", "@pagerduty-limen"]. | `list(string)` | `[]` | no |
| spool\_pending\_threshold | Unshipped events in any spool, sustained for 15 minutes. | `number` | `10000` | no |
| tags | Tags added to every monitor. | `list(string)` | <pre>[<br/>  "service:limen"<br/>]</pre> | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| monitor\_ids | Datadog monitor ids by name. |
<!-- END_TF_DOCS -->
