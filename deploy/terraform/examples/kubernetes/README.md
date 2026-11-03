# Kubernetes example

The foundation for the Helm chart: database, keys, audit store and secrets, plus the control plane's IRSA role. It does not create the cluster. `terraform output -raw helm_values > limen-values.yaml`, then follow [Deploying Limen on AWS](../../../../docs/guides/deploy.md) (On Kubernetes).

Unverified: validated with `terraform validate`, never applied to AWS (#123).

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
| ---- | ------- |
| terraform | >= 1.6 |
| aws | >= 6.0, < 7.0 |
| random | >= 3.6, < 4.0 |

## Modules

| Name | Source | Version |
| ---- | ------ | ------- |
| foundation | ../../modules/foundation | n/a |



## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| database\_subnet\_ids | Private subnets of that VPC, in at least two zones. | `list(string)` | n/a | yes |
| eks\_oidc\_provider\_arn | OIDC provider ARN of the cluster (IRSA). | `string` | n/a | yes |
| eks\_oidc\_provider\_url | Issuer URL of that provider, without https://. | `string` | n/a | yes |
| node\_cidrs | CIDRs of the EKS nodes or pods that may reach PostgreSQL (the control plane runs there). | `list(string)` | n/a | yes |
| oidc | Your identity provider's issuer URL and the client id registered for Limen. | <pre>object({<br/>    issuer    = string<br/>    client_id = string<br/>  })</pre> | n/a | yes |
| proxies | Proxy groups you will run, keyed as in the chart's `proxies`, with the public DNS name of each. | `map(object({ dns_name = string }))` | n/a | yes |
| vpc\_id | VPC of your EKS cluster. The database goes here. | `string` | n/a | yes |
| worker\_groups | Keys of the worker groups you will run, as in the chart's `workers`. | `set(string)` | n/a | yes |
| database | PostgreSQL settings (see modules/foundation). | `any` | `{}` | no |
| kubernetes\_namespace | Namespace the chart is installed in; the IRSA role trusts its service accounts. | `string` | `"limen"` | no |
| name | Prefix for every resource. | `string` | `"limen-prod"` | no |
| region | AWS region for the foundation. | `string` | `"eu-west-1"` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| control\_plane\_role\_arn | IRSA role for the control plane service account, or null without eks\_oidc\_provider\_arn. |
| helm\_values | Values for the chart's controlPlaneDefaults. |
| kubernetes\_secrets | Secret values for kubectl (see docs/guides/deploy.md). |
<!-- END_TF_DOCS -->
