# Terraform module: foundation

Everything Limen needs besides compute: a PostgreSQL database (RDS), the four KMS signing keys, the audit store (the `audit` module), the secrets (database URL, join tokens, the internal CA certificate) and an IAM role for the control plane's Kubernetes service account. Its outputs feed the `ecs` and `ec2` modules, or the Helm chart (`helm_values`, `kubernetes_secrets`).

```hcl
module "foundation" {
  source = "github.com/limen-dev/limen//deploy/terraform/modules/foundation?ref=vX.Y.Z"

  name       = "limen"
  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets
  oidc       = { issuer = "https://idp.example.com", client_id = "limen" }
  # ...
}
```

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
| audit | ../audit | n/a |
| ca\_key | terraform-aws-modules/kms/aws | ~> 4.2 |
| control\_plane\_irsa | terraform-aws-modules/iam/aws//modules/iam-role | ~> 6.8 |
| database | terraform-aws-modules/rds/aws | ~> 7.2 |
| database\_url | terraform-aws-modules/secrets-manager/aws | ~> 2.2 |
| internal\_ca | terraform-aws-modules/secrets-manager/aws | ~> 2.2 |
| join\_token | terraform-aws-modules/secrets-manager/aws | ~> 2.2 |
| static\_join\_tokens | terraform-aws-modules/secrets-manager/aws | ~> 2.2 |

## Resources

| Name | Type |
| ---- | ---- |
| [aws_iam_policy.audit_writer](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy.control_plane_kms](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy.ocsf_writer](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_security_group.database](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_vpc_security_group_ingress_rule.database_cidr](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc_security_group_ingress_rule) | resource |
| [random_password.database](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/password) | resource |
| [random_password.join_token](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/password) | resource |
| [aws_iam_policy_document.control_plane](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| database\_subnet\_ids | Private subnets (at least two zones) for the database. | `list(string)` | n/a | yes |
| name | Prefix for every resource, e.g. "limen-prod". | `string` | n/a | yes |
| oidc | Your identity provider's issuer URL and the Limen client id. The IdP itself is not created here. | <pre>object({<br/>    issuer    = string<br/>    client_id = string<br/>  })</pre> | n/a | yes |
| vpc\_id | VPC for the database. | `string` | n/a | yes |
| audit | Settings passed to the audit module (S3 Object Lock, retention, the optional OCSF export for SIEMs). | <pre>object({<br/>    retention_days   = optional(number, 400)<br/>    object_lock_days = optional(number, 0)<br/>    ocsf = optional(object({<br/>      enabled        = optional(bool, false)<br/>      bucket_name    = optional(string)<br/>      retention_days = optional(number, 90)<br/>      kms_key_arn    = optional(string)<br/>    }), {})<br/>  })</pre> | `{}` | no |
| console\_public\_url | Public URL users reach the proxy at, e.g. "https://limen.example.com". Turns on the web console. | `string` | `null` | no |
| database | PostgreSQL settings. Deletion protection and a final snapshot are on by default. | <pre>object({<br/>    engine_version         = optional(string, "17")<br/>    instance_class         = optional(string, "db.t4g.medium")<br/>    allocated_storage_gb   = optional(number, 50)<br/>    max_allocated_storage  = optional(number, 200)<br/>    multi_az               = optional(bool, true)<br/>    backup_retention_days  = optional(number, 14)<br/>    deletion_protection    = optional(bool, true)<br/>    skip_final_snapshot    = optional(bool, false)<br/>    database_name          = optional(string, "limen")<br/>    username               = optional(string, "limen")<br/>    performance_insights   = optional(bool, true)<br/>    apply_immediately      = optional(bool, false)<br/>    parameter_group_family = optional(string, "postgres17")<br/>    major_engine_version   = optional(string, "17")<br/>  })</pre> | `{}` | no |
| database\_allowed\_cidrs | CIDRs allowed to reach PostgreSQL, normally the control plane's subnets. Add per-service rules with the database\_security\_group\_id output. | `list(string)` | `[]` | no |
| eks\_oidc\_provider\_arn | OIDC provider ARN of your EKS cluster. When set, an IAM role for the control plane's Kubernetes service account is created (IRSA). | `string` | `null` | no |
| eks\_oidc\_provider\_url | Issuer URL of the EKS OIDC provider without https://. Required with eks\_oidc\_provider\_arn. | `string` | `null` | no |
| kubernetes\_namespace | Namespace the Helm release runs in (for the IRSA trust policy). | `string` | `"limen"` | no |
| name\_prefix | Prefix of the display names proxies and workers ask for (LIMEN\_NAME), approved by every static join token as the pattern "<prefix>-*". The Helm chart's namePrefix takes the same value from helm\_values. Defaults to name. Lowercase letters, digits and hyphens. | `string` | `null` | no |
| proxy\_dns\_names | DNS names proxies may put in their certificates (LIMEN\_PROXY\_DNS\_NAMES): every proxy's public name. | `list(string)` | `[]` | no |
| proxy\_groups | Keys of the proxy groups you will run. Each gets its own join token, labelled group=<key>. | `set(string)` | `[]` | no |
| tags | Tags added to every resource. | `map(string)` | `{}` | no |
| worker\_groups | Keys of the worker groups you will run. Each gets its own join token, labelled group=<key>. | `set(string)` | `[]` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| audit\_bucket | Audit bucket name. |
| ca\_key\_arns | ARN of each of the four KMS keys, by role (internal\_ca, user\_ca, ssh\_user\_ca, ssh\_host\_ca). |
| control\_plane\_environment | Plain LIMEN\_* settings for every control plane (ECS and EC2 modules: services.<key>.environment). |
| control\_plane\_irsa\_role\_arn | Role for the control plane's Kubernetes service account (set eks\_oidc\_provider\_arn). |
| control\_plane\_policy\_arns | Policies for the control plane's role: KMS signing, audit writes and, with audit.ocsf.enabled, OCSF writes. |
| control\_plane\_secrets | Secret ARNs for every control plane, as environment variable name => ARN. |
| database\_endpoint | PostgreSQL address. |
| database\_security\_group\_id | Allow the control plane's security group on port 5432 with aws\_vpc\_security\_group\_ingress\_rule. |
| helm\_values | Values for deploy/helm/limen's controlPlaneDefaults. Save with: terraform output -raw helm\_values > limen-values.yaml |
| internal\_ca\_secret\_arn | Secret the control plane publishes its internal CA certificate to; pass it as internal\_ca = { secret\_arn = ... } to the ecs and ec2 modules. |
| join\_token\_secret\_arns | Per group ("proxy-<key>", "worker-<key>"): the secret that holds its LIMEN\_JOIN\_TOKEN. |
| kubernetes\_secrets | Values for the Kubernetes Secrets the chart reads: database URL, the control plane's static tokens, and one token per proxy and worker group. |
| ocsf\_bucket | OCSF bucket name. Null unless audit.ocsf.enabled. |
| ocsf\_reader\_policy\_json | IAM policy for the SIEM's collector: the OCSF bucket and key only. Null unless audit.ocsf.enabled. |
<!-- END_TF_DOCS -->
