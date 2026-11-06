# Terraform module: audit

The audit store: an S3 bucket the control plane appends signed, hash-chained batches and recordings to, a Glue table over it with partition projection, and an Athena workgroup for Grafana. It also outputs the IAM policies for the control plane (write), Grafana (read) and the verifier.

```hcl
module "audit" {
  source = "github.com/limen-dev/limen//deploy/terraform/modules/audit?ref=vX.Y.Z"

  name = "limen"
}
```

Unverified: validated with `terraform validate`, never applied to AWS (#123).

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
| ---- | ------- |
| terraform | >= 1.6 |
| aws | >= 6.0, < 7.0 |



## Resources

| Name | Type |
| ---- | ---- |
| [aws_athena_workgroup.audit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/athena_workgroup) | resource |
| [aws_glue_catalog_database.audit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/glue_catalog_database) | resource |
| [aws_glue_catalog_table.events](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/glue_catalog_table) | resource |
| [aws_iam_role.verifier](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy.verifier](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_kms_alias.audit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_alias) | resource |
| [aws_kms_key.audit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key) | resource |
| [aws_s3_bucket.athena_results](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
| [aws_s3_bucket.audit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
| [aws_s3_bucket_lifecycle_configuration.athena_results](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_lifecycle_configuration) | resource |
| [aws_s3_bucket_lifecycle_configuration.audit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_lifecycle_configuration) | resource |
| [aws_s3_bucket_object_lock_configuration.audit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_object_lock_configuration) | resource |
| [aws_s3_bucket_ownership_controls.athena_results](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_ownership_controls) | resource |
| [aws_s3_bucket_ownership_controls.audit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_ownership_controls) | resource |
| [aws_s3_bucket_policy.audit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_policy) | resource |
| [aws_s3_bucket_public_access_block.athena_results](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block) | resource |
| [aws_s3_bucket_public_access_block.audit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block) | resource |
| [aws_s3_bucket_server_side_encryption_configuration.athena_results](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_server_side_encryption_configuration) | resource |
| [aws_s3_bucket_server_side_encryption_configuration.audit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_server_side_encryption_configuration) | resource |
| [aws_s3_bucket_versioning.audit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_versioning) | resource |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.assume_verifier](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.bucket](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.reader](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.verifier](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.verifier_trust](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.writer](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_partition.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/partition) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| name | Prefix for every resource name, e.g. "limen-prod". | `string` | n/a | yes |
| athena\_bytes\_scanned\_cutoff | Per-query scan limit for the Athena workgroup, in bytes. | `number` | `10737418240` | no |
| athena\_results\_days | Days to keep Athena query results. | `number` | `7` | no |
| bucket\_name | Audit bucket name. Defaults to "<name>-audit-<account id>". | `string` | `null` | no |
| deny\_version\_deletion | Deny s3:DeleteObjectVersion on the audit bucket to every principal. Lifecycle expiry still applies. | `bool` | `true` | no |
| kms\_key\_arn | Existing KMS key for the bucket. A new key is created when null. | `string` | `null` | no |
| object\_lock\_days | Object Lock retention in compliance mode, in days. 0 disables Object Lock.<br/>Object Lock can only be turned on when the bucket is created, and nobody,<br/>including the account root, can delete a locked object early. | `number` | `0` | no |
| retention\_days | Days to keep audit events, manifests, and recordings. 0 keeps them forever. | `number` | `400` | no |
| tags | Tags for every resource. | `map(string)` | `{}` | no |
| verifier\_trusted\_principal\_arns | IAM principals allowed to assume the verifier role: the control plane's task<br/>or instance role. The control plane assumes it to give auditors short-lived,<br/>read-only access for `limen audit verify`. Leave empty to create no role and<br/>attach verifier\_policy\_json yourself. | `list(string)` | `[]` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| assume\_verifier\_policy\_json | IAM policy for the control plane's role, letting it assume the verifier role. Null when no verifier role exists. |
| athena\_workgroup | Workgroup for Grafana's Athena data source. |
| bucket | Audit bucket name, for --audit-s3-bucket. |
| bucket\_arn | Audit bucket ARN. |
| glue\_database | Glue database holding the events table. |
| glue\_table | Glue table over the audit events, with partition projection. |
| kms\_key\_arn | Key for --audit-s3-kms-key. |
| reader\_policy\_json | IAM policy for Grafana. |
| verifier\_policy\_json | Read-only IAM policy for the audit bucket. Attached to the verifier role when verifier\_trusted\_principal\_arns is set. |
| verifier\_role\_arn | Role for the control plane's LIMEN\_AUDIT\_VERIFIER\_ROLE\_ARN. Null when verifier\_trusted\_principal\_arns is empty. |
| writer\_policy\_json | IAM policy for the control plane. |
<!-- END_TF_DOCS -->
