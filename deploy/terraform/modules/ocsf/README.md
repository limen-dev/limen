# Terraform module: ocsf

The bucket and KMS key for the OCSF export of the audit trail (ADR-0047, [guide](../../../../docs/guides/audit-ocsf.md)), and the IAM policies for the control plane (write) and a SIEM collector (read). It is separate from the [audit](../audit/README.md) module on purpose: the audit bucket and its key also hold session recordings, and a SIEM reader must not be able to reach them.

```hcl
module "ocsf" {
  source = "github.com/limen-dev/limen//deploy/terraform/modules/ocsf?ref=vX.Y.Z"

  name = "limen"
}
```

Then run the control plane with `--audit-ocsf-s3-bucket`, `--audit-ocsf-s3-kms-key` (the module's outputs) and attach `writer_policy_json` to its role. Give the SIEM collector `reader_policy_json`.

Unverified: validated with `terraform validate`, never applied to AWS.

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
| ---- | ------- |
| terraform | >= 1.6 |
| aws | >= 6.0, < 7.0 |



## Resources

| Name | Type |
| ---- | ---- |
| [aws_kms_alias.ocsf](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_alias) | resource |
| [aws_kms_key.ocsf](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key) | resource |
| [aws_s3_bucket.ocsf](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
| [aws_s3_bucket_lifecycle_configuration.ocsf](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_lifecycle_configuration) | resource |
| [aws_s3_bucket_ownership_controls.ocsf](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_ownership_controls) | resource |
| [aws_s3_bucket_policy.ocsf](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_policy) | resource |
| [aws_s3_bucket_public_access_block.ocsf](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block) | resource |
| [aws_s3_bucket_server_side_encryption_configuration.ocsf](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_server_side_encryption_configuration) | resource |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.bucket](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.reader](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.writer](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| name | Prefix for every resource name, e.g. "limen-prod". | `string` | n/a | yes |
| audit\_kms\_key\_arn | The audit bucket's KMS key (the audit module's kms\_key\_arn output). Optional: when set, applying fails if kms\_key\_arn is the same key, because that key also protects recordings. | `string` | `null` | no |
| bucket\_name | OCSF bucket name. Defaults to "<name>-ocsf-<account id>". | `string` | `null` | no |
| kms\_key\_arn | Existing KMS key for the bucket. It must not be the audit key, which also protects recordings. A new key is created when null. | `string` | `null` | no |
| retention\_days | Days to keep OCSF objects. The audit bucket is the record; this copy is for the SIEM. 0 keeps them forever. | `number` | `90` | no |
| tags | Tags for every resource. | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| bucket | OCSF bucket name, for --audit-ocsf-s3-bucket. |
| bucket\_arn | OCSF bucket ARN. |
| kms\_key\_arn | Key for --audit-ocsf-s3-kms-key. |
| reader\_policy\_json | IAM policy for the SIEM's collector: this bucket and this key only. |
| writer\_policy\_json | IAM policy for the control plane's OCSF writes. |
<!-- END_TF_DOCS -->