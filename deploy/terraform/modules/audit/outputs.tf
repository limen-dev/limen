output "bucket" {
  description = "Audit bucket name, for --audit-s3-bucket."
  value       = aws_s3_bucket.audit.bucket
}

output "bucket_arn" {
  description = "Audit bucket ARN."
  value       = aws_s3_bucket.audit.arn
}

output "kms_key_arn" {
  description = "Key for --audit-s3-kms-key."
  value       = local.kms_arn
}

output "glue_database" {
  description = "Glue database holding the events table."
  value       = aws_glue_catalog_database.audit.name
}

output "glue_table" {
  description = "Glue table over the audit events, with partition projection."
  value       = aws_glue_catalog_table.events.name
}

output "athena_workgroup" {
  description = "Workgroup for Grafana's Athena data source."
  value       = aws_athena_workgroup.audit.name
}

output "writer_policy_json" {
  description = "IAM policy for the control plane."
  value       = data.aws_iam_policy_document.writer.json
}

output "reader_policy_json" {
  description = "IAM policy for Grafana."
  value       = data.aws_iam_policy_document.reader.json
}

output "verifier_policy_json" {
  description = "Read-only IAM policy for the audit bucket. Attached to the verifier role when verifier_trusted_principal_arns is set."
  value       = data.aws_iam_policy_document.verifier.json
}

output "verifier_role_arn" {
  description = "Role for the control plane's LIMEN_AUDIT_VERIFIER_ROLE_ARN. Null when verifier_trusted_principal_arns is empty."
  value       = try(aws_iam_role.verifier[0].arn, null)
}

output "assume_verifier_policy_json" {
  description = "IAM policy for the control plane's role, letting it assume the verifier role. Null when no verifier role exists."
  value       = try(data.aws_iam_policy_document.assume_verifier[0].json, null)
}
