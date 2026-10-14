output "bucket" {
  description = "Audit bucket name, for --audit-s3-bucket."
  value       = aws_s3_bucket.audit.bucket
}

output "bucket_arn" {
  value = aws_s3_bucket.audit.arn
}

output "kms_key_arn" {
  description = "Key for --audit-s3-kms-key."
  value       = local.kms_arn
}

output "glue_database" {
  value = aws_glue_catalog_database.audit.name
}

output "glue_table" {
  value = aws_glue_catalog_table.events.name
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
  description = "IAM policy for whoever runs limen-audit-verify."
  value       = data.aws_iam_policy_document.verifier.json
}
