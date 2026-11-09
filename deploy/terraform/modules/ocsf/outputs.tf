output "bucket" {
  description = "OCSF bucket name, for --audit-ocsf-s3-bucket."
  value       = aws_s3_bucket.ocsf.bucket
}

output "bucket_arn" {
  description = "OCSF bucket ARN."
  value       = aws_s3_bucket.ocsf.arn
}

output "kms_key_arn" {
  description = "Key for --audit-ocsf-s3-kms-key."
  value       = local.kms_arn
}

output "writer_policy_json" {
  description = "IAM policy for the control plane's OCSF writes."
  value       = data.aws_iam_policy_document.writer.json
}

output "reader_policy_json" {
  description = "IAM policy for the SIEM's collector: this bucket and this key only."
  value       = data.aws_iam_policy_document.reader.json
}
