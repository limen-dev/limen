output "autoscaling_group_name" {
  value = aws_autoscaling_group.this.name
}

output "security_group_id" {
  description = "Security group of the instances; allow it on the peer's ingress."
  value       = aws_security_group.this.id
}

output "role_name" {
  description = "Attach further policies (KMS, S3) to this role."
  value       = aws_iam_role.this.name
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.this.name
}
