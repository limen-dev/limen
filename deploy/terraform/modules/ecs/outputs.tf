output "cluster_arn" {
  value = coalesce(var.cluster_arn, try(aws_ecs_cluster.this[0].arn, null))
}

output "service_name" {
  value = aws_ecs_service.this.name
}

output "security_group_id" {
  description = "Security group of the tasks; allow it on the peer's ingress."
  value       = aws_security_group.this.id
}

output "task_role_name" {
  description = "Attach further policies (KMS, S3) to this role."
  value       = aws_iam_role.task.name
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.this.name
}
