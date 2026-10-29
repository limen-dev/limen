output "cluster_arn" {
  description = "ARN of the ECS cluster."
  value       = module.cluster.arn
}

output "services" {
  description = "Per service key: name, security group (allow it on a peer's ingress) and the task role (attach KMS or S3 policies to it)."
  value = {
    for key, svc in module.service : key => {
      name              = svc.name
      security_group_id = svc.security_group_id
      task_role_name    = svc.tasks_iam_role_name
      task_role_arn     = svc.tasks_iam_role_arn
    }
  }
}
