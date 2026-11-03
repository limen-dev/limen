output "role_arn" {
  description = "Put this in the discovery document's role_arn."
  value       = module.role.arn
}

output "assume_policy_arn" {
  description = "Policy that lets a worker role assume the discovery role. Attach it to the worker roles (role_policy_arns of the ec2 module)."
  value       = aws_iam_policy.assume.arn
}
