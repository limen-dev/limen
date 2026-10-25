output "role_arn" {
  description = "Put this in the discovery document's accounts[].role_arn."
  value       = aws_iam_role.discovery.arn
}

output "actions" {
  description = "Every action the role can take. All of them read."
  value       = local.allowed
}
