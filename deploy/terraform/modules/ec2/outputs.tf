output "groups" {
  description = "Per group key: Auto Scaling group name, security group (allow it on a peer's ingress) and the instance role (attach KMS or S3 policies to it)."
  value = {
    for key, asg in module.asg : key => {
      autoscaling_group_name = asg.autoscaling_group_name
      security_group_id      = module.security_group[key].id
      role_name              = asg.iam_role_name
      role_arn               = asg.iam_role_arn
    }
  }
}
