module "security_group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 6.0"

  for_each = local.groups

  name            = "${var.name}-${each.key}"
  description     = "Limen ${each.value.component}"
  vpc_id          = each.value.vpc_id
  use_name_prefix = true

  ingress_rules = {
    for k, rule in local.ingress_rules[each.key] : k => merge(rule, {
      from_port   = each.value.port.main
      to_port     = each.value.port.main
      ip_protocol = "tcp"
    })
  }
  # Every component dials out; inbound is only the service port.
  egress_rules = {
    all = { ip_protocol = "-1", cidr_ipv4 = "0.0.0.0/0" }
  }

  tags = var.tags
}

resource "aws_cloudwatch_log_group" "this" {
  for_each = local.groups

  name              = "/limen/${var.name}/${each.key}"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

module "asg" {
  source  = "terraform-aws-modules/autoscaling/aws"
  version = "~> 9.3"

  for_each = local.groups

  name                = "${var.name}-${each.key}"
  vpc_zone_identifier = each.value.subnet_ids
  min_size            = each.value.min_size
  max_size            = each.value.max_size
  desired_capacity    = each.value.desired_capacity
  # Scale with your own policies without Terraform resetting the count.
  ignore_desired_capacity_changes = true

  health_check_type = length(each.value.target_group_arns) > 0 ? "ELB" : "EC2"
  traffic_source_attachments = {
    for i, arn in each.value.target_group_arns : "tg-${i}" => {
      traffic_source_identifier = arn
      traffic_source_type       = "elbv2"
    }
  }

  image_id      = data.aws_ssm_parameter.ami.value
  instance_type = each.value.instance_type
  network_interfaces = [{
    device_index                = 0
    associate_public_ip_address = each.value.associate_public_ip
    delete_on_termination       = true
    security_groups             = [module.security_group[each.key].id]
  }]

  block_device_mappings = [{
    device_name = "/dev/xvda"
    ebs = {
      volume_size = each.value.volume_size_gb
      volume_type = "gp3"
      encrypted   = true
    }
  }]

  # IMDSv2 only, one hop: containers cannot reach the instance role.
  metadata_options = {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  create_iam_instance_profile = true
  iam_role_name               = "${var.name}-${each.key}"
  iam_role_policies = merge(
    { ssm = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore" },
    each.value.role_policy_arns,
  )

  user_data = base64encode(templatefile("${path.module}/user-data.sh.tftpl", {
    image        = each.value.image
    component    = each.value.component
    region       = data.aws_region.current.region
    log_group    = aws_cloudwatch_log_group.this[each.key].name
    stop_timeout = each.value.stop_timeout
    publish      = local.publish[each.key]
    environment  = each.value.environment
    secrets      = each.value.secrets
  }))

  instance_refresh = {
    strategy = "Rolling"
    preferences = {
      min_healthy_percentage = 66
    }
  }

  tags = var.tags
}

# Secrets Manager read access for the secrets the group lists.
data "aws_iam_policy_document" "read_secrets" {
  for_each = { for k, g in local.groups : k => g if length(g.secrets) > 0 }

  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = values(each.value.secrets)
  }
}

resource "aws_iam_role_policy" "read_secrets" {
  for_each = data.aws_iam_policy_document.read_secrets

  name   = "read-secrets"
  role   = module.asg[each.key].iam_role_name
  policy = each.value.json
}
