data "aws_region" "current" {}

data "aws_ssm_parameter" "ami" {
  name = var.ami_ssm_parameter
}

locals {
  ports = {
    control-plane = { main = 3080, admin = 3081 }
    proxy         = { main = 3443, admin = 3444 }
    worker        = { main = null, admin = 3090 }
  }
  port = local.ports[var.component]

  environment = merge(
    { LIMEN_DATA_DIR = "/var/lib/limen/${var.component}" },
    var.environment,
  )

  # Docker publishes the main port on the host; the admin port stays on the
  # loopback interface for the health check.
  publish = concat(
    local.port.main == null ? [] : ["-p ${local.port.main}:${local.port.main}"],
    ["-p 127.0.0.1:${local.port.admin}:${local.port.admin}"],
  )
}

resource "aws_security_group" "this" {
  name_prefix = "${var.name}-"
  vpc_id      = var.vpc_id
  description = "Limen ${var.component}"
  tags        = merge(var.tags, { Name = var.name })
  lifecycle { create_before_destroy = true }
}

resource "aws_vpc_security_group_egress_rule" "all" {
  security_group_id = aws_security_group.this.id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "cidr" {
  for_each          = local.port.main == null ? toset([]) : toset(var.ingress_cidrs)
  security_group_id = aws_security_group.this.id
  ip_protocol       = "tcp"
  from_port         = local.port.main
  to_port           = local.port.main
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_ingress_rule" "sg" {
  for_each                     = local.port.main == null ? toset([]) : toset(var.ingress_security_group_ids)
  security_group_id            = aws_security_group.this.id
  ip_protocol                  = "tcp"
  from_port                    = local.port.main
  to_port                      = local.port.main
  referenced_security_group_id = each.value
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "this" {
  name_prefix        = "${var.name}-"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "this" {
  for_each   = toset(concat(var.task_role_policy_arns, ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]))
  role       = aws_iam_role.this.name
  policy_arn = each.value
}

data "aws_iam_policy_document" "read_secrets" {
  count = length(var.secrets) > 0 ? 1 : 0
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = values(var.secrets)
  }
}

resource "aws_iam_role_policy" "read_secrets" {
  count  = length(var.secrets) > 0 ? 1 : 0
  name   = "read-secrets"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.read_secrets[0].json
}

resource "aws_iam_instance_profile" "this" {
  name_prefix = "${var.name}-"
  role        = aws_iam_role.this.name
  tags        = var.tags
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/limen/${var.name}"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

resource "aws_launch_template" "this" {
  name_prefix   = "${var.name}-"
  image_id      = data.aws_ssm_parameter.ami.value
  instance_type = var.instance_type
  tags          = var.tags

  iam_instance_profile { name = aws_iam_instance_profile.this.name }

  network_interfaces {
    associate_public_ip_address = var.associate_public_ip
    security_groups             = [aws_security_group.this.id]
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size = var.volume_size_gb
      volume_type = "gp3"
      encrypted   = true
    }
  }

  # IMDSv2 only, one hop: containers cannot reach the instance role.
  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  user_data = base64encode(templatefile("${path.module}/user-data.sh.tftpl", {
    image        = var.image
    component    = var.component
    region       = data.aws_region.current.region
    log_group    = aws_cloudwatch_log_group.this.name
    stop_timeout = var.stop_timeout
    publish      = join(" ", local.publish)
    environment  = local.environment
    secrets      = var.secrets
  }))

  tag_specifications {
    resource_type = "instance"
    tags          = merge(var.tags, { Name = var.name })
  }
}

resource "aws_autoscaling_group" "this" {
  name_prefix         = "${var.name}-"
  vpc_zone_identifier = var.subnet_ids
  min_size            = var.min_size
  max_size            = var.max_size
  desired_capacity    = var.desired_capacity
  target_group_arns   = var.target_group_arn == null ? [] : [var.target_group_arn]
  health_check_type   = var.target_group_arn == null ? "EC2" : "ELB"

  # Terminating instances finish their drain on shutdown; give them the time.
  default_instance_warmup = 60

  launch_template {
    id      = aws_launch_template.this.id
    version = aws_launch_template.this.latest_version
  }

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 66
    }
  }

  lifecycle {
    create_before_destroy = true
    ignore_changes        = [desired_capacity]
  }
}
