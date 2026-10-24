data "aws_region" "current" {}

locals {
  # Ports and health checks per component; see deploy/kubernetes/limen.
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
}

resource "aws_ecs_cluster" "this" {
  count = var.cluster_arn == null ? 1 : 0
  name  = var.name
  tags  = var.tags
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/limen/${var.name}"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

resource "aws_security_group" "this" {
  name_prefix = "${var.name}-"
  vpc_id      = var.vpc_id
  description = "Limen ${var.component}"
  tags        = merge(var.tags, { Name = var.name })
  lifecycle { create_before_destroy = true }
}

# Every component dials out (control plane to its database and KMS, proxy to
# the control plane, worker to the proxy); the only inbound port is the
# component's own.
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
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name_prefix        = "${var.name}-exec-"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "read_secrets" {
  count = length(var.secrets) > 0 ? 1 : 0
  statement {
    actions   = ["secretsmanager:GetSecretValue", "ssm:GetParameters"]
    resources = values(var.secrets)
  }
}

resource "aws_iam_role_policy" "read_secrets" {
  count  = length(var.secrets) > 0 ? 1 : 0
  name   = "read-secrets"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.read_secrets[0].json
}

resource "aws_iam_role" "task" {
  name_prefix        = "${var.name}-task-"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "task" {
  for_each   = toset(var.task_role_policy_arns)
  role       = aws_iam_role.task.name
  policy_arn = each.value
}

resource "aws_ecs_task_definition" "this" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn
  tags                     = var.tags

  container_definitions = jsonencode([{
    name        = var.component
    image       = var.image
    essential   = true
    stopTimeout = var.stop_timeout
    portMappings = concat(
      local.port.main == null ? [] : [{ containerPort = local.port.main, protocol = "tcp" }],
      [{ containerPort = local.port.admin, protocol = "tcp" }],
    )
    environment = [for k, v in local.environment : { name = k, value = v }]
    secrets     = [for k, v in var.secrets : { name = k, valueFrom = v }]
    healthCheck = {
      command  = ["CMD-SHELL", "wget -q -O /dev/null http://127.0.0.1:${local.port.admin}/readyz || exit 1"]
      interval = 10
      timeout  = 3
      retries  = 3
    }
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.this.name
        awslogs-region        = data.aws_region.current.region
        awslogs-stream-prefix = var.component
      }
    }
  }])
}

resource "aws_ecs_service" "this" {
  name            = var.name
  cluster         = coalesce(var.cluster_arn, try(aws_ecs_cluster.this[0].arn, null))
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"
  tags            = var.tags

  # Replace one task at a time, never below the desired count.
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 150

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [aws_security_group.this.id]
    assign_public_ip = var.assign_public_ip
  }

  dynamic "load_balancer" {
    for_each = var.target_group_arn == null ? [] : [var.target_group_arn]
    content {
      target_group_arn = load_balancer.value
      container_name   = var.component
      container_port   = local.port.main
    }
  }

  lifecycle { ignore_changes = [desired_count] }
}
