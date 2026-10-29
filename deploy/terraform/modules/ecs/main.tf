module "cluster" {
  source  = "terraform-aws-modules/ecs/aws//modules/cluster"
  version = "~> 7.6"

  name = var.name
  tags = var.tags
}

module "service" {
  source  = "terraform-aws-modules/ecs/aws//modules/service"
  version = "~> 7.6"

  for_each = local.services

  name        = "${var.name}-${each.key}"
  cluster_arn = module.cluster.arn

  cpu    = each.value.cpu
  memory = each.value.memory

  desired_count    = each.value.desired_count
  assign_public_ip = each.value.assign_public_ip
  subnet_ids       = each.value.subnet_ids

  # Replace one task at a time, never below the desired count.
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 150

  container_definitions = merge(
    {
      (each.value.component) = {
        image       = each.value.image
        essential   = true
        stopTimeout = each.value.stop_timeout

        portMappings = concat(
          each.value.port.main == null ? [] : [{ name = "main", containerPort = each.value.port.main, protocol = "tcp" }],
          [{ name = "admin", containerPort = each.value.port.admin, protocol = "tcp" }],
        )
        environment = [for k, v in each.value.environment : { name = k, value = v }]
        secrets     = [for k, v in each.value.secrets : { name = k, valueFrom = v }]

        mountPoints = concat(
          each.value.publishes ? [{ sourceVolume = "ca-public", containerPath = local.ca_export_dir }] : [],
          each.value.consumes ? [{ sourceVolume = "ca-trust", containerPath = local.ca_trust_dir, readOnly = true }] : [],
        )
        dependsOn = each.value.consumes ? [{ containerName = "ca-writer", condition = "SUCCESS" }] : []

        # The images are distroless: no shell, so no container health check.
        # The load balancer's health check covers proxies and control planes.
        cloudwatch_log_group_name              = "/limen/${var.name}/${each.key}"
        cloudwatch_log_group_retention_in_days = var.log_retention_days
      }
    },
    each.value.publishes ? {
      ca-publisher = {
        image      = var.helper_images.aws_cli
        essential  = false
        entryPoint = ["/bin/sh", "-c"]
        command    = [local.ca_publisher_script]
        environment = [
          { name = "CA_SECRET_ID", value = var.internal_ca.secret_arn },
        ]
        mountPoints = [{ sourceVolume = "ca-public", containerPath = local.ca_export_dir, readOnly = true }]

        cloudwatch_log_group_name              = "/limen/${var.name}/${each.key}"
        cloudwatch_log_group_retention_in_days = var.log_retention_days
      }
    } : {},
    each.value.consumes ? {
      ca-writer = {
        image       = var.helper_images.shell
        essential   = false
        entryPoint  = ["/bin/sh", "-c"]
        command     = [local.ca_writer_script]
        secrets     = [{ name = "CA_PEM", valueFrom = var.internal_ca.secret_arn }]
        mountPoints = [{ sourceVolume = "ca-trust", containerPath = local.ca_trust_dir }]

        cloudwatch_log_group_name              = "/limen/${var.name}/${each.key}"
        cloudwatch_log_group_retention_in_days = var.log_retention_days
      }
    } : {},
  )

  # Task-level volumes shared by the containers of one task.
  volume = merge(
    each.value.publishes ? { ca-public = {} } : {},
    each.value.consumes ? { ca-trust = {} } : {},
  )

  load_balancer = each.value.target_group_arn == null ? {} : {
    service = {
      target_group_arn = each.value.target_group_arn
      container_name   = each.value.component
      container_port   = each.value.port.main
    }
  }

  # The task execution role reads the secrets; values never enter the task
  # definition or the state.
  task_exec_secret_arns   = values(each.value.secrets)
  tasks_iam_role_policies = each.value.task_role_policy_arns
  tasks_iam_role_statements = each.value.publishes ? [{
    actions   = ["secretsmanager:PutSecretValue"]
    resources = [var.internal_ca.secret_arn]
  }] : []

  # Every component dials out (control plane to its database and KMS, proxy to
  # the control plane, worker to the proxy); inbound is only the service port.
  security_group_ingress_rules = {
    for k, rule in local.ingress_rules[each.key] : k => merge(rule, {
      from_port   = each.value.port.main
      to_port     = each.value.port.main
      ip_protocol = "tcp"
    })
  }
  security_group_egress_rules = {
    all = { ip_protocol = "-1", cidr_ipv4 = "0.0.0.0/0" }
  }
  vpc_id = each.value.vpc_id

  enable_autoscaling       = each.value.min_count != null
  autoscaling_min_capacity = coalesce(each.value.min_count, each.value.desired_count)
  autoscaling_max_capacity = coalesce(each.value.max_count, each.value.desired_count)
  autoscaling_policies = {
    cpu = {
      policy_type = "TargetTrackingScaling"
      target_tracking_scaling_policy_configuration = {
        target_value = each.value.cpu_target_percent
        predefined_metric_specification = {
          predefined_metric_type = "ECSServiceAverageCPUUtilization"
        }
      }
    }
  }

  tags = var.tags
}
