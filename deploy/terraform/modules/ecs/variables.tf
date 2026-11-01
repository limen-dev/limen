variable "name" {
  description = "Prefix for the cluster and every service, e.g. \"limen-prod\"."
  type        = string
}

variable "services" {
  description = <<-EOT
    Limen services to run, keyed by a short name that becomes part of the
    resource names: { proxy-a = { component = "proxy", ... }, worker-a = {...} }.
    Add as many entries as you need of any component; each has its own VPC,
    subnets, size and settings, so proxies and workers can live in different VPCs.
    "environment" holds plain LIMEN_* settings; "secrets" maps a variable name to
    a Secrets Manager or SSM parameter ARN, read at task start.
  EOT
  type = map(object({
    component                  = string
    image                      = string
    vpc_id                     = string
    subnet_ids                 = list(string)
    assign_public_ip           = optional(bool, false)
    desired_count              = optional(number, 3)
    min_count                  = optional(number)
    max_count                  = optional(number)
    cpu_target_percent         = optional(number, 60)
    cpu                        = optional(number, 512)
    memory                     = optional(number, 1024)
    stop_timeout               = optional(number, 60)
    environment                = optional(map(string), {})
    secrets                    = optional(map(string), {})
    ingress_cidrs              = optional(list(string), [])
    ingress_security_group_ids = optional(list(string), [])
    admin_ingress_cidrs        = optional(list(string), [])
    target_group_arn           = optional(string)
    task_role_policy_arns      = optional(map(string), {})
  }))

  validation {
    condition     = alltrue([for s in var.services : contains(["control-plane", "proxy", "worker"], s.component)])
    error_message = "component must be control-plane, proxy or worker."
  }
  validation {
    condition     = alltrue([for s in var.services : s.stop_timeout >= 2 && s.stop_timeout <= 120])
    error_message = "Fargate stop_timeout must be 2-120 seconds (set Limen's drain timeout below it)."
  }
  validation {
    condition     = alltrue([for s in var.services : (s.min_count == null) == (s.max_count == null)])
    error_message = "Set min_count and max_count together to enable autoscaling."
  }
  validation {
    condition     = alltrue([for s in var.services : s.target_group_arn == null || s.component != "worker"])
    error_message = "Workers accept no inbound traffic; target_group_arn applies to proxy and control-plane only."
  }
}

variable "internal_ca" {
  description = <<-EOT
    Pass { secret_arn = ... }: the Secrets Manager secret for the Limen internal CA certificate (the
    foundation module creates it). Control plane tasks run a publisher sidecar
    that writes the certificate they export into it; proxy and worker tasks
    wait for it and write it to the file LIMEN_CA_FILE points at. Needed when
    any service is a proxy or worker.
  EOT
  type = object({
    secret_arn = string
  })
  default = null
}

variable "helper_images" {
  description = "Images of the two helper containers: the CA publisher (needs a shell and the AWS CLI) and the CA writer (needs a shell)."
  type = object({
    aws_cli = optional(string, "public.ecr.aws/aws-cli/aws-cli:2.38.0")
    shell   = optional(string, "public.ecr.aws/docker/library/busybox:1.37.0")
  })
  default = {}
}

variable "log_retention_days" {
  description = "Retention of each service's CloudWatch log group."
  type        = number
  default     = 90
}

variable "tags" {
  description = "Tags added to every resource."
  type        = map(string)
  default     = {}
}
