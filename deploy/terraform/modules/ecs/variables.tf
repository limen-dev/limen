variable "name" {
  description = "Prefix for every resource name, e.g. \"limen-prod-proxy\"."
  type        = string
}

variable "component" {
  description = "Which Limen component this deployment runs."
  type        = string
  validation {
    condition     = contains(["control-plane", "proxy", "worker"], var.component)
    error_message = "component must be control-plane, proxy or worker."
  }
}

variable "image" {
  description = "Full image reference, e.g. \"ghcr.io/your-org/limen-proxy:0.1.0\"."
  type        = string
}

variable "vpc_id" {
  description = "VPC of this component. Each component can use its own VPC."
  type        = string
}

variable "subnet_ids" {
  description = "Subnets for the tasks."
  type        = list(string)
}

variable "assign_public_ip" {
  description = "Give tasks a public IP (needed in public subnets without a NAT gateway)."
  type        = bool
  default     = false
}

variable "cluster_arn" {
  description = "Existing ECS cluster. A new one is created when null."
  type        = string
  default     = null
}

variable "desired_count" {
  type    = number
  default = 3
}

variable "cpu" {
  description = "Fargate task CPU units."
  type        = number
  default     = 512
}

variable "memory" {
  description = "Fargate task memory in MiB."
  type        = number
  default     = 1024
}

variable "environment" {
  description = "Plain environment variables (LIMEN_*), merged over the component defaults."
  type        = map(string)
  default     = {}
}

variable "secrets" {
  description = "Environment variables read from Secrets Manager or SSM at task start: name => ARN. Values never appear in the task definition."
  type        = map(string)
  default     = {}
}

variable "ingress_cidrs" {
  description = "CIDRs allowed to reach the public port (proxy) or the gRPC port (control plane). Workers accept no inbound traffic."
  type        = list(string)
  default     = []
}

variable "ingress_security_group_ids" {
  description = "Security groups allowed to reach the same port, e.g. a load balancer's."
  type        = list(string)
  default     = []
}

variable "target_group_arn" {
  description = "Load balancer target group for the public port (proxy only)."
  type        = string
  default     = null
}

variable "task_role_policy_arns" {
  description = "Managed policies for the task role, e.g. KMS and S3 access for the control plane."
  type        = list(string)
  default     = []
}

variable "stop_timeout" {
  description = "Seconds ECS waits after SIGTERM. Fargate allows at most 120; set Limen's drain timeout below it."
  type        = number
  default     = 60
  validation {
    condition     = var.stop_timeout >= 2 && var.stop_timeout <= 120
    error_message = "Fargate stop_timeout must be 2-120 seconds."
  }
}

variable "log_retention_days" {
  type    = number
  default = 90
}

variable "tags" {
  type    = map(string)
  default = {}
}
