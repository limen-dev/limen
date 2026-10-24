variable "region" {
  type    = string
  default = "eu-west-1"
}

variable "name" {
  description = "Prefix for every resource."
  type        = string
  default     = "limen-prod"
}

variable "image_registry" {
  description = "Registry and path of the Limen images, e.g. \"ghcr.io/your-org\"."
  type        = string
}

variable "image_tag" {
  type = string
}

variable "oidc_issuer" {
  type = string
}

variable "oidc_client_id" {
  type = string
}

variable "ca_key_arns" {
  description = "KMS keys behind LIMEN_KMS_*_KEY."
  type = object({
    internal_ca = string
    user_ca     = string
    ssh_user_ca = string
    ssh_host_ca = string
  })
}

variable "database_url_secret_arn" {
  description = "Secrets Manager secret holding the PostgreSQL URL."
  type        = string
}

variable "control_plane_addr" {
  description = "host:port the proxies dial, e.g. an internal NLB or Cloud Map name for the control plane's port 3080."
  type        = string
}

variable "control_planes" {
  description = "Control plane services on ECS. Add entries to run more replicas groups, each in its own VPC."
  type = map(object({
    vpc_id        = string
    subnet_ids    = list(string)
    desired_count = optional(number, 3)
  }))
}

variable "proxies" {
  description = "Proxy services on ECS, each behind its own load balancer target group and public name."
  type = map(object({
    vpc_id                = string
    subnet_ids            = list(string)
    desired_count         = optional(number, 3)
    dns_name              = string
    target_group_arn      = string
    join_token_secret_arn = string
    client_cidrs          = optional(list(string), ["0.0.0.0/0"])
  }))
}

variable "workers" {
  description = "Worker groups on EC2. Each dials the proxy named by \"proxy\" (a key of var.proxies); put each group in the VPC of the hosts and databases it reaches."
  type = map(object({
    vpc_id                = string
    subnet_ids            = list(string)
    proxy                 = string
    desired_capacity      = optional(number, 3)
    max_sessions          = optional(number, 200)
    join_token_secret_arn = string
  }))

  validation {
    condition     = length(var.workers) > 0
    error_message = "Define at least one worker group."
  }
}
