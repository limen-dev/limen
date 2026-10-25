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

variable "oidc" {
  description = "Your identity provider's issuer URL and the client id registered for Limen."
  type = object({
    issuer    = string
    client_id = string
  })
}

variable "core_vpc" {
  description = "The VPC created for the database, control planes and proxies."
  type = object({
    cidr               = optional(string, "10.40.0.0/16")
    azs                = optional(list(string), ["eu-west-1a", "eu-west-1b", "eu-west-1c"])
    private_subnets    = optional(list(string), ["10.40.0.0/20", "10.40.16.0/20", "10.40.32.0/20"])
    public_subnets     = optional(list(string), ["10.40.100.0/24", "10.40.101.0/24", "10.40.102.0/24"])
    single_nat_gateway = optional(bool, true)
  })
  default = {}
}

variable "database" {
  description = "PostgreSQL settings (see modules/foundation)."
  type        = any
  default     = {}
}

variable "control_planes" {
  description = "Control plane services on ECS, all in the core VPC. Raise desired_count to scale, or add entries."
  type = map(object({
    desired_count = optional(number, 3)
  }))
  default = { core = {} }
}

variable "proxies" {
  description = "Proxy services on ECS in the core VPC, each behind its own public Network Load Balancer. dns_name is the public name you will point at the load balancer."
  type = map(object({
    desired_count = optional(number, 3)
    dns_name      = string
    client_cidrs  = optional(list(string), ["0.0.0.0/0"])
  }))
}

variable "workers" {
  description = "Worker groups on EC2, one per network they reach. Each lives in an existing VPC (the one of the hosts and databases it connects to) and dials the proxy named by \"proxy\" (a key of var.proxies)."
  type = map(object({
    vpc_id           = string
    subnet_ids       = list(string)
    proxy            = string
    desired_capacity = optional(number, 3)
    max_sessions     = optional(number, 200)
  }))

  validation {
    condition     = alltrue([for w in var.workers : contains(keys(var.proxies), w.proxy)])
    error_message = "Each worker's proxy must be a key of var.proxies."
  }
}
