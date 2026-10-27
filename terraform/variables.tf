variable "aws_region" {
  description = "AWS Primary Deployment Region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment Environment (prod, staging, dev)"
  type        = string
  default     = "prod"
}

variable "owner" {
  description = "Resource Owner and Maintainer"
  type        = string
  default     = "Kosha Gohil"
}

variable "origin_domain_name" {
  description = "Upstream Origin Domain (Application Load Balancer or API Gateway)"
  type        = string
  default     = "origin-api.secure-mesh.example.com"
}

variable "rate_limit_threshold" {
  description = "Maximum allowable requests per 5-minute evaluation window per IP"
  type        = number
  default     = 300
}

variable "initial_blocked_ips" {
  description = "Seed list of CIDRs for automated WAF IP blocklist"
  type        = list(string)
  default     = ["198.51.100.250/32"]
}
