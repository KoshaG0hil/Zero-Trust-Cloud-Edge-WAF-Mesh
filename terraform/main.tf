terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "Zero-Trust-Cloud-Edge-WAF-Mesh"
      Environment = var.environment
      ManagedBy   = "Terraform"
      Owner       = var.owner
      Compliance  = "Zero-Trust-Perimeter"
    }
  }
}

# Provider alias for CloudFront and Global WAFv2 (Must be us-east-1)
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = {
      Project     = "Zero-Trust-Cloud-Edge-WAF-Mesh"
      Environment = var.environment
      ManagedBy   = "Terraform"
      Owner       = var.owner
    }
  }
}

locals {
  name_prefix = "zero-trust-waf-${var.environment}"
}
