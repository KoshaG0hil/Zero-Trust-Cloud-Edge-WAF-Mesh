# Enterprise AWS WAFv2 WebACL for Edge CloudFront Distribution
resource "aws_wafv2_web_acl" "edge_perimeter" {
  provider    = aws.us_east_1
  name        = "${local.name_prefix}-web-acl"
  description = "Multi-layer Zero-Trust perimeter WebACL with Bot Control and Threat Intel"
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  # Priority 1: Automated IP Blocklist (Immediate Drop)
  rule {
    name     = "EnforceDynamicBannedIPs"
    priority = 1

    action {
      block {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.automated_blocklist.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "WAF_EnforceDynamicBannedIPs"
      sampled_requests_enabled   = true
    }
  }

  # Priority 2: Custom Rate Limiting per IP
  rule {
    name     = "AdaptiveRateLimitPerIP"
    priority = 2

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.rate_limit_threshold
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "WAF_AdaptiveRateLimitPerIP"
      sampled_requests_enabled   = true
    }
  }

  # Priority 3: AWS Managed IP Reputation List
  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "WAF_AmazonIpReputationList"
      sampled_requests_enabled   = true
    }
  }

  # Priority 4: AWS Managed OWASP Core Rule Set
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 4

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "WAF_CommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # Priority 5: AWS Managed SQL Injection Protections
  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 5

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "WAF_SQLiRuleSet"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name_prefix}-WebAclMetrics"
    sampled_requests_enabled   = true
  }

  tags = {
    Name = "${local.name_prefix}-web-acl"
  }
}
