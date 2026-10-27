# CloudWatch Alarms for Edge Threat Telemetry
resource "aws_cloudwatch_metric_alarm" "high_waf_blocked_requests" {
  alarm_name          = "${local.name_prefix}-HighBlockedRequests"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = 300
  statistic           = "Sum"
  threshold           = 50
  alarm_description   = "Triggered when AWS WAF blocks more than 50 malicious requests in 5 minutes"

  dimensions = {
    WebACL = aws_wafv2_web_acl.edge_perimeter.name
    Region = "us-east-1"
    Rule   = "ALL"
  }

  tags = {
    Name = "${local.name_prefix}-high-blocked-alarm"
  }
}

resource "aws_cloudwatch_metric_alarm" "cloudfront_error_rate" {
  alarm_name          = "${local.name_prefix}-CloudFront4xxErrorSpike"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "4xxErrorRate"
  namespace           = "AWS/CloudFront"
  period              = 300
  statistic           = "Average"
  threshold           = 15.0
  alarm_description   = "Triggers when CloudFront 4xx error rate exceeds 15% across edge locations"

  dimensions = {
    DistributionId = aws_cloudfront_distribution.edge_cdn.id
  }

  tags = {
    Name = "${local.name_prefix}-cf-error-alarm"
  }
}
