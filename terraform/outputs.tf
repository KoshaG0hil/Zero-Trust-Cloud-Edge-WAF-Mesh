output "web_acl_arn" {
  description = "ARN of the Edge WAFv2 WebACL"
  value       = aws_wafv2_web_acl.edge_perimeter.arn
}

output "web_acl_id" {
  description = "ID of the Edge WAFv2 WebACL"
  value       = aws_wafv2_web_acl.edge_perimeter.id
}

output "ip_set_arn" {
  description = "ARN of the Dynamic Automated IP Blocklist"
  value       = aws_wafv2_ip_set.automated_blocklist.arn
}

output "cloudfront_distribution_id" {
  description = "ID of the CloudFront Distribution"
  value       = aws_cloudfront_distribution.edge_cdn.id
}

output "cloudfront_domain_name" {
  description = "Edge Domain Name for the CloudFront CDN"
  value       = aws_cloudfront_distribution.edge_cdn.domain_name
}

output "lambda_edge_role_arn" {
  description = "Execution Role ARN for Lambda@Edge Inspection"
  value       = aws_iam_role.lambda_edge_exec.arn
}
