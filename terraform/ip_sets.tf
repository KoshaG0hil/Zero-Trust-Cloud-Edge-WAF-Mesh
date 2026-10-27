# Dynamic WAF IP Set for Automated Edge Threat Mitigation
resource "aws_wafv2_ip_set" "automated_blocklist" {
  provider           = aws.us_east_1
  name               = "${local.name_prefix}-banned-ips"
  description        = "Dynamic IP blocklist populated automatically by Zero-Trust Edge Security Engine"
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV4"
  addresses          = var.initial_blocked_ips

  tags = {
    Name = "${local.name_prefix}-banned-ips"
  }
}
