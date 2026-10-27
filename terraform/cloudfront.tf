# Strict Edge Security Headers Policy
resource "aws_cloudfront_response_headers_policy" "strict_security_headers" {
  name    = "${local.name_prefix}-strict-headers"
  comment = "Enforces Zero-Trust HSTS, CSP, and framing restrictions at CDN edge"

  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      preload                    = true
      override                   = true
    }

    content_type_options {
      override = true
    }

    frame_options {
      frame_option = "DENY"
      override     = true
    }

    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }

    content_security_policy {
      content_security_policy = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none';"
      override                = true
    }
  }
}

# Edge CloudFront CDN Distribution
resource "aws_cloudfront_distribution" "edge_cdn" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "Zero-Trust Protected Edge Distribution"
  default_root_object = "index.html"
  web_acl_id         = aws_wafv2_web_acl.edge_perimeter.arn

  origin {
    domain_name = var.origin_domain_name
    origin_id   = "PrimarySecureOrigin"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "PrimarySecureOrigin"

    viewer_protocol_policy     = "redirect-to-https"
    response_headers_policy_id = aws_cloudfront_response_headers_policy.strict_security_headers.id
    min_ttl                    = 0
    default_ttl                = 300
    max_ttl                    = 86400

    forwarded_values {
      query_string = true
      headers      = ["Host", "CloudFront-Viewer-Country", "CloudFront-Viewer-ASN"]

      cookies {
        forward = "none"
      }
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
    minimum_protocol_version       = "TLSv1.2_2021"
  }

  tags = {
    Name = "${local.name_prefix}-cdn"
  }
}
