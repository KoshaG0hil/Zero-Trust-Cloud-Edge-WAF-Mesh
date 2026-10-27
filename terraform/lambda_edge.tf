# IAM Execution Role for Lambda@Edge Viewer-Request Inspection
resource "aws_iam_role" "lambda_edge_exec" {
  name = "${local.name_prefix}-edge-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = [
            "lambda.amazonaws.com",
            "edgelambda.amazonaws.com"
          ]
        }
      }
    ]
  })

  tags = {
    Name = "${local.name_prefix}-edge-lambda-role"
  }
}

resource "aws_iam_role_policy" "lambda_edge_policy" {
  name = "${local.name_prefix}-edge-lambda-policy"
  role = aws_iam_role.lambda_edge_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "wafv2:GetIPSet",
          "wafv2:UpdateIPSet"
        ]
        Resource = aws_wafv2_ip_set.automated_blocklist.arn
      }
    ]
  })
}
