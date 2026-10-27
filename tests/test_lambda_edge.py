"""Tests for AWS Lambda@Edge viewer-request event handler."""

from src.lambda_edge_handler import lambda_handler


def test_lambda_edge_blocks_sqli_request():
    event = {
        "Records": [
            {
                "cf": {
                    "config": {"requestId": "test-req-001"},
                    "request": {
                        "clientIp": "203.0.113.10",
                        "method": "GET",
                        "uri": "/search",
                        "querystring": "q=' UNION SELECT 1,2,3--",
                        "headers": {
                            "user-agent": [{"key": "User-Agent", "value": "Mozilla/5.0"}],
                            "cloudfront-viewer-country": [{"key": "CloudFront-Viewer-Country", "value": "US"}],
                        },
                    },
                }
            }
        ]
    }
    response = lambda_handler(event, None)
    assert response["status"] == "403"
    assert "AccessDeniedByEdgePerimeterPolicy" in response["body"]


def test_lambda_edge_allows_clean_request():
    event = {
        "Records": [
            {
                "cf": {
                    "config": {"requestId": "test-req-002"},
                    "request": {
                        "clientIp": "198.51.100.5",
                        "method": "GET",
                        "uri": "/products",
                        "querystring": "category=electronics",
                        "headers": {
                            "user-agent": [{"key": "User-Agent", "value": "Mozilla/5.0"}],
                            "cloudfront-viewer-country": [{"key": "CloudFront-Viewer-Country", "value": "US"}],
                        },
                    },
                }
            }
        ]
    }
    response = lambda_handler(event, None)
    # Allowed requests pass the request object through with injected headers
    assert "headers" in response
    assert "x-zero-trust-risk-score" in response["headers"]
    assert response["headers"]["x-zero-trust-action"][0]["value"] == "ALLOW"
