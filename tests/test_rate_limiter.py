"""Tests for sliding window rate limiting."""

from src.core.config import RequestContext
from src.inspectors.rate_limiter import SlidingWindowRateLimiter


def test_standard_traffic_within_limit():
    limiter = SlidingWindowRateLimiter(window_seconds=60, default_limit=10)
    context = RequestContext(client_ip="198.51.100.10", method="GET", uri="/articles")

    for _ in range(5):
        findings = limiter.inspect(context)
        assert len(findings) == 0


def test_burst_traffic_triggers_rate_limit():
    limiter = SlidingWindowRateLimiter(window_seconds=60, default_limit=5)
    context = RequestContext(client_ip="198.51.100.20", method="GET", uri="/articles")

    # Send 5 requests (within limit)
    for _ in range(5):
        limiter.inspect(context)

    # 6th request triggers rate limit
    findings = limiter.inspect(context)
    assert len(findings) == 1
    assert findings[0].rule_id == "RATE_LIMIT_EXCEEDED"


def test_auth_endpoint_has_stricter_limit():
    limiter = SlidingWindowRateLimiter(window_seconds=60, default_limit=50, auth_limit=3)
    context = RequestContext(client_ip="198.51.100.30", method="POST", uri="/api/v1/auth/login")

    for _ in range(3):
        limiter.inspect(context)

    # 4th login attempt triggers limit
    findings = limiter.inspect(context)
    assert len(findings) == 1
    assert findings[0].rule_id == "RATE_LIMIT_EXCEEDED"
