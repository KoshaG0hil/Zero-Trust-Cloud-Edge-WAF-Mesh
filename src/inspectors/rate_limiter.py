"""Sliding Window Token Bucket Rate Limiter for Edge DDoS and Burst Protection."""

from collections import defaultdict
import time
from typing import Dict, List, Optional
from ..core.config import RequestContext
from .sqli_xss_inspector import InspectionFinding


class SlidingWindowRateLimiter:
    """Simulates an edge sliding window rate limit counter (like AWS WAF Rate-Based rules)."""

    def __init__(
        self,
        window_seconds: int = 60,
        default_limit: int = 100,
        auth_limit: int = 10,
    ):
        self.window_seconds = window_seconds
        self.default_limit = default_limit
        self.auth_limit = auth_limit
        # ip -> list of timestamps
        self.ip_history: Dict[str, List[float]] = defaultdict(list)

    def reset(self):
        """Clears all in-memory rate tracking histories."""
        self.ip_history.clear()

    def record_request(self, ip: str, timestamp: Optional[float] = None) -> int:
        """Records an incoming request timestamp and cleans out entries older than window."""
        now = timestamp if timestamp is not None else time.time()
        cutoff = now - self.window_seconds

        history = self.ip_history[ip]
        # Retain only timestamps within sliding window
        self.ip_history[ip] = [ts for ts in history if ts >= cutoff] + [now]
        return len(self.ip_history[ip])

    def inspect(self, context: RequestContext, current_time: Optional[float] = None) -> List[InspectionFinding]:
        findings: List[InspectionFinding] = []
        is_auth = any(keyword in context.uri.lower() for keyword in ["/login", "/auth", "/signin", "/token"])
        threshold = self.auth_limit if is_auth else self.default_limit

        count = self.record_request(context.client_ip, timestamp=current_time)

        if count > threshold:
            findings.append(
                InspectionFinding(
                    rule_id="RATE_LIMIT_EXCEEDED",
                    attack_type="DDOS_VELOCITY",
                    risk_score=70,
                    matched_target="ClientIP",
                    matched_pattern=f"{count} requests in {self.window_seconds}s (limit: {threshold})",
                )
            )

        return findings
