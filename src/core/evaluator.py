"""Zero-Trust Edge Evaluator Engine orchestrating multi-vector request scoring."""

import time
from typing import List, Optional
from .config import EvaluationDecision, MitigationAction, RequestContext, ZeroTrustConfig
from ..inspectors.bot_detector import BotDetector
from ..inspectors.geo_inspector import GeoRiskInspector
from ..inspectors.rate_limiter import SlidingWindowRateLimiter
from ..inspectors.sqli_xss_inspector import InspectionFinding, SqliXssInspector


class ZeroTrustEdgeEvaluator:
    """Orchestrates comprehensive multi-layer security inspection at CloudFront/WAF edge."""

    def __init__(self, config: Optional[ZeroTrustConfig] = None):
        self.config = config or ZeroTrustConfig()
        self.sqli_xss = SqliXssInspector()
        self.bot_detector = BotDetector()
        self.rate_limiter = SlidingWindowRateLimiter()
        self.geo_inspector = GeoRiskInspector(sanctioned_countries=set(self.config.sanctioned_countries))

    def evaluate(self, context: RequestContext) -> EvaluationDecision:
        """Evaluates an incoming request and decides mitigation action in under 2ms."""
        start_time = time.perf_counter()
        all_findings: List[InspectionFinding] = []

        # 1. Payload & OWASP Inspection
        all_findings.extend(self.sqli_xss.inspect(context))

        # 2. Bot & Scraper Inspection
        all_findings.extend(self.bot_detector.inspect(context))

        # 3. Rate Limiting Inspection
        all_findings.extend(self.rate_limiter.inspect(context))

        # 4. Geo & ASN Inspection
        all_findings.extend(self.geo_inspector.inspect(context))

        # Calculate Combined Risk Score (capped at 100)
        if not all_findings:
            risk_score = 0
            action = MitigationAction.ALLOW
            reasons = ["Zero threats detected; clean edge request"]
            matched_rules = []
        else:
            # Highest individual threat dominates base score + additive incremental penalty
            base_score = max(f.risk_score for f in all_findings)
            additive_penalty = min(20, (len(all_findings) - 1) * 10)
            risk_score = min(100, base_score + additive_penalty)

            # Determine Mitigation Action
            if risk_score >= 86:
                action = MitigationAction.BLOCK
            elif risk_score >= 66:
                action = MitigationAction.DIVERT_HONEYPOT
            elif risk_score >= 26:
                action = MitigationAction.CHALLENGE_CAPTCHA
            else:
                action = MitigationAction.ALLOW

            matched_rules = [f.rule_id for f in all_findings]
            reasons = [f"[{f.attack_type}] {f.matched_pattern} on {f.matched_target}" for f in all_findings]

        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 3)

        return EvaluationDecision(
            request_id=context.request_id,
            client_ip=context.client_ip,
            risk_score=risk_score,
            action=action,
            matched_rules=matched_rules,
            reasons=reasons,
            execution_time_ms=elapsed_ms,
        )
