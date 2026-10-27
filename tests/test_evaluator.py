"""Tests for Zero-Trust edge evaluation decisions and action thresholds."""

from src.core.config import MitigationAction, RequestContext
from src.core.evaluator import ZeroTrustEdgeEvaluator


def test_clean_request_allowed():
    evaluator = ZeroTrustEdgeEvaluator()
    context = RequestContext(
        client_ip="198.51.100.1",
        method="GET",
        uri="/home",
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0"},
        country_code="US",
        asn=15169,
    )
    decision = evaluator.evaluate(context)
    assert decision.action == MitigationAction.ALLOW
    assert decision.risk_score == 0
    assert decision.execution_time_ms >= 0


def test_sqli_attack_blocked():
    evaluator = ZeroTrustEdgeEvaluator()
    context = RequestContext(
        client_ip="198.51.100.2",
        method="GET",
        uri="/products",
        query_string="id=1' or 1=1--",
        country_code="US",
    )
    decision = evaluator.evaluate(context)
    assert decision.action == MitigationAction.BLOCK
    assert decision.risk_score >= 86
    assert "SQLI_TAUTOLOGY" in decision.matched_rules


def test_honeypot_probe_diverted_or_blocked():
    evaluator = ZeroTrustEdgeEvaluator()
    context = RequestContext(
        client_ip="198.51.100.3",
        method="GET",
        uri="/wp-login.php",
        country_code="US",
    )
    decision = evaluator.evaluate(context)
    # Honeypot score is 100, which triggers hard block or honeypot diversion
    assert decision.action in (MitigationAction.BLOCK, MitigationAction.DIVERT_HONEYPOT)
    assert decision.risk_score >= 86


def test_suspicious_bot_leads_to_challenge_or_honeypot():
    evaluator = ZeroTrustEdgeEvaluator()
    context = RequestContext(
        client_ip="198.51.100.4",
        method="GET",
        uri="/pricing",
        headers={"User-Agent": "python-requests/2.31.0"},
        country_code="NL",
        asn=9009,
    )
    decision = evaluator.evaluate(context)
    assert decision.action in (
        MitigationAction.CHALLENGE_CAPTCHA,
        MitigationAction.DIVERT_HONEYPOT,
        MitigationAction.BLOCK,
    )
    assert decision.risk_score > 25
