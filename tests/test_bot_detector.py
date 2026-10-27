"""Tests for bot fingerprinting and honeypot detection."""

from src.core.config import RequestContext
from src.inspectors.bot_detector import BotDetector


def test_clean_browser_agent():
    detector = BotDetector()
    context = RequestContext(
        client_ip="1.2.3.4",
        method="GET",
        uri="/catalog",
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
    )
    findings = detector.inspect(context)
    assert len(findings) == 0


def test_detects_malicious_security_scanners():
    detector = BotDetector()
    for bad_ua in ["sqlmap/1.6", "nikto/2.1.6", "masscan/1.0", "wpscan v3.8"]:
        context = RequestContext(
            client_ip="1.2.3.4",
            method="GET",
            uri="/",
            headers={"User-Agent": bad_ua},
        )
        findings = detector.inspect(context)
        assert len(findings) > 0
        assert findings[0].rule_id == "MALICIOUS_BOT_USER_AGENT"


def test_detects_spoofed_search_bot():
    detector = BotDetector()
    # Googlebot claims to be Googlebot, but comes from rogue ASN 99999 instead of 15169
    context = RequestContext(
        client_ip="1.2.3.4",
        method="GET",
        uri="/",
        headers={"User-Agent": "Googlebot/2.1 (+http://www.google.com/bot.html)"},
        asn=99999,
    )
    findings = detector.inspect(context)
    assert len(findings) > 0
    assert findings[0].rule_id == "SPOOFED_SEARCH_BOT"


def test_detects_honeypot_probe():
    detector = BotDetector()
    context = RequestContext(
        client_ip="1.2.3.4",
        method="GET",
        uri="/.git/config",
        headers={"User-Agent": "Mozilla/5.0"},
    )
    findings = detector.inspect(context)
    assert any(f.rule_id == "HONEYPOT_PROBE_ACCESSED" for f in findings)
