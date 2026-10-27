"""Bot Detection & Scraper Identification Engine."""

import re
from typing import List
from ..core.config import RequestContext
from .sqli_xss_inspector import InspectionFinding


class BotDetector:
    """Classifies user agents, headless browser fingerprints, and automated scrapers."""

    BAD_BOT_PATTERNS = [
        re.compile(r"(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wpscan|scrapy)", re.IGNORECASE),
        re.compile(r"python-requests/(?!\d)", re.IGNORECASE),
        re.compile(r"^curl/(?:7\.[0-5]|6\.)", re.IGNORECASE),
        re.compile(r"(HeadlessChrome|PhantomJS|Puppeteer|Playwright)", re.IGNORECASE),
    ]

    VERIFIED_BOT_PATTERNS = [
        (re.compile(r"Googlebot", re.IGNORECASE), [15169]),
        (re.compile(r"bingbot", re.IGNORECASE), [8075]),
    ]

    HONEYPOT_PATHS = {
        "/api/v1/internal/admin_debug",
        "/.git/config",
        "/wp-login.php",
        "/actuator/health",
        "/aws-credentials",
        "/phpmyadmin",
    }

    def inspect(self, context: RequestContext) -> List[InspectionFinding]:
        findings: List[InspectionFinding] = []
        user_agent = context.get_header("User-Agent", "")

        # 1. Check if it pretends to be a verified search bot, but ASN does not match (Spoofed Bot)
        for pattern, valid_asns in self.VERIFIED_BOT_PATTERNS:
            if pattern.search(user_agent):
                if context.asn not in valid_asns:
                    findings.append(
                        InspectionFinding(
                            rule_id="SPOOFED_SEARCH_BOT",
                            attack_type="BOT",
                            risk_score=90,
                            matched_target="User-Agent",
                            matched_pattern=f"Spoofed {pattern.pattern} from rogue ASN {context.asn}",
                        )
                    )
                return findings  # If legit verified bot, return early with no findings

        # 2. Check for known malicious scrapers and offensive security scanners
        for pattern in self.BAD_BOT_PATTERNS:
            match = pattern.search(user_agent)
            if match:
                findings.append(
                    InspectionFinding(
                        rule_id="MALICIOUS_BOT_USER_AGENT",
                        attack_type="BOT",
                        risk_score=75,
                        matched_target="User-Agent",
                        matched_pattern=match.group(0),
                    )
                )

        # 3. Check for empty or missing User-Agent
        if not user_agent or len(user_agent.strip()) < 4:
            findings.append(
                InspectionFinding(
                    rule_id="ANOMALOUS_EMPTY_USER_AGENT",
                    attack_type="BOT",
                    risk_score=40,
                    matched_target="User-Agent",
                    matched_pattern="<empty>",
                )
            )

        # 4. Check for Honeypot probing
        if context.uri.lower() in self.HONEYPOT_PATHS:
            findings.append(
                InspectionFinding(
                    rule_id="HONEYPOT_PROBE_ACCESSED",
                    attack_type="HONEYPOT",
                    risk_score=100,
                    matched_target="URI",
                    matched_pattern=context.uri,
                )
            )

        return findings
