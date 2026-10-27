"""Inspector for SQL Injection, Cross-Site Scripting, Path Traversal, and SSRF attacks."""

from dataclasses import dataclass
import re
from typing import List
from ..core.config import RequestContext


@dataclass
class InspectionFinding:
    rule_id: str
    attack_type: str
    risk_score: int
    matched_target: str
    matched_pattern: str


class SqliXssInspector:
    """Detects OWASP Top 10 injection vectors in edge requests."""

    SQLI_PATTERNS = [
        (re.compile(r"('|\")\s*(or|and)\s*('|\")?\d*('|\")?\s*=\s*('|\")?\d*", re.IGNORECASE), "SQLI_TAUTOLOGY", 90),
        (re.compile(r"union(\s+all)?\s+select", re.IGNORECASE), "SQLI_UNION_SELECT", 95),
        (re.compile(r"(sleep|benchmark)\s*\(\s*\d+\s*\)", re.IGNORECASE), "SQLI_TIME_BASED", 95),
        (re.compile(r";\s*(drop|delete|insert|update|alter)\s+[a-z0-9_]+", re.IGNORECASE), "SQLI_STACKED_QUERY", 95),
        (re.compile(r"--\s*$", re.IGNORECASE), "SQLI_COMMENT", 60),
    ]

    XSS_PATTERNS = [
        (re.compile(r"<script[^>]*>[\s\S]*?</script>", re.IGNORECASE), "XSS_SCRIPT_TAG", 85),
        (re.compile(r"javascript:\s*[^\s;]+", re.IGNORECASE), "XSS_PSEUDO_PROTOCOL", 85),
        (
            re.compile(r"(onerror|onload|onclick|onmouseover)\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE),
            "XSS_DOM_HANDLER",
            80,
        ),
        (re.compile(r"<iframe[^>]*>", re.IGNORECASE), "XSS_IFRAME_INJECTION", 75),
    ]

    TRAVERSAL_SSRF_PATTERNS = [
        (re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)", re.IGNORECASE), "PATH_TRAVERSAL", 85),
        (
            re.compile(r"(/etc/passwd|/etc/shadow|/proc/self/|win\.ini|system32)", re.IGNORECASE),
            "LFI_SENSITIVE_FILE",
            95,
        ),
        (re.compile(r"169\.254\.169\.254|metadata\.google\.internal", re.IGNORECASE), "SSRF_CLOUD_METADATA", 100),
        (re.compile(r"(\.env|\.git/config|\.aws/credentials)", re.IGNORECASE), "SENSITIVE_PROBING", 95),
    ]

    def inspect(self, context: RequestContext) -> List[InspectionFinding]:
        findings: List[InspectionFinding] = []
        targets = [
            ("URI", context.uri),
            ("QueryString", context.query_string),
            ("Body", context.body),
        ]

        # Scan each target against all patterns
        all_rules = self.SQLI_PATTERNS + self.XSS_PATTERNS + self.TRAVERSAL_SSRF_PATTERNS

        for target_name, target_value in targets:
            if not target_value:
                continue
            for regex, rule_id, score in all_rules:
                match = regex.search(target_value)
                if match:
                    findings.append(
                        InspectionFinding(
                            rule_id=rule_id,
                            attack_type=rule_id.split("_")[0],
                            risk_score=score,
                            matched_target=target_name,
                            matched_pattern=match.group(0)[:60],
                        )
                    )

        return findings
