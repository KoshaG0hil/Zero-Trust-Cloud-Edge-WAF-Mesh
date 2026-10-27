"""Tests for SQL injection, XSS, and path traversal detection."""

from src.core.config import RequestContext
from src.inspectors.sqli_xss_inspector import SqliXssInspector


def test_clean_request_has_no_findings():
    inspector = SqliXssInspector()
    context = RequestContext(
        client_ip="1.2.3.4",
        method="GET",
        uri="/home",
        query_string="category=tech&page=2",
    )
    findings = inspector.inspect(context)
    assert len(findings) == 0


def test_detects_sqli_tautology_in_query_string():
    inspector = SqliXssInspector()
    context = RequestContext(
        client_ip="1.2.3.4",
        method="GET",
        uri="/products",
        query_string="id=1' or 1=1--",
    )
    findings = inspector.inspect(context)
    assert len(findings) > 0
    rule_ids = [f.rule_id for f in findings]
    assert "SQLI_TAUTOLOGY" in rule_ids


def test_detects_union_select_sqli():
    inspector = SqliXssInspector()
    context = RequestContext(
        client_ip="1.2.3.4",
        method="POST",
        uri="/search",
        body="query=books' UNION SELECT null, username, password FROM users--",
    )
    findings = inspector.inspect(context)
    rule_ids = [f.rule_id for f in findings]
    assert "SQLI_UNION_SELECT" in rule_ids


def test_detects_stored_xss_in_body():
    inspector = SqliXssInspector()
    context = RequestContext(
        client_ip="1.2.3.4",
        method="POST",
        uri="/comments",
        body="<script>alert(document.domain)</script>",
    )
    findings = inspector.inspect(context)
    rule_ids = [f.rule_id for f in findings]
    assert "XSS_SCRIPT_TAG" in rule_ids


def test_detects_path_traversal_and_ssrf():
    inspector = SqliXssInspector()
    context = RequestContext(
        client_ip="1.2.3.4",
        method="GET",
        uri="/view?file=../../../../etc/passwd",
    )
    findings = inspector.inspect(context)
    rule_ids = [f.rule_id for f in findings]
    assert "PATH_TRAVERSAL" in rule_ids
    assert "LFI_SENSITIVE_FILE" in rule_ids
