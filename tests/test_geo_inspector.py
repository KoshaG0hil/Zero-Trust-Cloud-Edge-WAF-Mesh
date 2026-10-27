"""Tests for geographic perimeter inspection."""

from src.core.config import RequestContext
from src.inspectors.geo_inspector import GeoRiskInspector


def test_standard_country_allowed():
    inspector = GeoRiskInspector()
    context = RequestContext(client_ip="1.2.3.4", method="GET", uri="/", country_code="US")
    findings = inspector.inspect(context)
    assert len(findings) == 0


def test_sanctioned_country_blocked():
    inspector = GeoRiskInspector()
    for country in ["KP", "IR", "SY", "CU"]:
        context = RequestContext(client_ip="1.2.3.4", method="GET", uri="/", country_code=country)
        findings = inspector.inspect(context)
        assert len(findings) > 0
        assert findings[0].rule_id == "SANCTIONED_GEOLOCATION"


def test_high_risk_asn():
    inspector = GeoRiskInspector()
    context = RequestContext(client_ip="1.2.3.4", method="GET", uri="/", country_code="NL", asn=9009)
    findings = inspector.inspect(context)
    assert any(f.rule_id == "HIGH_RISK_HOSTING_ASN" for f in findings)
