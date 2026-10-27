"""Geographic and ASN Zero-Trust Perimeter Inspector."""

from typing import List, Set
from ..core.config import RequestContext
from .sqli_xss_inspector import InspectionFinding


class GeoRiskInspector:
    """Evaluates geographic origin and autonomous system number (ASN) risk."""

    SANCTIONED_COUNTRIES: Set[str] = {"KP", "IR", "SY", "CU"}
    HIGH_RISK_ASNS: Set[int] = {9009, 4134, 4837}  # Known bulletproof hosting / high bot concentration ASNs

    def __init__(self, sanctioned_countries: Set[str] = None):
        self.sanctioned = sanctioned_countries or self.SANCTIONED_COUNTRIES

    def inspect(self, context: RequestContext) -> List[InspectionFinding]:
        findings: List[InspectionFinding] = []
        country = context.country_code.upper()

        if country in self.sanctioned:
            findings.append(
                InspectionFinding(
                    rule_id="SANCTIONED_GEOLOCATION",
                    attack_type="GEO_ZERO_TRUST",
                    risk_score=95,
                    matched_target="CountryCode",
                    matched_pattern=f"Sanctioned Origin: {country}",
                )
            )

        if context.asn in self.HIGH_RISK_ASNS:
            findings.append(
                InspectionFinding(
                    rule_id="HIGH_RISK_HOSTING_ASN",
                    attack_type="ASN_REPUTATION",
                    risk_score=65,
                    matched_target="ASN",
                    matched_pattern=f"Bulletproof Hosting ASN: {context.asn}",
                )
            )

        return findings
