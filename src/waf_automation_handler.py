"""CloudWatch Event / WAF Log Automation Handler for Dynamic Offender Blacklisting."""

from typing import Any, Dict, List
from .mitigation.waf_controller import AwsWafController


def process_waf_log_event(
    event: Dict[str, Any],
    waf_controller: AwsWafController = None,
    ip_set_name: str = "AutomatedBannedIPSet",
    ip_set_id: str = "mock-waf-ipset-id",
) -> List[str]:
    """Inspects WAF event payloads, identifies rogue IPs, and executes ban."""
    controller = waf_controller or AwsWafController()
    banned_ips: List[str] = []

    # Check for direct IP list or simulated event
    offender_ips = event.get("offender_ips", [])
    if not offender_ips and "Records" in event:
        for record in event["Records"]:
            ip = record.get("sourceIP") or record.get("clientIp")
            if ip:
                offender_ips.append(ip)

    for ip in offender_ips:
        success = controller.add_ip_to_blocklist(ip, name=ip_set_name, ip_set_id=ip_set_id)
        if success:
            banned_ips.append(ip)

    return banned_ips
