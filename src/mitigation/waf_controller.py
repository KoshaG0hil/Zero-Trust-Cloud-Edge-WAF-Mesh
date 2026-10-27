"""AWS WAFv2 Dynamic IP Blocking and Threat Intelligence Controller."""

from typing import Any, Dict, List, Optional
import boto3
from botocore.exceptions import ClientError


class AwsWafController:
    """Manages AWS WAFv2 WebACLs, IP Sets, and automated IP ban lists."""

    def __init__(
        self,
        scope: str = "CLOUDFRONT",
        region: str = "us-east-1",
        session: Optional[boto3.Session] = None,
    ):
        self.scope = scope
        self.region = region if scope == "REGIONAL" else "us-east-1"
        self.session = session or boto3.Session()
        self.client = self.session.client("wafv2", region_name=self.region)

    def get_ip_set_with_token(self, name: str, ip_set_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves WAF IP Set details along with its concurrency LockToken."""
        try:
            response = self.client.get_ip_set(
                Name=name,
                Scope=self.scope,
                Id=ip_set_id,
            )
            ip_set = response.get("IPSet", {})
            lock_token = response.get("LockToken") or ip_set.get("LockToken", "mock-token")
            return {
                "IPSet": ip_set,
                "LockToken": lock_token,
            }
        except ClientError:
            return None

    def get_ip_set(self, name: str, ip_set_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves WAF IP Set details and CIDR addresses."""
        result = self.get_ip_set_with_token(name, ip_set_id)
        return result["IPSet"] if result else None

    def add_ip_to_blocklist(self, ip: str, name: str, ip_set_id: str) -> bool:
        """Appends a client IP (/32) to the specified AWS WAFv2 IP Set."""
        cidr = f"{ip}/32" if "/" not in ip else ip
        try:
            res = self.get_ip_set_with_token(name, ip_set_id)
            if not res or not res.get("IPSet"):
                return False

            lock_token = res["LockToken"]
            current_addresses: List[str] = res["IPSet"].get("Addresses", [])

            if cidr in current_addresses:
                return True  # Already blocked

            updated_addresses = current_addresses + [cidr]
            self.client.update_ip_set(
                Name=name,
                Scope=self.scope,
                Id=ip_set_id,
                Addresses=updated_addresses,
                LockToken=lock_token,
            )
            return True
        except ClientError:
            return False

    def remove_ip_from_blocklist(self, ip: str, name: str, ip_set_id: str) -> bool:
        """Removes a client IP from the specified AWS WAFv2 IP Set."""
        cidr = f"{ip}/32" if "/" not in ip else ip
        try:
            res = self.get_ip_set_with_token(name, ip_set_id)
            if not res or not res.get("IPSet"):
                return False

            lock_token = res["LockToken"]
            current_addresses: List[str] = res["IPSet"].get("Addresses", [])

            if cidr not in current_addresses:
                return True

            updated_addresses = [addr for addr in current_addresses if addr != cidr]
            self.client.update_ip_set(
                Name=name,
                Scope=self.scope,
                Id=ip_set_id,
                Addresses=updated_addresses,
                LockToken=lock_token,
            )
            return True
        except ClientError:
            return False
