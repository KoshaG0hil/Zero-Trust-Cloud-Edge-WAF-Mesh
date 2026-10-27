"""Tests for AWS WAFv2 controller and dynamic IP blocklist."""

from src.mitigation.waf_controller import AwsWafController


def test_get_ip_set(mock_wafv2_client):
    info = mock_wafv2_client
    controller = AwsWafController(scope="CLOUDFRONT")
    ip_set = controller.get_ip_set(info["ip_set_name"], info["ip_set_id"])
    assert ip_set is not None
    assert ip_set["Name"] == info["ip_set_name"]
    assert "198.51.100.1/32" in ip_set["Addresses"]


def test_add_ip_to_blocklist(mock_wafv2_client):
    info = mock_wafv2_client
    controller = AwsWafController(scope="CLOUDFRONT")
    new_ip = "203.0.113.50"

    success = controller.add_ip_to_blocklist(new_ip, info["ip_set_name"], info["ip_set_id"])
    assert success is True

    updated_set = controller.get_ip_set(info["ip_set_name"], info["ip_set_id"])
    assert f"{new_ip}/32" in updated_set["Addresses"]


def test_remove_ip_from_blocklist(mock_wafv2_client):
    info = mock_wafv2_client
    controller = AwsWafController(scope="CLOUDFRONT")
    target_ip = "198.51.100.1"

    success = controller.remove_ip_from_blocklist(target_ip, info["ip_set_name"], info["ip_set_id"])
    assert success is True

    updated_set = controller.get_ip_set(info["ip_set_name"], info["ip_set_id"])
    assert f"{target_ip}/32" not in updated_set["Addresses"]
