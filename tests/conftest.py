"""Pytest fixtures and mock AWS setup for Zero-Trust WAF test suite."""

import os
import boto3
import pytest
from moto import mock_aws

# Ensure mock AWS credentials exist before any boto3 client initialization
os.environ["AWS_ACCESS_KEY_ID"] = "testing-mock-key"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing-mock-secret"
os.environ["AWS_SECURITY_TOKEN"] = "testing-mock-token"
os.environ["AWS_SESSION_TOKEN"] = "testing-mock-session"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture(scope="function")
def aws_credentials():
    """Sets standard mock credentials for testing."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing-mock-key"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing-mock-secret"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture(scope="function")
def mock_wafv2_client(aws_credentials):
    """Provides a mocked AWS WAFv2 client with a seeded IP set."""
    with mock_aws():
        client = boto3.client("wafv2", region_name="us-east-1")
        ip_set = client.create_ip_set(
            Name="TestAutomatedBannedIPSet",
            Scope="CLOUDFRONT",
            IPAddressVersion="IPV4",
            Addresses=["198.51.100.1/32"],
            Description="Unit test banned IP set",
        )
        yield {
            "client": client,
            "ip_set_name": "TestAutomatedBannedIPSet",
            "ip_set_id": ip_set["Summary"]["Id"],
            "lock_token": ip_set["Summary"]["LockToken"],
        }
