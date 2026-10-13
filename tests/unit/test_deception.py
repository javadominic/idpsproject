"""
Unit tests for Deception Service (Canary tokens and Honeypots).
"""

import pytest

from services.deception.canary_tokens import CanaryTokenManager
from services.deception.honeypot import SSHHoneypot


def test_canary_tokens_lifecycle():
    mgr = CanaryTokenManager(tenant_id="tenant-sec")

    # Generate Web bug token
    token_id, url = mgr.generate_web_bug_token("Confidential_Exec_Salaries.pdf")
    assert "http://" in url
    assert token_id in mgr._tokens

    # Generate AWS Credentials token
    aws_id, creds = mgr.generate_aws_credentials_token("AWS_S3_Backup_Key")
    assert creds["aws_access_key_id"].startswith("AKIA")

    # Simulate Attacker triggering the canary token
    event = mgr.trigger_token(
        token_id=token_id,
        attacker_ip="198.51.100.77",
        payload="HTTP GET /t/...",
    )
    assert event is not None
    assert event.attacker_ip == "198.51.100.77"
    assert event.deception_type == "canary_token"
