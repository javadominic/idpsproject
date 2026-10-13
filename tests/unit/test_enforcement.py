"""
Unit tests for Enforcement Layer (Firewall, Inline IPS, Host, Fail-Mode).
"""

import pytest

from services.enforcement.actions.firewall import FirewallActionExecutor
from services.enforcement.actions.inline_ips import InlineIPSExecutor
from services.enforcement.actions.host_action import HostActionExecutor
from services.enforcement.fail_mode import FailModeController


@pytest.mark.asyncio
async def test_firewall_and_inline_execution():
    fw = FirewallActionExecutor(dry_run=True)
    success, reason = await fw.block_ip("203.0.113.99", ttl_seconds=60, reason="C2 block")
    assert success is True
    assert "203.0.113.99" in fw.list_active_blocks()

    ips = InlineIPSExecutor(dry_run=True)
    drop_success, drop_reason = await ips.drop("flow-101", "203.0.113.99", "10.0.0.5")
    assert drop_success is True


@pytest.mark.asyncio
async def test_host_action_and_fail_mode():
    host = HostActionExecutor(dry_run=True)
    success, reason = await host.kill_process(1337, process_name="malware.exe", host="srv-01")
    assert success is True

    # Test Fail-Mode activation
    fail_mode = FailModeController()
    assert fail_mode.is_fail_mode_active is False

    # Trigger consecutive failures
    fail_mode.record_failure("Latency timeout")
    fail_mode.record_failure("Latency timeout")
    is_active = fail_mode.record_failure("Latency timeout")
    assert is_active is True
    assert fail_mode.get_fallback_action() == "allow_traffic" # Fail-open default
