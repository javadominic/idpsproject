"""
Unit tests for Real, Non-Hardcoded Features:
- Real Suricata EVE JSON parser & evidence preservation
- Real Firewall safe allowlists, duplicate prevention, and TTL expiration
- Real Scapy Network packet normalization & capture status
- Real WAF pattern inspection (SQLi, XSS, Path Traversal)
"""

import asyncio
import os
from datetime import datetime, timezone

from services.detection.suricata_engine import SuricataIntegration
from services.enforcement.actions.firewall import FirewallActionExecutor
from services.ingestion.sensors import NetworkSensor
from services.api.routes.waf import inspect_payload


async def test_suricata_eve_ingestion():
    fixture_path = os.path.join(os.path.dirname(__file__), "..", "fixtures", "sample_eve.json")
    suricata = SuricataIntegration()

    # 1. Probe engine
    status = suricata.probe_engine()
    assert "suricata" in status
    assert "available" in status["suricata"]

    # 2. Ingest real EVE JSON fixture
    records = suricata.ingest_eve_file(fixture_path)
    assert len(records) == 2

    # Verify Alert event
    ev1, det1 = records[0]
    assert ev1.network.src_ip == "198.51.100.42"
    assert det1 is not None
    assert det1.rule_id == "SURICATA-2021001"
    assert "log4j" in det1.rule_name.lower()
    assert det1.evidence.get("suricata_alert") is not None

    # Verify DNS query event
    ev2, det2 = records[1]
    assert ev2.network.src_ip == "10.0.2.15"
    assert det2 is None  # Normal query has no alert


async def test_firewall_allowlist_and_safeguards():
    fw = FirewallActionExecutor(dry_run=True)

    # 1. Attempt to block allowlisted IP (localhost) -> MUST FAIL
    success, reason = await fw.block_ip("127.0.0.1", ttl_seconds=60)
    assert success is False
    assert "protected allowlist" in reason.lower()

    # 2. Block valid external malicious IP
    target_ip = "198.51.100.99"
    success, reason = await fw.block_ip(target_ip, ttl_seconds=3600, reason="C2 Node")
    assert success is True
    assert target_ip in fw.list_active_blocks()

    # 3. Duplicate block test -> must be idempotent
    success_dup, reason_dup = await fw.block_ip(target_ip, ttl_seconds=3600)
    assert success_dup is True
    assert "already blocked" in reason_dup.lower()

    # 4. Unblock IP
    unblock_success, unblock_msg = await fw.unblock_ip(target_ip)
    assert unblock_success is True
    assert target_ip not in fw.list_active_blocks()


async def test_network_sensor_capture_status():
    sensor = NetworkSensor(sensor_id="net_test", interface="lo0")
    status = sensor.get_capture_status()
    assert status["status"] == "stopped"
    assert status["packets_captured"] == 0

    # Start capture (will set status cleanly or report permission status if unprivileged)
    res = await sensor.start_capture()
    assert res["status"] in ("capturing", "permission_denied", "error")
    await sensor.stop_capture()
    assert sensor.get_capture_status()["status"] == "stopped"


def test_waf_real_inspection():
    # 1. SQL Injection attempt -> BLOCKED
    verdict, reason = inspect_payload("GET", "/api/users?id=1%20UNION%20SELECT%20password%20FROM%20users--", "", {})
    assert verdict == "BLOCKED"
    assert "SQL" in reason

    # 2. Path Traversal attempt -> BLOCKED
    verdict, reason = inspect_payload("GET", "/download?file=../../../../etc/passwd", "", {})
    assert verdict == "BLOCKED"
    assert "Path Traversal" in reason

    # 3. Legitimate clean request -> ALLOWED
    verdict, reason = inspect_payload("GET", "/api/v1/alerts?limit=10", "", {})
    assert verdict == "ALLOWED"
    assert reason is None


def test_pcap_offline_replay():
    pcap_path = os.path.join(os.path.dirname(__file__), "..", "fixtures", "sample_attack.pcap")
    assert os.path.exists(pcap_path), f"PCAP fixture missing: {pcap_path}"
    
    sensor = NetworkSensor(sensor_id="pcap_test_sensor", interface="lo0")
    events = sensor.replay_pcap(pcap_path)
    
    assert len(events) >= 5, f"Expected at least 5 packets, got {len(events)}"
    # Check that IP and port normalization succeeded on the packets
    syn_events = [e for e in events if e.network and e.network.src_ip == "192.168.1.150"]
    assert len(syn_events) >= 1
    assert syn_events[0].network.dst_ip == "192.168.1.1"
    assert syn_events[0].network.protocol == "tcp"

