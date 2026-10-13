"""
Unit tests for detection engines.
"""

import pytest
from datetime import datetime, timezone

from shared.models import (
    DNSInfo, EventType, FileInfo, NetworkInfo, NormalizedEvent,
    ProcessInfo, Severity, TLSInfo, ThreatCategory,
)
from services.detection.engines import (
    SignatureEngine, SignatureRule, ProtocolAnalyzer,
    BehaviorAnalyzer, MLEngine, SandboxEngine,
)
from services.detection.correlation import CorrelationEngine


@pytest.mark.asyncio
async def test_signature_engine_match():
    engine = SignatureEngine()
    await engine.start()

    # Create event matching SIG-002: Suspicious PowerShell execution
    event = NormalizedEvent(
        event_type=EventType.HOST_PROCESS,
        process=ProcessInfo(
            name="powershell.exe",
            command_line="powershell.exe -ExecutionPolicy Bypass -NoProfile -enc SQBFAFgA...",
        ),
    )

    detections = await engine.analyze(event)
    assert len(detections) >= 1
    assert any("PowerShell" in (d.rule_name or "") for d in detections)
    assert detections[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_protocol_analyzer_dga_detection():
    analyzer = ProtocolAnalyzer()
    await analyzer.start()

    # DGA suspect event
    event = NormalizedEvent(
        event_type=EventType.DNS_QUERY,
        dns=DNSInfo(
            query_name="xrkqwbzxvnmcptyj.evil-c2.xyz",
            query_type="A",
        ),
    )

    detections = await analyzer.analyze(event)
    assert len(detections) >= 1
    assert any("DGA" in (d.rule_name or "") for d in detections)


@pytest.mark.asyncio
async def test_behavior_analyzer_port_scan():
    analyzer = BehaviorAnalyzer()
    await analyzer.start()

    # Simulate scanning 25 distinct ports from single source IP
    src_ip = "192.168.1.105"
    detections = []
    for port in range(1, 26):
        event = NormalizedEvent(
            event_type=EventType.NETWORK_FLOW,
            network=NetworkInfo(
                src_ip=src_ip,
                dst_ip="10.0.0.1",
                dst_port=port,
                protocol="tcp",
            ),
        )
        res = await analyzer.analyze(event)
        if res:
            detections.extend(res)

    assert len(detections) >= 1
    assert any("Port Scan" in (d.rule_name or "") for d in detections)


@pytest.mark.asyncio
async def test_sandbox_engine_malicious_detection():
    sandbox = SandboxEngine(backend="local")
    await sandbox.start()

    event = NormalizedEvent(
        event_type=EventType.FILE_ARTIFACT,
        file=FileInfo(
            name="ransomware_payload.exe",
            hash_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            size_bytes=102400,
            is_executable=True,
            is_packed=True,
            entropy=7.8,
        ),
    )

    verdict, report = await sandbox._run_local_sandbox(event)
    assert verdict == "malicious"
    assert report["packed"] is True
    assert report["high_entropy"] is True


@pytest.mark.asyncio
async def test_correlation_engine_boost():
    correlator = CorrelationEngine()

    from shared.models import Detection, DetectionMethod
    det1 = Detection(
        event_id="ev-123",
        detection_method=DetectionMethod.SIGNATURE,
        rule_id="SIG-001",
        rule_name="Brute Force",
        severity=Severity.HIGH,
        confidence=0.8,
        evidence={"src_ip": "10.0.0.99"},
    )
    det2 = Detection(
        event_id="ev-123",
        detection_method=DetectionMethod.BEHAVIORAL,
        rule_id="BHV-004",
        rule_name="Brute Force Attack",
        severity=Severity.HIGH,
        confidence=0.85,
        evidence={"src_ip": "10.0.0.99"},
    )

    correlated = await correlator.correlate([det1, det2])
    assert len(correlated) >= 1
    assert correlated[0].detection_method == DetectionMethod.CORRELATION
    assert correlated[0].confidence > 0.85
