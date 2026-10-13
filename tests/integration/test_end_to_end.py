"""
Comprehensive End-to-End Pipeline Integration Test
==================================================
Verifies the complete flow:
Sensor Event → Detection Engine → Cross-Engine Correlation →
Decision & Enrichment → Enforcement & Audit → Alert & Forensic Preservation →
Compliance Audit Reporting.
"""

import pytest
import asyncio
from datetime import datetime, timezone

from shared.messaging import MessageBus, Topic
from shared.models import (
    EventType, NormalizedEvent, NetworkInfo, ProcessInfo, Severity
)
from shared.storage import get_storage
from services.detection.pipeline import DetectionPipeline
from services.decision.pipeline import DecisionPipeline
from services.enforcement.pipeline import EnforcementPipeline
from services.alert.pipeline import AlertPipeline
from idps_platform.compliance.reporter import ComplianceEngine


@pytest.mark.asyncio
async def test_full_idps_pipeline_flow():
    # 1. Setup in-memory message bus and shared storage
    bus = MessageBus()
    await bus.start()
    storage = get_storage()
    await storage.initialize()

    # 2. Instantiate all layer pipelines
    detection_pipe = DetectionPipeline(bus=bus)
    decision_pipe = DecisionPipeline(bus=bus)
    enforcement_pipe = EnforcementPipeline(bus=bus)
    alert_pipe = AlertPipeline(bus=bus)

    await detection_pipe.start()
    await decision_pipe.start()
    await enforcement_pipe.start()
    await alert_pipe.start()

    # 3. Inject a high-risk security event (Suspicious PowerShell command from external IP)
    event = NormalizedEvent(
        event_type=EventType.HOST_PROCESS,
        timestamp=datetime.now(timezone.utc),
        source_sensor="host_agent_01",
        hostname="dc01.corp.internal",
        network=NetworkInfo(
            src_ip="198.51.100.23", # Known Threat Intel IOC
            dst_ip="10.0.0.1",
            dst_port=443,
            direction="inbound",
        ),
        process=ProcessInfo(
            name="powershell.exe",
            command_line="powershell.exe -ExecutionPolicy Bypass -NoProfile -enc SQBFAFgA...",
            user="NT AUTHORITY\\SYSTEM",
            is_elevated=True,
        ),
        raw_log="powershell.exe -ExecutionPolicy Bypass -NoProfile -enc SQBFAFgA...",
    )
    await storage.events.save(event)

    # 4. Trigger detection analysis
    detections = await detection_pipe.process_event(event)
    assert len(detections) >= 1, "Expected detection engines to flag suspicious PowerShell execution"

    # 5. Process decision
    decision = await decision_pipe.process_detection(detections[0], bypass_dedup=True)
    assert decision is not None, "Expected decision pipeline to produce a Decision"
    assert decision.risk_score >= 70.0, "Expected high composite risk score due to threat intel & elevated process"

    # 6. Process enforcement
    enforcement_record = await enforcement_pipe.execute_decision(decision)
    assert enforcement_record is not None, "Expected enforcement record"
    assert enforcement_record.decision_id == decision.id

    # 7. Process SOC alert
    alert = await alert_pipe.process_decision(decision)
    assert alert is not None, "Expected alert pipeline to generate an Alert"
    assert alert.priority <= 2, "Expected high priority alert (P1/P2)"

    # Verify forensic evidence record created
    evidence_list = await storage.evidence.list(limit=10)
    assert len(evidence_list) >= 1, "Expected forensic evidence preservation record"
    assert evidence_list[0].hash_sha256 != ""
    assert evidence_list[0].is_verified is True

    # 8. Verify Compliance Report Generation
    comp_engine = ComplianceEngine()
    report = await comp_engine.generate_report(framework="pci-dss")
    assert report.total_controls > 0
    assert report.overall_score >= 80.0

    # Clean up pipelines
    await detection_pipe.stop()
    await decision_pipe.stop()
    await enforcement_pipe.stop()
    await alert_pipe.stop()
    await bus.stop()
    await storage.close()
