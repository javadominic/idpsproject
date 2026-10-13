"""
Unit tests for Decision Layer (Risk scoring, Policy evaluation, Threat Hunting).
"""

import pytest

from shared.models import (
    Detection, DetectionMethod, EnforcementAction, EnrichmentResult,
    NormalizedEvent, PolicyMode, Severity, ThreatCategory,
)
from services.decision.enrichment import ThreatIntelEnricher
from services.decision.risk_scorer import RiskScorer
from services.decision.policy_engine import PolicyEngine
from services.decision.threat_hunter import ThreatHunter


@pytest.mark.asyncio
async def test_risk_scorer_and_enrichment():
    enricher = ThreatIntelEnricher()
    scorer = RiskScorer()

    detection = Detection(
        event_id="ev-ioc",
        detection_method=DetectionMethod.SIGNATURE,
        rule_name="Malicious C2 Communication",
        severity=Severity.HIGH,
        confidence=0.8,
        category=ThreatCategory.COMMAND_AND_CONTROL,
        evidence={"src_ip": "198.51.100.23"}, # Known APT29 IOC in test database
    )

    enrichment = await enricher.enrich(detection)
    assert enrichment.threat_intel_score > 0
    assert len(enrichment.known_iocs_matched) > 0

    risk_score, adj_conf, adj_sev = scorer.calculate_risk(detection, enrichment)
    assert risk_score >= 80.0
    assert adj_sev == Severity.CRITICAL


def test_policy_engine_evaluation():
    engine = PolicyEngine()
    detection = Detection(
        event_id="ev-pol",
        detection_method=DetectionMethod.SIGNATURE,
        rule_name="C2 Activity",
        severity=Severity.CRITICAL,
        category=ThreatCategory.COMMAND_AND_CONTROL,
    )
    enrichment = EnrichmentResult()

    action, mode, approved, just = engine.evaluate(
        detection, enrichment, risk_score=92.0, confidence=0.9, severity=Severity.CRITICAL
    )
    # Default config has enforcement_mode="shadow"
    assert action in (EnforcementAction.IPS_DROP, EnforcementAction.FIREWALL_TTL_BLOCK)
    assert mode == PolicyMode.SHADOW
    assert approved is False  # Shadow mode logs without approving


@pytest.mark.asyncio
async def test_threat_hunter_session():
    hunter = ThreatHunter(tenant_id="test-tenant")
    hunt = await hunter.create_hunt(
        title="Hunt for LOLBins Execution",
        hypothesis="Adversaries using certutil or bitsadmin to download payloads",
        query="lolbin",
    )
    assert hunt.id is not None
    assert hunt.status == "active"

    executed = await hunter.execute_hunt(hunt.id)
    assert executed.status == "completed"
    assert executed.conclusion is not None
