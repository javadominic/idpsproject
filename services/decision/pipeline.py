"""
IDPS Decision Pipeline
=======================
Consumes detections, enriches with Threat Intel & Assets, scores risk,
evaluates policy, and publishes approved decisions to the Enforcement & Alert Layers.
"""

from __future__ import annotations

import asyncio
import time

from shared.messaging import MessageBus, Topic, MessageEnvelope, deserialize_message
from shared.models import Decision, Detection, EnforcementAction
from shared.observability import decisions_total, pipeline_throughput, get_logger
from shared.storage import get_storage
from services.decision.correlator import DecisionCorrelator
from services.decision.enrichment import ThreatIntelEnricher
from services.decision.policy_engine import PolicyEngine
from services.decision.risk_scorer import RiskScorer
from services.decision.threat_hunter import ThreatHunter

logger = get_logger("decision.pipeline")


class DecisionPipeline:
    """Main decision orchestrator."""

    def __init__(self, bus: MessageBus, tenant_id: str = "default"):
        self.bus = bus
        self.tenant_id = tenant_id

        self.correlator = DecisionCorrelator()
        self.enricher = ThreatIntelEnricher()
        self.risk_scorer = RiskScorer()
        self.policy_engine = PolicyEngine(tenant_id=tenant_id)
        self.threat_hunter = ThreatHunter(tenant_id=tenant_id)
        self._running = False

    async def start(self) -> None:
        """Subscribe to detection events."""
        self._running = True
        logger.info("Starting Decision Pipeline...")
        await self.bus.subscribe(
            Topic.DETECTIONS,
            self.handle_detection_message,
            group_id="idps-decision-group",
        )
        await self.bus.subscribe(
            Topic.CORRELATION_EVENTS,
            self.handle_detection_message,
            group_id="idps-decision-group",
        )
        logger.info("Decision Pipeline started")

    async def stop(self) -> None:
        """Stop decision pipeline."""
        self._running = False
        logger.info("Decision Pipeline stopped")

    async def handle_detection_message(self, envelope: MessageEnvelope) -> None:
        """Process an incoming detection message."""
        try:
            detection = deserialize_message(envelope.payload, Detection)
            await self.process_detection(detection)
        except Exception as e:
            logger.error(f"Error handling detection in decision pipeline: {e}")

    async def process_detection(self, detection: Detection, bypass_dedup: bool = False) -> Decision | None:
        """
        Evaluate a single detection:
        1. Check deduplication / suppression
        2. Threat Intel & Asset enrichment
        3. Risk calculation
        4. Policy evaluation & action determination
        5. Publish Decision and (if approved) Action
        """
        start = time.perf_counter()

        # 1. Deduplication check
        if not bypass_dedup and self.correlator.should_suppress(detection):
            logger.debug(f"Suppressed duplicate detection: {detection.rule_id}")
            return None

        # 2. Enrichment
        enrichment = await self.enricher.enrich(detection)

        # 3. Risk scoring
        risk_score, adj_conf, adj_sev = self.risk_scorer.calculate_risk(detection, enrichment)

        # 4. Policy evaluation
        action, mode, approved, justification = self.policy_engine.evaluate(
            detection, enrichment, risk_score, adj_conf, adj_sev
        )

        # 5. Create Decision object
        decision = Decision(
            detection_id=detection.id,
            event_id=detection.event_id,
            risk_score=risk_score,
            confidence=adj_conf,
            severity=adj_sev,
            policy_mode=mode,
            recommended_action=action,
            policy_justification=justification,
            enrichment=enrichment,
            approved=approved,
            approved_by="policy_engine" if approved else "unapproved",
            approved_at=detection.created_at if approved else None,
            tenant_id=detection.tenant_id,
        )

        # Save to storage
        storage = get_storage()
        await storage.decisions.save(decision)
        await storage.detections.save(detection)

        # Publish Decision to message bus
        await self.bus.publish(
            Topic.DECISIONS,
            decision,
            key=decision.tenant_id,
            headers={
                "action": action.value,
                "approved": str(approved),
                "severity": adj_sev.value,
            },
        )
        decisions_total.labels(
            action=action.value,
            policy_mode=mode.value,
            tenant_id=decision.tenant_id,
        ).inc()
        pipeline_throughput.labels(layer="decision").inc()

        # If approved for active enforcement, publish to APPROVED_ACTIONS
        if approved and action != EnforcementAction.LOG_ONLY:
            await self.bus.publish(
                Topic.APPROVED_ACTIONS,
                decision,
                key=decision.tenant_id,
                headers={"action": action.value},
            )

        elapsed = (time.perf_counter() - start) * 1000
        logger.debug(
            f"Decision for {detection.rule_id} evaluated in {elapsed:.2f}ms: "
            f"action={action.value}, risk={risk_score}, approved={approved}"
        )
        return decision
