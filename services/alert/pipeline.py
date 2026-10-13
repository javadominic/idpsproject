"""
IDPS Alert Pipeline
====================
Consumes Decisions and Enforcement Results, generates SOC Alerts, triggers SOAR playbooks,
preserves forensic evidence, and forwards to SIEM and notification channels.
"""

from __future__ import annotations

import asyncio
from typing import Any

from shared.messaging import MessageBus, Topic, MessageEnvelope, deserialize_message
from shared.models import Alert, Decision, EnforcementRecord, Incident, Severity
from shared.observability import get_logger
from services.alert.alert_manager import AlertManager
from services.alert.forensics import ForensicsManager
from services.alert.incident_manager import IncidentManager
from services.alert.notification import NotificationDispatcher
from services.alert.siem_integration import SIEMForwarder
from services.alert.soar_engine import SOAREngine

logger = get_logger("alert.pipeline")


class AlertPipeline:
    """Main alert and incident response orchestrator."""

    def __init__(self, bus: MessageBus, tenant_id: str = "default"):
        self.bus = bus
        self.tenant_id = tenant_id

        self.alert_manager = AlertManager(tenant_id=tenant_id)
        self.forensics = ForensicsManager(tenant_id=tenant_id)
        self.incident_manager = IncidentManager(tenant_id=tenant_id)
        self.soar = SOAREngine(tenant_id=tenant_id)
        self.siem = SIEMForwarder()
        self.notifications = NotificationDispatcher(tenant_id=tenant_id)
        self._running = False

    async def start(self) -> None:
        """Subscribe to decisions and enforcement results."""
        self._running = True
        logger.info("Starting Alert Pipeline...")
        await self.bus.subscribe(
            Topic.DECISIONS,
            self.handle_decision_message,
            group_id="idps-alert-group",
        )
        logger.info("Alert Pipeline running and listening for decisions")

    async def stop(self) -> None:
        """Stop alert pipeline."""
        self._running = False
        logger.info("Alert Pipeline stopped")

    async def handle_decision_message(self, envelope: MessageEnvelope) -> None:
        """Process an incoming decision from the Decision Layer."""
        try:
            decision = deserialize_message(envelope.payload, Decision)
            await self.process_decision(decision)
        except Exception as e:
            logger.error(f"Error handling decision in alert pipeline: {e}")

    async def process_decision(self, decision: Decision) -> Alert | None:
        """Convert qualifying decision into an alert and execute response actions."""
        # Only create alerts for noteworthy severity
        if decision.severity == Severity.INFO and decision.risk_score < 30.0:
            return None

        # 1. Create prioritized alert
        alert = await self.alert_manager.create_alert_from_decision(decision)

        # 2. Preserve forensic evidence if payload exists
        sample_evidence = f"EventID: {decision.event_id}\nRisk: {decision.risk_score}\nJustification: {decision.policy_justification}".encode()
        await self.forensics.preserve_evidence(
            incident_id=alert.id,
            evidence_type="log",
            data=sample_evidence,
            description=f"Automated forensic log snapshot for alert {alert.id}",
            alert_id=alert.id,
        )

        # 3. Publish Alert to message bus
        await self.bus.publish(
            Topic.ALERTS,
            alert,
            key=alert.id,
            headers={"severity": alert.severity.value, "priority": str(alert.priority)},
        )

        # 4. Trigger SOAR Playbook
        await self.soar.execute_matching_playbook(alert)

        # 5. Forward to SIEM
        await self.siem.forward(alert)

        # 6. Dispatch notifications
        await self.notifications.notify(alert)

        # 7. Escalate to full Incident if Critical
        if alert.severity == Severity.CRITICAL:
            incident = await self.incident_manager.create_incident(
                title=f"CRITICAL INCIDENT: {alert.title}",
                description=alert.description,
                severity=Severity.CRITICAL,
                alert_ids=[alert.id],
            )
            await self.bus.publish(Topic.INCIDENTS, incident, key=incident.id)

        return alert
