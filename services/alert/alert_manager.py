"""
IDPS Alert Layer — Alert Manager
=================================
Prioritizes, correlates, and manages the lifecycle of SOC alerts.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from shared.models import (
    Alert, AlertStatus, Decision, Detection, Severity,
)
from shared.observability import alerts_created, alerts_by_status, get_logger
from shared.storage import get_storage

logger = get_logger("alert.alert_manager")


class AlertManager:
    """Manages the creation, triage, and lifecycle of SOC alerts."""

    def __init__(self, tenant_id: str = "default"):
        self.tenant_id = tenant_id

    async def create_alert_from_decision(
        self,
        decision: Decision,
        detection: Detection | None = None,
    ) -> Alert:
        """Create a new prioritized SOC alert from a decision."""
        # Calculate Priority: 1 (Critical) to 5 (Info)
        priority_map = {
            Severity.CRITICAL: 1,
            Severity.HIGH: 2,
            Severity.MEDIUM: 3,
            Severity.LOW: 4,
            Severity.INFO: 5,
        }
        priority = priority_map.get(decision.severity, 3)

        title = f"[{decision.severity.value.upper()}] Threat Detected: {decision.policy_justification[:80]}"
        if detection and detection.rule_name:
            title = f"[{decision.severity.value.upper()}] {detection.rule_name}"

        # Extract MITRE info
        tactics = []
        techniques = []
        if detection and detection.mitre:
            tactics.append(detection.mitre.tactic)
            techniques.append(detection.mitre.technique)

        alert = Alert(
            title=title,
            description=decision.policy_justification,
            severity=decision.severity,
            status=AlertStatus.NEW,
            detection_ids=[decision.detection_id],
            event_ids=[decision.event_id],
            priority=priority,
            mitre_tactics=tactics,
            mitre_techniques=techniques,
            tenant_id=decision.tenant_id,
        )

        storage = get_storage()
        await storage.alerts.save(alert)

        alerts_created.labels(
            severity=alert.severity.value,
            tenant_id=alert.tenant_id,
        ).inc()
        alerts_by_status.labels(
            status=alert.status.value,
            tenant_id=alert.tenant_id,
        ).inc()

        logger.info(f"Alert Created: P{alert.priority} - {alert.title} ({alert.id})")
        return alert

    async def update_status(
        self,
        alert_id: str,
        new_status: AlertStatus,
        assigned_to: str | None = None,
        notes: str | None = None,
    ) -> Alert | None:
        """Update an alert's triage status."""
        storage = get_storage()
        alert = await storage.alerts.get_by_id(alert_id, tenant_id=self.tenant_id)
        if not alert:
            return None

        old_status = alert.status
        alert.status = new_status
        if assigned_to:
            alert.assigned_to = assigned_to
        if notes:
            alert.resolution_notes = notes

        if new_status == AlertStatus.ACKNOWLEDGED and not alert.acknowledged_at:
            alert.acknowledged_at = datetime.now(timezone.utc)
        elif new_status in (AlertStatus.RESOLVED, AlertStatus.CLOSED):
            alert.resolved_at = datetime.now(timezone.utc)

        await storage.alerts.save(alert)
        alerts_by_status.labels(status=old_status.value, tenant_id=alert.tenant_id).dec()
        alerts_by_status.labels(status=new_status.value, tenant_id=alert.tenant_id).inc()

        logger.info(f"Alert {alert_id} status updated: {old_status.value} -> {new_status.value}")
        return alert
