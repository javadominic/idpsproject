"""
IDPS Alert Layer — Incident Manager
====================================
Orchestrates incident response cases, grouping related alerts and
tracking containment, eradication, and post-incident lessons learned.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from shared.models import Alert, Incident, IncidentStatus, Severity
from shared.observability import get_logger
from shared.storage import get_storage

logger = get_logger("alert.incident_manager")


class IncidentManager:
    """Manages multi-alert security incidents and response lifecycles."""

    def __init__(self, tenant_id: str = "default"):
        self.tenant_id = tenant_id

    async def create_incident(
        self,
        title: str,
        description: str,
        severity: Severity = Severity.HIGH,
        lead_analyst: str | None = None,
        alert_ids: list[str] | None = None,
    ) -> Incident:
        """Create a new incident case."""
        incident = Incident(
            title=title,
            description=description,
            severity=severity,
            status=IncidentStatus.OPEN,
            lead_analyst=lead_analyst,
            alert_ids=alert_ids or [],
            detected_at=datetime.now(timezone.utc),
            tenant_id=self.tenant_id,
        )
        storage = get_storage()
        await storage.incidents.save(incident)
        logger.info(f"Incident Opened: {incident.title} ({incident.id})")
        return incident

    async def advance_stage(
        self,
        incident_id: str,
        stage: IncidentStatus,
        notes: str = "",
    ) -> Incident | None:
        """Advance the incident along the IR lifecycle."""
        storage = get_storage()
        incident = await storage.incidents.get_by_id(incident_id, tenant_id=self.tenant_id)
        if not incident:
            return None

        incident.status = stage
        now = datetime.now(timezone.utc)

        if stage == IncidentStatus.CONTAINMENT:
            incident.contained_at = now
        elif stage == IncidentStatus.ERADICATION:
            incident.eradicated_at = now
        elif stage == IncidentStatus.RECOVERY:
            incident.recovered_at = now
        elif stage == IncidentStatus.CLOSED:
            incident.closed_at = now

        if notes:
            incident.action_items.append({"stage": stage.value, "notes": notes, "at": now.isoformat()})

        await storage.incidents.save(incident)
        logger.info(f"Incident {incident_id} advanced to stage {stage.value}")
        return incident
