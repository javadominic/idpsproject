"""
IDPS Decision Layer — Threat Hunter (★ NEW)
=============================================
Proactive threat hunting engine for identifying stealthy threats, APTs, and
uncovered techniques through hypothesis-driven automated queries.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone, timedelta
from typing import Any

from shared.models import (
    Detection, EventType, NormalizedEvent, ThreatCategory, ThreatHunt,
)
from shared.observability import active_hunts, hunts_completed, get_logger
from shared.storage import get_storage

logger = get_logger("decision.threat_hunter")


class ThreatHunter:
    """Hypothesis-driven automated threat hunting engine."""

    def __init__(self, tenant_id: str = "default"):
        self.tenant_id = tenant_id
        self._active_hunts: dict[str, ThreatHunt] = {}

    async def create_hunt(
        self,
        title: str,
        hypothesis: str,
        methodology: str = "",
        query: str = "",
        analyst: str = "automated",
        time_range_hours: int = 24,
    ) -> ThreatHunt:
        """Create a new hunting session."""
        now = datetime.now(timezone.utc)
        hunt = ThreatHunt(
            title=title,
            hypothesis=hypothesis,
            methodology=methodology,
            query=query,
            analyst=analyst,
            time_range_start=now - timedelta(hours=time_range_hours),
            time_range_end=now,
            tenant_id=self.tenant_id,
        )
        self._active_hunts[hunt.id] = hunt
        storage = get_storage()
        await storage.hunts.save(hunt)
        active_hunts.inc()
        logger.info(f"Threat hunt created: {hunt.title} ({hunt.id})")
        return hunt

    async def execute_hunt(self, hunt_id: str) -> ThreatHunt:
        """Execute a threat hunt session against historical events."""
        hunt = self._active_hunts.get(hunt_id)
        if not hunt:
            storage = get_storage()
            hunt = await storage.hunts.get_by_id(hunt_id, tenant_id=self.tenant_id)
            if not hunt:
                raise ValueError(f"Threat hunt not found: {hunt_id}")

        logger.info(f"Executing threat hunt: {hunt.title}")
        storage = get_storage()
        recent_events = await storage.events.list(tenant_id=self.tenant_id, limit=1000)

        findings: list[dict[str, Any]] = []

        # Analyze events based on hunt hypothesis patterns
        query_lower = (hunt.query or "").lower()
        for ev in recent_events:
            matched = False
            reason = ""

            # Pattern 1: Living off the Land Binaries (LOLBins)
            if "lolbin" in query_lower or "certutil" in query_lower or "bitsadmin" in query_lower:
                if ev.process and ev.process.name:
                    pname = ev.process.name.lower()
                    if pname in ("certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe", "wmic.exe"):
                        matched = True
                        reason = f"Suspicious LOLBin execution: {pname}"

            # Pattern 2: Rare parent-child process relationships
            elif "parent" in query_lower or "spawning" in query_lower:
                if ev.process and ev.process.parent_name:
                    parent = ev.process.parent_name.lower()
                    child = (ev.process.name or "").lower()
                    if parent in ("word.exe", "excel.exe", "powerpnt.exe") and child in ("cmd.exe", "powershell.exe"):
                        matched = True
                        reason = f"Office app spawned shell: {parent} -> {child}"

            # Pattern 3: DNS Tunneling hunt
            elif "dns" in query_lower or "tunnel" in query_lower:
                if ev.dns and ev.dns.query_name and len(ev.dns.query_name) > 60:
                    matched = True
                    reason = f"Anomalously long DNS query: {ev.dns.query_name[:30]}..."

            # Fallback text query match
            elif hunt.query and hunt.query.lower() in str(ev.raw_log or "").lower():
                matched = True
                reason = "Matched query string in raw log"

            if matched:
                findings.append({
                    "event_id": ev.id,
                    "timestamp": ev.timestamp.isoformat(),
                    "reason": reason,
                    "hostname": ev.hostname,
                })

        hunt.findings = findings
        hunt.status = "completed"
        hunt.conclusion = (
            f"Hunt completed. Found {len(findings)} suspicious events matching hypothesis."
            if findings
            else "Hunt completed. No anomalous indicators found."
        )

        await storage.hunts.save(hunt)
        if hunt.id in self._active_hunts:
            del self._active_hunts[hunt.id]
        active_hunts.dec()
        hunts_completed.labels(outcome="detections_found" if findings else "no_findings").inc()

        logger.info(f"Threat hunt completed: {hunt.title} ({len(findings)} findings)")
        return hunt
