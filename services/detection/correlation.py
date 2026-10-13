"""
IDPS Cross-Engine Correlation
==============================
Correlates detections across multiple engines (Signature, Protocol, Behavioral,
ML, Sandbox, Deception) to identify multi-stage attacks and elevate high-confidence threats.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any

from shared.models import (
    Detection, DetectionMethod, Severity, ThreatCategory, MITREMapping,
)
from shared.observability import detections_total, get_logger

logger = get_logger("detection.correlation")


class CorrelationEngine:
    """
    Cross-engine correlation engine.

    Responsibilities:
    1. Multi-Engine Corroboration:
       If 2 or more distinct engines flag the same event/IP, boost confidence and severity.
    2. Multi-Stage Attack Correlation (Kill Chain / MITRE):
       Tracks progressions across MITRE tactics (e.g. Initial Access -> Execution -> C2 -> Exfiltration)
       within a sliding time window.
    3. Deception Elevation:
       Any activity following a Honeypot / Canary trigger is instantly marked CRITICAL.
    """

    def __init__(
        self,
        window_minutes: int = 15,
        confidence_boost: float = 0.2,
        tenant_id: str = "default",
    ):
        self.window = timedelta(minutes=window_minutes)
        self.confidence_boost = confidence_boost
        self.tenant_id = tenant_id

        # State tracking: entity (IP/host) -> list of (timestamp, Detection)
        self._entity_detections: dict[str, list[tuple[datetime, Detection]]] = defaultdict(list)
        # Deception flag tracking: IP -> timestamp
        self._deception_tainted_ips: dict[str, datetime] = {}
        self._lock = asyncio.Lock()

    async def correlate(self, new_detections: list[Detection]) -> list[Detection]:
        """Correlate a batch of new detections with current window state."""
        if not new_detections:
            return []

        async with self._lock:
            now = datetime.now(timezone.utc)
            self._purge_expired(now)

            correlated_detections: list[Detection] = []

            for det in new_detections:
                entity = self._extract_entity(det)
                if not entity:
                    continue

                # Check if this detection is from Deception
                if det.detection_method == DetectionMethod.DECEPTION or (
                    det.category == ThreatCategory.DISCOVERY and "honeypot" in det.description.lower()
                ):
                    self._deception_tainted_ips[entity] = now

                # Add to history
                self._entity_detections[entity].append((now, det))
                history = [d for _, d in self._entity_detections[entity]]

                # 1. Multi-engine corroboration
                distinct_methods = {d.detection_method for d in history if d.event_id == det.event_id}
                if len(distinct_methods) > 1:
                    composite = self._create_multi_engine_detection(det, history, distinct_methods)
                    if composite:
                        correlated_detections.append(composite)

                # 2. Kill Chain progression check
                kill_chain_det = self._check_kill_chain_progression(entity, history)
                if kill_chain_det:
                    correlated_detections.append(kill_chain_det)

                # 3. Deception taint elevation
                if entity in self._deception_tainted_ips:
                    tainted_det = self._create_deception_taint_detection(det, entity)
                    if tainted_det:
                        correlated_detections.append(tainted_det)

            return correlated_detections

    def _extract_entity(self, det: Detection) -> str | None:
        """Extract primary entity (IP, host, or user) from detection evidence."""
        evidence = det.evidence or {}
        for key in ("src_ip", "source", "ip", "attacker_ip", "hostname", "host"):
            if key in evidence and evidence[key]:
                return str(evidence[key])
        return None

    def _create_multi_engine_detection(
        self,
        trigger: Detection,
        history: list[Detection],
        distinct_methods: set[DetectionMethod],
    ) -> Detection | None:
        """Create composite detection when multiple engines agree on the same event."""
        related = [d for d in history if d.event_id == trigger.event_id]
        if len(related) < 2:
            return None

        method_names = ", ".join(m.value for m in distinct_methods)
        boosted_confidence = min(0.99, max(d.confidence for d in related) + self.confidence_boost)

        return Detection(
            event_id=trigger.event_id,
            detection_method=DetectionMethod.CORRELATION,
            rule_id="CORR-MULTI-ENGINE",
            rule_name=f"Multi-Engine Corroboration ({len(distinct_methods)} engines)",
            severity=Severity.HIGH if trigger.severity != Severity.CRITICAL else Severity.CRITICAL,
            confidence=boosted_confidence,
            category=trigger.category,
            mitre=trigger.mitre,
            description=f"Event confirmed by {len(distinct_methods)} engines: {method_names}",
            evidence={
                "engines": list(method_names.split(", ")),
                "underlying_rule_ids": [d.rule_id for d in related if d.rule_id],
            },
            related_event_ids=[trigger.event_id],
            tenant_id=self.tenant_id,
        )

    def _check_kill_chain_progression(
        self,
        entity: str,
        history: list[Detection],
    ) -> Detection | None:
        """Detect progression across MITRE ATT&CK kill chain stages."""
        tactics_seen: dict[str, Detection] = {}
        for d in history:
            if d.mitre and d.mitre.tactic:
                tactics_seen[d.mitre.tactic_id or d.mitre.tactic] = d

        # If entity has hit >= 3 distinct tactics in the window
        if len(tactics_seen) >= 3:
            tactic_names = [d.mitre.tactic for d in tactics_seen.values() if d.mitre]
            event_ids = list({d.event_id for d in tactics_seen.values()})

            return Detection(
                event_id=history[-1].event_id,
                detection_method=DetectionMethod.CORRELATION,
                rule_id="CORR-KILL-CHAIN",
                rule_name="Multi-Stage Attack Progression (Kill Chain)",
                severity=Severity.CRITICAL,
                confidence=0.95,
                category=ThreatCategory.LATERAL_MOVEMENT,
                description=f"Entity '{entity}' progressed across {len(tactics_seen)} MITRE tactics: {', '.join(tactic_names)}",
                evidence={
                    "entity": entity,
                    "tactics_seen": tactic_names,
                    "progression_count": len(tactics_seen),
                },
                related_event_ids=event_ids,
                tenant_id=self.tenant_id,
            )
        return None

    def _create_deception_taint_detection(self, det: Detection, entity: str) -> Detection | None:
        """Elevate actions from known honeypot/canary-interacted entities."""
        if det.detection_method == DetectionMethod.CORRELATION:
            return None

        return Detection(
            event_id=det.event_id,
            detection_method=DetectionMethod.CORRELATION,
            rule_id="CORR-DECEPTION-TAINT",
            rule_name="Post-Deception Hostile Activity",
            severity=Severity.CRITICAL,
            confidence=0.98,
            category=det.category or ThreatCategory.COMMAND_AND_CONTROL,
            description=f"Entity '{entity}' previously triggered honeypot/canary and is now active: {det.description}",
            evidence={"entity": entity, "subsequent_rule": det.rule_id},
            related_event_ids=[det.event_id],
            tenant_id=self.tenant_id,
        )

    def _purge_expired(self, now: datetime) -> None:
        """Purge detections older than the sliding window."""
        cutoff = now - self.window
        for entity in list(self._entity_detections.keys()):
            self._entity_detections[entity] = [
                (t, d) for t, d in self._entity_detections[entity] if t > cutoff
            ]
            if not self._entity_detections[entity]:
                del self._entity_detections[entity]

        for ip in list(self._deception_tainted_ips.keys()):
            if self._deception_tainted_ips[ip] <= cutoff:
                del self._deception_tainted_ips[ip]
