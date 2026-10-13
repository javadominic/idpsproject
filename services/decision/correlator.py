"""
IDPS Decision Layer — Correlator & Deduplicator
================================================
Deduplicates repetitive detections, groups related events, and suppresses alert floods.
"""

from __future__ import annotations

import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta

from shared.models import Detection
from shared.observability import get_logger

logger = get_logger("decision.correlator")


class DecisionCorrelator:
    """Handles alert deduplication and flood suppression."""

    def __init__(self, suppression_window_seconds: int = 60):
        self.suppression_window = timedelta(seconds=suppression_window_seconds)
        # Signature key -> last seen timestamp
        self._seen_signatures: dict[str, datetime] = {}
        self._suppressed_count: dict[str, int] = defaultdict(int)

    def should_suppress(self, detection: Detection) -> bool:
        """
        Check if detection should be suppressed as duplicate.
        Key is (rule_id, entity, tenant_id).
        """
        now = datetime.now(timezone.utc)
        evidence = detection.evidence or {}
        entity = evidence.get("src_ip") or evidence.get("source") or detection.event_id

        key = f"{detection.tenant_id}:{detection.rule_id}:{entity}"

        if key in self._seen_signatures:
            last_seen = self._seen_signatures[key]
            if now - last_seen < self.suppression_window:
                self._suppressed_count[key] += 1
                return True

        self._seen_signatures[key] = now
        self._cleanup(now)
        return False

    def _cleanup(self, now: datetime) -> None:
        """Purge stale cache keys."""
        cutoff = now - (self.suppression_window * 2)
        for k in list(self._seen_signatures.keys()):
            if self._seen_signatures[k] < cutoff:
                del self._seen_signatures[k]
                self._suppressed_count.pop(k, None)
