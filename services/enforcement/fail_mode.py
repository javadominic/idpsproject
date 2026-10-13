"""
IDPS Enforcement Layer — Fail-Mode (★ NEW)
===========================================
High-Availability failover mechanism for inline IPS engines.
When packet processing latency exceeds SLA budget (> 2ms) or downstream services degrade:
- Fail-Open: Passes traffic uninspected (prioritizes availability over security)
- Fail-Closed: Blocks all suspect traffic (prioritizes security over availability)
"""

from __future__ import annotations

import time
from shared.config import config, FailMode
from shared.observability import fail_mode_activations, get_logger

logger = get_logger("enforcement.fail_mode")


class FailModeController:
    """Monitors system health and applies fail-open / fail-closed policies during failure states."""

    def __init__(self, tenant_id: str = "default"):
        self.tenant_id = tenant_id
        self._is_active = False
        self._active_reason = ""
        self._failure_count = 0
        self._max_consecutive_failures = 3

    @property
    def is_fail_mode_active(self) -> bool:
        return self._is_active

    def record_success(self) -> None:
        """Reset failure counter on healthy operations."""
        self._failure_count = 0
        if self._is_active:
            logger.info("Fail-mode deactivated: system recovered")
            self._is_active = False

    def record_failure(self, reason: str) -> bool:
        """
        Record a processing failure or timeout.
        Activates fail-mode if consecutive failures exceed threshold.
        """
        self._failure_count += 1
        if self._failure_count >= self._max_consecutive_failures and not self._is_active:
            self._is_active = True
            self._active_reason = reason
            cfg = config()
            mode = cfg.enforcement_fail_mode.value
            logger.critical(
                f"FAIL-MODE ACTIVATED: Consecutive failures={self._failure_count}. "
                f"Mode={mode}. Reason={reason}"
            )
            fail_mode_activations.labels(
                fail_mode=mode,
                tenant_id=self.tenant_id,
            ).inc()
            return True
        return self._is_active

    def get_fallback_action(self) -> str:
        """Return the fallback decision based on configured fail-mode."""
        cfg = config()
        if cfg.enforcement_fail_mode == FailMode.FAIL_OPEN:
            return "allow_traffic"
        return "block_traffic"
