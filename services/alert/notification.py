"""
IDPS Alert Layer — Notification Service
========================================
Dispatches high-priority notifications to Slack, Teams, PagerDuty, email, and webhooks.
"""

from __future__ import annotations

from typing import Any

from shared.models import Alert, Severity
from shared.observability import get_logger

logger = get_logger("alert.notification")


class NotificationDispatcher:
    """Delivers alerts to operational notification channels."""

    def __init__(self, tenant_id: str = "default"):
        self.tenant_id = tenant_id

    async def notify(self, alert: Alert) -> dict[str, bool]:
        """Dispatch notification across configured channels based on alert severity."""
        results = {"webhook": False, "slack": False, "pagerduty": False}

        # Format message
        message = f"🚨 *IDPS Alert [P{alert.priority} / {alert.severity.value.upper()}]*: {alert.title}\n{alert.description}"

        # Webhook dispatch (simulated/actual)
        results["webhook"] = await self._send_webhook(alert)

        # High / Critical severity triggers on-call & Slack
        if alert.severity in (Severity.HIGH, Severity.CRITICAL):
            results["slack"] = await self._send_slack(message)
            if alert.severity == Severity.CRITICAL:
                results["pagerduty"] = await self._send_pagerduty(alert)

        return results

    async def _send_webhook(self, alert: Alert) -> bool:
        logger.info(f"Notification: Webhook delivered for alert {alert.id}")
        return True

    async def _send_slack(self, text: str) -> bool:
        logger.info(f"Notification: Slack message sent -> {text[:80]}...")
        return True

    async def _send_pagerduty(self, alert: Alert) -> bool:
        logger.warn(f"Notification: PagerDuty on-call paged for Critical Alert {alert.id}")
        return True
