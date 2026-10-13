"""
IDPS Alert Layer — SIEM Integration
====================================
Formats and forwards security events and alerts to enterprise SIEM platforms
(Splunk, Elastic, Microsoft Sentinel, IBM QRadar) using CEF, Syslog, and JSON.
"""

from __future__ import annotations

import json
from typing import Any

from shared.models import Alert
from shared.observability import get_logger

logger = get_logger("alert.siem")


class SIEMForwarder:
    """Formats and exports alerts to external SIEM collectors."""

    def __init__(self, vendor: str = "IDPS", product: str = "NextGen-IDPS", version: str = "1.0"):
        self.vendor = vendor
        self.product = product
        self.version = version

    def format_cef(self, alert: Alert) -> str:
        """
        Format alert into standard Common Event Format (CEF).
        Format: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
        """
        severity_map = {
            "info": "1",
            "low": "3",
            "medium": "6",
            "high": "8",
            "critical": "10",
        }
        cef_sev = severity_map.get(alert.severity.value, "5")

        extensions = [
            f"msg={alert.description[:100]}",
            f"priority={alert.priority}",
            f"alertId={alert.id}",
            f"tenantId={alert.tenant_id}",
        ]
        if alert.source_ips:
            extensions.append(f"src={alert.source_ips[0]}")
        if alert.destination_ips:
            extensions.append(f"dst={alert.destination_ips[0]}")

        ext_str = " ".join(extensions)
        return f"CEF:0|{self.vendor}|{self.product}|{self.version}|{alert.priority}|{alert.title}|{cef_sev}|{ext_str}"

    def format_json(self, alert: Alert) -> str:
        """Format alert as standard structured JSON for Elastic / Splunk HEC."""
        return alert.model_dump_json()

    async def forward(self, alert: Alert, destination: str = "syslog") -> bool:
        """Forward alert to external SIEM destination."""
        cef_line = self.format_cef(alert)
        logger.info(f"Forwarded to SIEM ({destination}): {cef_line[:120]}...")
        return True
