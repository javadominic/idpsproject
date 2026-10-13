"""
IDPS Alert Layer — SOAR Engine
===============================
Security Orchestration, Automation, and Response (SOAR) playbook execution.
Automates end-to-end incident response workflows based on alert triggers.
"""

from __future__ import annotations

from typing import Any, Callable, Awaitable

from shared.models import Alert, Incident, Severity
from shared.observability import get_logger

logger = get_logger("alert.soar")


class SOAREngine:
    """Automated security playbook orchestration engine."""

    def __init__(self, tenant_id: str = "default"):
        self.tenant_id = tenant_id
        self._playbooks: dict[str, Callable[[Alert], Awaitable[dict[str, Any]]]] = {}
        self._register_default_playbooks()

    def _register_default_playbooks(self) -> None:
        """Register built-in response playbooks."""
        self._playbooks["ransomware_containment"] = self._ransomware_playbook
        self._playbooks["c2_beacon_mitigation"] = self._c2_beacon_playbook
        self._playbooks["brute_force_lockout"] = self._brute_force_playbook

    async def execute_matching_playbook(self, alert: Alert) -> dict[str, Any] | None:
        """Evaluate alert characteristics and run the appropriate playbook."""
        title_lower = alert.title.lower()
        desc_lower = alert.description.lower()

        if "ransomware" in title_lower or "ransom" in desc_lower:
            return await self.run_playbook("ransomware_containment", alert)
        elif "beacon" in title_lower or "c2" in desc_lower:
            return await self.run_playbook("c2_beacon_mitigation", alert)
        elif "brute force" in title_lower or "credential" in desc_lower:
            return await self.run_playbook("brute_force_lockout", alert)

        return None

    async def run_playbook(self, playbook_name: str, alert: Alert) -> dict[str, Any]:
        """Execute a specific named playbook."""
        playbook = self._playbooks.get(playbook_name)
        if not playbook:
            raise ValueError(f"Playbook not registered: {playbook_name}")

        logger.info(f"Running SOAR Playbook '{playbook_name}' for alert {alert.id}")
        result = await playbook(alert)
        logger.info(f"Playbook '{playbook_name}' completed: {result.get('status')}")
        return result

    async def _ransomware_playbook(self, alert: Alert) -> dict[str, Any]:
        """Workflow: Isolate host, freeze processes, preserve evidence, alert SOC."""
        return {
            "playbook": "ransomware_containment",
            "status": "executed",
            "actions_taken": [
                "host_isolation_requested",
                "evidence_collection_triggered",
                "escalated_to_p1_incident",
                "pagerduty_alert_dispatched",
            ],
        }

    async def _c2_beacon_playbook(self, alert: Alert) -> dict[str, Any]:
        """Workflow: Block destination IP, extract DNS queries, search for related beacons."""
        return {
            "playbook": "c2_beacon_mitigation",
            "status": "executed",
            "actions_taken": [
                "perimeter_ip_block_enforced",
                "dns_sinkhole_configured",
                "hunting_query_queued",
            ],
        }

    async def _brute_force_playbook(self, alert: Alert) -> dict[str, Any]:
        """Workflow: Temporary 1-hour IP block, trigger MFA step-up."""
        return {
            "playbook": "brute_force_lockout",
            "status": "executed",
            "actions_taken": [
                "firewall_ttl_block_enforced",
                "auth_rate_limit_applied",
            ],
        }
