"""
IDPS Enforcement Layer — Audit Logger (★ NEW)
==============================================
Maintains an immutable, cryptographically verifiable audit log of every
enforcement action executed. Essential for compliance audits (PCI-DSS 10.6, SOC2 CC7.2).
"""

from __future__ import annotations

from shared.messaging import MessageBus, Topic
from shared.models import EnforcementRecord
from shared.observability import get_logger
from shared.storage import get_storage

logger = get_logger("enforcement.audit_logger")


class EnforcementAuditLogger:
    """Audit logger for regulatory compliance and accountability."""

    def __init__(self, bus: MessageBus):
        self.bus = bus

    async def log_action(self, record: EnforcementRecord) -> None:
        """Persist audit record and stream to compliance topic."""
        storage = get_storage()
        await storage.enforcements.save(record)

        # Integrity hash for non-repudiation
        digest = record.integrity_hash()

        logger.info(
            f"Enforcement Audit: Action {record.action.value} on {record.action_target} "
            f"| Success: {record.success} | Hash: {digest[:16]}"
        )

        # Stream to audit topic
        await self.bus.publish(
            Topic.ENFORCEMENT_AUDIT,
            record,
            key=record.decision_id,
            headers={
                "action": record.action.value,
                "success": str(record.success),
                "integrity_hash": digest,
            },
        )
