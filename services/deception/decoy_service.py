"""
IDPS Deception Service — Decoy Service Orchestrator
===================================================
Coordinates honeypots, canary tokens, and decoy assets.
Feeds deception triggers directly into the sensor/detection pipeline.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from shared.messaging import MessageBus, Topic
from shared.models import (
    DeceptionEvent, EventType, NetworkInfo, NormalizedEvent,
)
from shared.observability import get_logger
from services.deception.canary_tokens import CanaryTokenManager
from services.deception.honeypot import SSHHoneypot, HTTPHoneypot, BaseHoneypot

logger = get_logger("deception.decoy_service")


class DecoyService:
    """Manages active deception technologies across the infrastructure."""

    def __init__(self, bus: MessageBus, tenant_id: str = "default"):
        self.bus = bus
        self.tenant_id = tenant_id
        self.canary_manager = CanaryTokenManager(tenant_id=tenant_id)
        self.honeypots: list[BaseHoneypot] = [
            SSHHoneypot(port=2222, tenant_id=tenant_id),
            HTTPHoneypot(port=8088, tenant_id=tenant_id),
        ]
        self._running = False

    async def start(self) -> None:
        """Start all honeypots and deception listeners."""
        self._running = True
        logger.info("Starting Deception Service...")

        for hp in self.honeypots:
            hp.set_event_handler(self.handle_deception_event)
            await hp.start()

        logger.info("Deception Service running with honeypots & canary tokens active")

    async def stop(self) -> None:
        """Stop honeypot listeners."""
        self._running = False
        for hp in self.honeypots:
            await hp.stop()
        logger.info("Deception Service stopped")

    async def handle_deception_event(self, event: DeceptionEvent) -> None:
        """
        Handle a captured deception trigger:
        1. Publish to Topic.DECEPTION_EVENTS
        2. Convert into a NormalizedEvent (EventType.DECEPTION_TRIGGER)
        3. Publish to Topic.NORMALIZED_EVENTS for instant detection processing.
        """
        logger.warn(
            f"DECEPTION ALERT: {event.deception_type} triggered by {event.attacker_ip} "
            f"on service {event.service_emulated}"
        )

        # 1. Publish to Deception topic
        await self.bus.publish(
            Topic.DECEPTION_EVENTS,
            event,
            key=event.attacker_ip,
            headers={"service": event.service_emulated},
        )

        # 2. Synthesize NormalizedEvent with is_deception_trigger=True
        norm_event = NormalizedEvent(
            event_type=EventType.DECEPTION_TRIGGER,
            timestamp=datetime.now(timezone.utc),
            source_sensor=f"deception_{event.deception_type}",
            network=NetworkInfo(
                src_ip=event.attacker_ip,
                dst_port=event.attacker_port,
                direction="inbound",
            ),
            raw_log=f"Attacker hit {event.deception_type} ({event.service_emulated}): {event.payload}",
            is_deception_trigger=True,
            tenant_id=self.tenant_id,
        )

        # 3. Publish to Ingestion / Detection pipeline
        await self.bus.publish(
            Topic.NORMALIZED_EVENTS,
            norm_event,
            key=event.attacker_ip,
            headers={"deception": "true", "tenant_id": self.tenant_id},
        )
