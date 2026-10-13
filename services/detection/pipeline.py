"""
IDPS Detection Pipeline
========================
Orchestrates all 5 detection engines and the correlation engine.
Subscribes to normalized events from the Sensor Layer and produces Detections.

Latency budgets handled:
- Inline synchronous path: Signature (<1ms) + Protocol (<5ms)
- Asynchronous path: Behavioral (<50ms) + ML (<100ms) + Sandbox (background)
- Cross-engine correlation: groups and boosts multi-engine/kill-chain signals.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from shared.config import config
from shared.messaging import MessageBus, Topic, MessageEnvelope, deserialize_message
from shared.models import NormalizedEvent, Detection, DetectionMethod
from shared.observability import (
    pipeline_throughput, detection_latency, detections_total, get_logger,
)
from services.detection.engines import (
    BaseDetectionEngine, SignatureEngine, ProtocolAnalyzer,
    BehaviorAnalyzer, MLEngine, SandboxEngine,
)
from services.detection.correlation import CorrelationEngine
from services.detection.rule_loader import RuleLoader

logger = get_logger("detection.pipeline")


class DetectionPipeline:
    """
    Main detection pipeline orchestrator.
    Consumes from Topic.NORMALIZED_EVENTS, runs detection engines,
    correlates findings, and emits to Topic.DETECTIONS.
    """

    def __init__(self, bus: MessageBus, tenant_id: str = "default"):
        self.bus = bus
        self.tenant_id = tenant_id

        # Initialize engines
        cfg = config()
        self.signature_engine = SignatureEngine(tenant_id=tenant_id)
        self.protocol_analyzer = ProtocolAnalyzer(
            tls_mode=cfg.tls_inspection_mode.value,
            tenant_id=tenant_id,
        )
        self.behavior_analyzer = BehaviorAnalyzer(tenant_id=tenant_id)
        self.ml_engine = MLEngine(tenant_id=tenant_id)
        self.sandbox_engine = SandboxEngine(
            backend=cfg.sandbox.backend,
            timeout_seconds=cfg.sandbox.timeout_seconds,
            max_concurrent=cfg.sandbox.max_concurrent,
            tenant_id=tenant_id,
        )

        self.engines: list[BaseDetectionEngine] = [
            self.signature_engine,
            self.protocol_analyzer,
            self.behavior_analyzer,
            self.ml_engine,
            self.sandbox_engine,
        ]

        self.correlator = CorrelationEngine(tenant_id=tenant_id)
        self.rule_loader = RuleLoader()
        self._running = False

    async def start(self) -> None:
        """Start all engines and subscribe to normalized events."""
        self._running = True
        logger.info("Starting Detection Pipeline...")

        # Load rules from directory
        rules = self.rule_loader.load_from_directory()
        for rule in rules:
            self.signature_engine.add_rule(rule)

        # Initialize all engines
        for engine in self.engines:
            await engine.start()

        # Subscribe to normalized events
        await self.bus.subscribe(
            Topic.NORMALIZED_EVENTS,
            self.handle_event_message,
            group_id="idps-detection-group",
        )
        logger.info("Detection Pipeline started and subscribed to events")

    async def stop(self) -> None:
        """Gracefully stop detection engines."""
        self._running = False
        for engine in self.engines:
            await engine.stop()
        logger.info("Detection Pipeline stopped")

    async def handle_event_message(self, envelope: MessageEnvelope) -> None:
        """Process an incoming message from the message bus."""
        try:
            event = deserialize_message(envelope.payload, NormalizedEvent)
            await self.process_event(event)
        except Exception as e:
            logger.error(f"Error processing event envelope in detection pipeline: {e}")

    async def process_event(self, event: NormalizedEvent) -> list[Detection]:
        """
        Process a single NormalizedEvent across all engines.
        Returns all generated detections (both direct and correlated).
        """
        start = time.perf_counter()
        detections: list[Detection] = []

        # 1. Inline Critical Path (Signature + Protocol)
        inline_tasks = [
            self.signature_engine.analyze(event),
            self.protocol_analyzer.analyze(event),
        ]
        inline_results = await asyncio.gather(*inline_tasks, return_exceptions=True)
        for res in inline_results:
            if isinstance(res, list):
                detections.extend(res)
            elif isinstance(res, Exception):
                logger.error(f"Inline detection engine error: {res}")

        # 2. Async Non-blocking Path (Behavior, ML, Sandbox)
        async_tasks = [
            self.behavior_analyzer.analyze(event),
            self.ml_engine.analyze(event),
            self.sandbox_engine.analyze(event),
        ]
        async_results = await asyncio.gather(*async_tasks, return_exceptions=True)
        for res in async_results:
            if isinstance(res, list):
                detections.extend(res)
            elif isinstance(res, Exception):
                logger.error(f"Async detection engine error: {res}")

        # 3. Cross-Engine Correlation
        correlated: list[Detection] = []
        if detections:
            try:
                correlated = await self.correlator.correlate(detections)
            except Exception as e:
                logger.error(f"Correlation error: {e}")

        all_detections = detections + correlated

        # 4. Publish detections to message bus for Decision Layer
        for det in all_detections:
            topic = Topic.CORRELATION_EVENTS if det.detection_method == DetectionMethod.CORRELATION else Topic.DETECTIONS
            await self.bus.publish(
                topic,
                det,
                key=event.network.src_ip if (event.network and event.network.src_ip) else event.id,
                headers={"engine": det.detection_method.value, "severity": det.severity.value},
            )
            pipeline_throughput.labels(layer="detection").inc()

        total_elapsed = (time.perf_counter() - start) * 1000
        logger.debug(
            f"Event {event.id} evaluated in {total_elapsed:.2f}ms: {len(all_detections)} detections"
        )
        return all_detections
