"""
IDPS Ingestion Pipeline
========================
Orchestrates all sensors, normalizes events, and publishes to the message bus.
Implements the full Sensor Layer from the architecture diagram.

Data Flow:
  External Data Sources
    ├─ Network Traffic (PCAP, NetFlow, DNS)
    ├─ Endpoints (EDR, EPP, logs, telemetry)
    ├─ Logs & Cloud (Syslog, cloud, app, infra)
    ├─ Threat Intel Feeds (IOC, TTP, STIX/TAXII)
    └─ Asset / Identity (AD, CMDB, IAM)
         │
         ▼  Ingest / Stream
  Sensor Layer (Collection & Normalization)
    ├─ Network Sensor (AF_XDP, tap, inline)
    ├─ Host Agent (eBPF, FIM, process)
    ├─ Log Collector (Syslog, cloud, app)
    └─ File/Artifact Collector (PCAP, logs, binaries)
         │
         ▼  Normalized Events (CEF/JSON)
  → Kafka: idps.sensor.normalized-events
"""

from __future__ import annotations

import asyncio
from typing import Any

from shared.config import config
from shared.messaging import MessageBus, Topic
from shared.models import NormalizedEvent
from shared.observability import (
    events_normalized, pipeline_throughput, get_logger, timed, ingestion_latency,
)
from services.ingestion.sensors import (
    BaseSensor, NetworkSensor, HostAgent, LogCollector, FileArtifactCollector,
)

logger = get_logger("ingestion.pipeline")


class IngestionPipeline:
    """
    Main orchestrator for the Sensor Layer.

    Manages all sensors, collects their events, applies normalization
    and filtering, then publishes to the message bus for downstream
    processing by the Detection Layer.
    """

    def __init__(self, bus: MessageBus, tenant_id: str = "default"):
        self.bus = bus
        self.tenant_id = tenant_id
        self._sensors: list[BaseSensor] = []
        self._running = False
        self._tasks: list[asyncio.Task] = []

        # Event pipeline settings
        self._batch_size = 100
        self._batch_timeout_ms = 50
        self._event_queue: asyncio.Queue[NormalizedEvent] = asyncio.Queue(maxsize=10000)

        # Filters
        self._ip_whitelist: set[str] = set()
        self._event_type_filters: set[str] = set()

    def register_sensor(self, sensor: BaseSensor) -> None:
        """Register a sensor with the pipeline."""
        self._sensors.append(sensor)
        logger.info(
            "Sensor registered",
            sensor_id=sensor.sensor_id,
            sensor_type=sensor.sensor_type,
        )

    def setup_default_sensors(self) -> None:
        """Initialize the default sensor configuration."""
        cfg = config()

        # Network Sensor — captures packets and flows
        self.register_sensor(NetworkSensor(
            sensor_id="network_sensor_01",
            interface="eth0",
            capture_mode="tap",
            tenant_id=self.tenant_id,
        ))

        # Host Agent — eBPF-based process and file monitoring
        self.register_sensor(HostAgent(
            sensor_id="host_agent_01",
            hostname="idps-host-01",
            watch_paths=["/etc", "/usr/bin", "/usr/local/bin", "/tmp"],
            tenant_id=self.tenant_id,
        ))

        # Log Collector — Syslog + cloud logs
        self.register_sensor(LogCollector(
            sensor_id="log_collector_01",
            listen_port=514,
            protocol="udp",
            tenant_id=self.tenant_id,
        ))

        # File/Artifact Collector — suspicious files for sandbox
        self.register_sensor(FileArtifactCollector(
            sensor_id="file_collector_01",
            watch_dirs=["/var/idps/incoming"],
            tenant_id=self.tenant_id,
        ))

        logger.info(f"Default sensors configured: {len(self._sensors)} sensors")

    async def start(self) -> None:
        """Start all sensors and the publish loop."""
        self._running = True
        logger.info("Ingestion pipeline starting")

        # Start each sensor's collection loop
        for sensor in self._sensors:
            await sensor.start()
            task = asyncio.create_task(
                self._sensor_loop(sensor),
                name=f"sensor_{sensor.sensor_id}",
            )
            self._tasks.append(task)

        # Start the batch publish loop
        self._tasks.append(
            asyncio.create_task(self._publish_loop(), name="publish_loop")
        )

        logger.info(
            "Ingestion pipeline started",
            sensor_count=len(self._sensors),
        )

    async def stop(self) -> None:
        """Gracefully stop all sensors and flush remaining events."""
        self._running = False

        # Stop all sensors
        for sensor in self._sensors:
            await sensor.stop()

        # Cancel tasks
        for task in self._tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        # Flush remaining events
        await self._flush_queue()
        logger.info("Ingestion pipeline stopped")

    async def ingest_event(self, event: NormalizedEvent) -> bool:
        """
        Manually ingest an event into the pipeline.
        Useful for API-submitted events or test events.
        """
        if self._should_filter(event):
            return False

        try:
            self._event_queue.put_nowait(event)
            return True
        except asyncio.QueueFull:
            logger.warning("Event queue full, dropping event")
            return False

    async def _sensor_loop(self, sensor: BaseSensor) -> None:
        """Collect events from a sensor and enqueue them."""
        try:
            async for event in sensor.collect():
                if not self._running:
                    break

                if not self._should_filter(event):
                    try:
                        self._event_queue.put_nowait(event)
                        events_normalized.labels(
                            sensor_type=sensor.sensor_type,
                            tenant_id=self.tenant_id,
                        ).inc()
                    except asyncio.QueueFull:
                        logger.warning(
                            "Event queue full",
                            sensor_id=sensor.sensor_id,
                        )
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(
                "Sensor loop error",
                sensor_id=sensor.sensor_id,
                error=str(e),
            )

    async def _publish_loop(self) -> None:
        """Batch events and publish to Kafka."""
        batch: list[NormalizedEvent] = []

        while self._running:
            try:
                # Collect a batch
                try:
                    event = await asyncio.wait_for(
                        self._event_queue.get(),
                        timeout=self._batch_timeout_ms / 1000,
                    )
                    batch.append(event)
                except asyncio.TimeoutError:
                    pass

                # Drain more if available (up to batch_size)
                while len(batch) < self._batch_size:
                    try:
                        event = self._event_queue.get_nowait()
                        batch.append(event)
                    except asyncio.QueueEmpty:
                        break

                # Publish batch
                if batch:
                    await self._publish_batch(batch)
                    batch = []

            except asyncio.CancelledError:
                # Flush remaining
                if batch:
                    await self._publish_batch(batch)
                break
            except Exception as e:
                logger.error(f"Publish loop error: {e}")
                batch = []
                await asyncio.sleep(0.1)

    async def _publish_batch(self, batch: list[NormalizedEvent]) -> None:
        """Publish a batch of events to the message bus."""
        for event in batch:
            # Use source IP as partition key for ordering
            key = None
            if event.network and event.network.src_ip:
                key = event.network.src_ip
            elif event.hostname:
                key = event.hostname

            await self.bus.publish(
                Topic.NORMALIZED_EVENTS,
                event,
                key=key,
                headers={
                    "sensor": event.source_sensor,
                    "event_type": event.event_type.value,
                    "tenant_id": event.tenant_id,
                },
            )

            pipeline_throughput.labels(layer="sensor").inc()

        logger.debug(f"Published batch of {len(batch)} events")

    async def _flush_queue(self) -> None:
        """Flush all remaining events in the queue."""
        batch: list[NormalizedEvent] = []
        while not self._event_queue.empty():
            try:
                event = self._event_queue.get_nowait()
                batch.append(event)
            except asyncio.QueueEmpty:
                break

        if batch:
            await self._publish_batch(batch)
            logger.info(f"Flushed {len(batch)} remaining events")

    def _should_filter(self, event: NormalizedEvent) -> bool:
        """Apply pre-publish filters."""
        # Whitelist filter
        if self._ip_whitelist and event.network:
            if event.network.src_ip in self._ip_whitelist:
                return True

        # Event type filter
        if self._event_type_filters:
            if event.event_type.value in self._event_type_filters:
                return True

        return False

    def add_ip_whitelist(self, ip: str) -> None:
        """Add an IP to the ingestion whitelist (will be filtered out)."""
        self._ip_whitelist.add(ip)

    def add_event_type_filter(self, event_type: str) -> None:
        """Filter out events of a specific type."""
        self._event_type_filters.add(event_type)

    @property
    def stats(self) -> dict[str, Any]:
        """Get pipeline statistics."""
        return {
            "sensors_registered": len(self._sensors),
            "sensors_running": sum(1 for s in self._sensors if s._running),
            "queue_size": self._event_queue.qsize(),
            "queue_max": self._event_queue.maxsize,
            "is_running": self._running,
        }
