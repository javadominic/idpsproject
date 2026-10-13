"""
IDPS Message Bus
================
Kafka-based event streaming abstraction for inter-service communication.
All services publish/consume through this bus using well-defined topics.

Supports:
- Async produce/consume via aiokafka
- Automatic serialization (orjson for performance)
- Dead letter queue for failed messages
- Per-tenant topic isolation when multi-tenancy is enabled
- Message tracing via OpenTelemetry
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Awaitable

import orjson
from pydantic import BaseModel

logger = logging.getLogger("idps.messaging")


# ─── Topic Definitions ──────────────────────────────────────────────────────────

class Topic(str, Enum):
    """
    Well-defined Kafka topics for the IDPS pipeline.
    Naming convention: idps.{layer}.{data_type}
    """
    # Sensor Layer → Detection Layer
    RAW_EVENTS = "idps.sensor.raw-events"
    NORMALIZED_EVENTS = "idps.sensor.normalized-events"

    # Detection Layer → Decision Layer
    DETECTIONS = "idps.detection.detections"
    CORRELATION_EVENTS = "idps.detection.correlations"

    # Decision Layer → Enforcement Layer
    DECISIONS = "idps.decision.decisions"
    APPROVED_ACTIONS = "idps.decision.approved-actions"

    # Enforcement Layer → Alert Layer
    ENFORCEMENT_RESULTS = "idps.enforcement.results"
    ENFORCEMENT_AUDIT = "idps.enforcement.audit"

    # Alert Layer
    ALERTS = "idps.alert.alerts"
    INCIDENTS = "idps.alert.incidents"
    NOTIFICATIONS = "idps.alert.notifications"

    # Deception Layer → Detection Layer
    DECEPTION_EVENTS = "idps.deception.events"

    # Feedback Loop (SOC → Management → Detection)
    RULE_UPDATES = "idps.management.rule-updates"
    POLICY_UPDATES = "idps.management.policy-updates"
    THREAT_INTEL_UPDATES = "idps.management.threat-intel"
    FALSE_POSITIVE_FEEDBACK = "idps.feedback.false-positives"
    TUNING_REQUESTS = "idps.feedback.tuning"

    # Compliance
    COMPLIANCE_EVENTS = "idps.compliance.events"

    # Forensics
    EVIDENCE_COLLECTED = "idps.forensics.evidence"

    # Threat Hunting
    HUNT_RESULTS = "idps.hunting.results"

    # Health / Observability
    HEALTH_CHECKS = "idps.platform.health"
    METRICS = "idps.platform.metrics"

    # Dead Letter Queue
    DLQ = "idps.dlq"


# ─── Message Envelope ───────────────────────────────────────────────────────────

@dataclass
class MessageEnvelope:
    """
    Wrapper around every message flowing through the bus.
    Provides tracing, routing, and error handling metadata.
    """
    topic: str
    key: str | None = None           # Partition key (e.g., tenant_id, src_ip)
    payload: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    timestamp_ms: int | None = None
    partition: int | None = None
    offset: int | None = None

    # Tracing
    trace_id: str | None = None
    span_id: str | None = None

    # Error handling
    retry_count: int = 0
    max_retries: int = 3
    original_topic: str | None = None  # For DLQ messages


def serialize_message(model: BaseModel) -> bytes:
    """Serialize a Pydantic model to bytes using orjson for performance."""
    return orjson.dumps(model.model_dump(mode="json"))


def deserialize_message(data: bytes, model_class: type[BaseModel]) -> BaseModel:
    """Deserialize bytes back to a Pydantic model."""
    return model_class.model_validate(orjson.loads(data))


# ─── Message Bus Interface ──────────────────────────────────────────────────────

MessageHandler = Callable[[MessageEnvelope], Awaitable[None]]


class MessageBus:
    """
    Async Kafka message bus abstraction.

    Usage:
        bus = MessageBus(bootstrap_servers="localhost:9092")
        await bus.start()

        # Produce
        await bus.publish(Topic.NORMALIZED_EVENTS, event)

        # Consume
        await bus.subscribe(Topic.NORMALIZED_EVENTS, handler_func)

        await bus.stop()
    """

    def __init__(
        self,
        bootstrap_servers: str = "localhost:9092",
        group_id: str = "idps-cluster",
        tenant_id: str = "default",
        multi_tenant: bool = False,
    ):
        self._bootstrap_servers = bootstrap_servers
        self._group_id = group_id
        self._tenant_id = tenant_id
        self._multi_tenant = multi_tenant
        self._producer = None
        self._consumers: dict[str, Any] = {}
        self._handlers: dict[str, list[MessageHandler]] = {}
        self._running = False
        self._consume_tasks: list[asyncio.Task] = []

    def _resolve_topic(self, topic: str | Topic) -> str:
        """Resolve topic name with optional tenant prefix for multi-tenancy."""
        topic_str = topic.value if isinstance(topic, Topic) else topic
        if self._multi_tenant:
            return f"{self._tenant_id}.{topic_str}"
        return topic_str

    async def start(self) -> None:
        """Initialize the producer and start consumer loops."""
        try:
            from aiokafka import AIOKafkaProducer
            self._producer = AIOKafkaProducer(
                bootstrap_servers=self._bootstrap_servers,
                value_serializer=lambda v: v if isinstance(v, bytes) else orjson.dumps(v),
                key_serializer=lambda k: k.encode("utf-8") if k else None,
                acks="all",
                enable_idempotence=True,
                compression_type=None,
            )
            await self._producer.start()
        except Exception as e:
            logger.warning(f"Kafka unavailable ({e}) — using in-memory message bus for development/standalone mode")
            self._producer = InMemoryProducer()

        self._running = True
        logger.info("Message bus started", extra={"bootstrap_servers": self._bootstrap_servers})

    async def stop(self) -> None:
        """Gracefully shut down producer and all consumers."""
        self._running = False

        for task in self._consume_tasks:
            task.cancel()

        for consumer in self._consumers.values():
            await consumer.stop()

        if self._producer:
            await self._producer.stop()

        logger.info("Message bus stopped")

    async def publish(
        self,
        topic: str | Topic,
        message: BaseModel | dict | bytes,
        key: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        """
        Publish a message to a topic.

        Args:
            topic: Target topic (can be Topic enum or string)
            message: Pydantic model, dict, or raw bytes
            key: Partition key for ordering guarantees
            headers: Optional message headers (trace IDs, etc.)
        """
        resolved_topic = self._resolve_topic(topic)

        if isinstance(message, BaseModel):
            payload = serialize_message(message)
        elif isinstance(message, dict):
            payload = orjson.dumps(message)
        else:
            payload = message

        kafka_headers = [(k, v.encode()) for k, v in (headers or {}).items()]

        if isinstance(self._producer, InMemoryProducer):
            await self._producer.send(resolved_topic, payload, key, kafka_headers)
        else:
            await self._producer.send_and_wait(
                resolved_topic,
                value=payload,
                key=key,
                headers=kafka_headers,
            )

        logger.debug(
            "Published message",
            extra={"topic": resolved_topic, "key": key, "size_bytes": len(payload)},
        )

    async def subscribe(
        self,
        topic: str | Topic,
        handler: MessageHandler,
        group_id: str | None = None,
    ) -> None:
        """
        Subscribe to a topic with a handler function.
        Multiple handlers can be registered for the same topic.
        """
        resolved_topic = self._resolve_topic(topic)

        if resolved_topic not in self._handlers:
            self._handlers[resolved_topic] = []
        self._handlers[resolved_topic].append(handler)

        if resolved_topic not in self._consumers:
            if isinstance(self._producer, InMemoryProducer):
                self._consumers[resolved_topic] = InMemoryConsumer(resolved_topic, self._handlers)
                async def _in_mem_dispatch(raw_val: bytes):
                    envelope = MessageEnvelope(
                        topic=resolved_topic,
                        payload=raw_val,
                        headers={},
                    )
                    for h in self._handlers.get(resolved_topic, []):
                        try:
                            await h(envelope)
                        except Exception as ex:
                            logger.error(f"In-memory handler exception: {ex}")
                self._producer.register_subscriber(resolved_topic, _in_mem_dispatch)
                logger.info(f"Using in-memory consumer dispatch for topic: {resolved_topic}")
            else:
                consumer_group = group_id or self._group_id
                try:
                    from aiokafka import AIOKafkaConsumer
                    consumer = AIOKafkaConsumer(
                        resolved_topic,
                        bootstrap_servers=self._bootstrap_servers,
                        group_id=consumer_group,
                        value_deserializer=lambda v: v,
                        auto_offset_reset="latest",
                        enable_auto_commit=True,
                    )
                    await consumer.start()
                    self._consumers[resolved_topic] = consumer

                    # Start consume loop
                    task = asyncio.create_task(self._consume_loop(resolved_topic, consumer))
                    self._consume_tasks.append(task)

                except Exception as e:
                    self._consumers[resolved_topic] = InMemoryConsumer(resolved_topic, self._handlers)
                    logger.warning(f"Kafka consumer unavailable ({e}) — using in-memory consumer for topic: {resolved_topic}")

        logger.info(
            "Subscribed to topic",
            extra={"topic": resolved_topic, "handler": handler.__name__},
        )

    async def _consume_loop(self, topic: str, consumer: Any) -> None:
        """Internal consume loop that dispatches messages to registered handlers."""
        while self._running:
            try:
                async for msg in consumer:
                    envelope = MessageEnvelope(
                        topic=topic,
                        key=msg.key.decode() if msg.key else None,
                        payload=msg.value,
                        timestamp_ms=msg.timestamp,
                        partition=msg.partition,
                        offset=msg.offset,
                        headers={k: v.decode() for k, v in (msg.headers or [])},
                    )
                    for handler in self._handlers.get(topic, []):
                        try:
                            await handler(envelope)
                        except Exception as e:
                            logger.error(
                                "Handler error",
                                extra={"topic": topic, "handler": handler.__name__, "error": str(e)},
                            )
                            # Send to DLQ
                            envelope.retry_count += 1
                            if envelope.retry_count >= envelope.max_retries:
                                envelope.original_topic = topic
                                await self._send_to_dlq(envelope)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Consumer loop error for {topic}: {e}")
                await asyncio.sleep(1)

    async def _send_to_dlq(self, envelope: MessageEnvelope) -> None:
        """Send failed messages to the Dead Letter Queue."""
        dlq_topic = self._resolve_topic(Topic.DLQ)
        dlq_payload = orjson.dumps({
            "original_topic": envelope.original_topic,
            "payload": envelope.payload.decode("utf-8", errors="replace"),
            "retry_count": envelope.retry_count,
            "headers": envelope.headers,
        })
        if self._producer:
            if isinstance(self._producer, InMemoryProducer):
                await self._producer.send(dlq_topic, dlq_payload, None, [])
            else:
                await self._producer.send_and_wait(dlq_topic, value=dlq_payload)
        logger.warning("Message sent to DLQ", extra={"original_topic": envelope.original_topic})


# ─── In-Memory Fallback (Development) ───────────────────────────────────────────

class InMemoryProducer:
    """In-memory producer for local development without Kafka."""

    def __init__(self) -> None:
        self._topics: dict[str, list[bytes]] = {}
        self._subscribers: dict[str, list[Callable]] = {}

    async def send(self, topic: str, value: bytes, key: Any = None, headers: Any = None) -> None:
        if topic not in self._topics:
            self._topics[topic] = []
        self._topics[topic].append(value)

        # Dispatch to any in-memory subscribers
        for callback in self._subscribers.get(topic, []):
            try:
                await callback(value)
            except Exception as e:
                logger.error(f"In-memory handler error: {e}")

    def register_subscriber(self, topic: str, callback: Callable) -> None:
        if topic not in self._subscribers:
            self._subscribers[topic] = []
        self._subscribers[topic].append(callback)

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass


class InMemoryConsumer:
    """In-memory consumer for local development without Kafka."""

    def __init__(self, topic: str, handlers: dict[str, list[MessageHandler]]) -> None:
        self._topic = topic
        self._handlers = handlers

    async def stop(self) -> None:
        pass


# Global singleton access
_global_bus: MessageBus | None = None


def get_message_bus(bootstrap_servers: str = "localhost:9092") -> MessageBus:
    """Get or initialize the global message bus singleton."""
    global _global_bus
    if _global_bus is None:
        _global_bus = MessageBus(bootstrap_servers=bootstrap_servers)
    return _global_bus


get_event_bus = get_message_bus

