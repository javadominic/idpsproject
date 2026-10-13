"""
IDPS Observability
==================
Structured logging, metrics collection, and distributed tracing
using OpenTelemetry and structlog.

Provides unified observability across all IDPS services with:
- Structured JSON logging with correlation IDs
- Prometheus metrics (counters, histograms, gauges)
- OpenTelemetry distributed tracing
- Per-service and per-layer instrumentation
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from functools import wraps
from typing import Any, AsyncGenerator, Callable

import structlog
from prometheus_client import Counter, Histogram, Gauge, Info


# ─── Structured Logging ─────────────────────────────────────────────────────────

def setup_logging(
    service_name: str,
    log_level: str = "INFO",
    json_output: bool = True,
) -> structlog.BoundLogger:
    """
    Configure structured logging for an IDPS service.

    All log entries include:
    - service: which microservice emitted the log
    - timestamp: ISO 8601 UTC
    - level: log severity
    - event: the log message
    - Additional context fields (tenant_id, trace_id, etc.)
    """
    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        structlog.processors.TimeStamper(fmt="iso"),
    ]

    if json_output:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=True))

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, log_level.upper(), logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    logger = structlog.get_logger(service=service_name)
    return logger


def get_logger(name: str = "") -> structlog.BoundLogger:
    """Get a logger instance with optional name binding."""
    return structlog.get_logger(component=name) if name else structlog.get_logger()


# ─── Prometheus Metrics ─────────────────────────────────────────────────────────

# Service info
service_info = Info("idps_service", "IDPS service information")

# ── Sensor Layer Metrics ──
events_ingested = Counter(
    "idps_events_ingested_total",
    "Total events ingested by sensor type",
    ["sensor_type", "event_type", "tenant_id"],
)

events_normalized = Counter(
    "idps_events_normalized_total",
    "Total events successfully normalized",
    ["sensor_type", "tenant_id"],
)

events_dropped = Counter(
    "idps_events_dropped_total",
    "Events dropped during ingestion",
    ["sensor_type", "reason", "tenant_id"],
)

ingestion_latency = Histogram(
    "idps_ingestion_latency_seconds",
    "Time to ingest and normalize an event",
    ["sensor_type"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
)

# ── Detection Layer Metrics ──
detections_total = Counter(
    "idps_detections_total",
    "Total detections by engine and severity",
    ["engine", "severity", "tenant_id"],
)

detection_latency = Histogram(
    "idps_detection_latency_seconds",
    "Detection engine processing time",
    ["engine"],
    buckets=[0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0],
)

active_rules = Gauge(
    "idps_active_rules",
    "Number of active detection rules",
    ["engine"],
)

# ── Decision Layer Metrics ──
decisions_total = Counter(
    "idps_decisions_total",
    "Total decisions by action and policy mode",
    ["action", "policy_mode", "tenant_id"],
)

risk_score_distribution = Histogram(
    "idps_risk_score",
    "Distribution of risk scores",
    ["severity"],
    buckets=[0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100],
)

# ── Enforcement Layer Metrics ──
enforcement_actions = Counter(
    "idps_enforcement_actions_total",
    "Total enforcement actions by type and outcome",
    ["action", "success", "tenant_id"],
)

enforcement_latency = Histogram(
    "idps_enforcement_latency_seconds",
    "Enforcement action execution time (CRITICAL for inline IPS)",
    ["action"],
    buckets=[0.0001, 0.0005, 0.001, 0.002, 0.005, 0.01, 0.05, 0.1],
)

fail_mode_activations = Counter(
    "idps_fail_mode_activations_total",
    "Times the enforcement layer activated fail-mode",
    ["fail_mode", "tenant_id"],
)

# ── Alert Layer Metrics ──
alerts_created = Counter(
    "idps_alerts_created_total",
    "Total alerts created by severity",
    ["severity", "tenant_id"],
)

alerts_by_status = Gauge(
    "idps_alerts_by_status",
    "Current alerts by status",
    ["status", "tenant_id"],
)

mean_time_to_detect = Histogram(
    "idps_mttd_seconds",
    "Mean Time to Detect (event timestamp to alert creation)",
    buckets=[1, 5, 10, 30, 60, 300, 600, 1800, 3600],
)

mean_time_to_respond = Histogram(
    "idps_mttr_seconds",
    "Mean Time to Respond (alert creation to enforcement action)",
    buckets=[1, 5, 10, 30, 60, 300, 600, 1800, 3600],
)

# ── Deception Metrics ──
deception_triggers = Counter(
    "idps_deception_triggers_total",
    "Deception technology triggers",
    ["deception_type", "service_emulated", "tenant_id"],
)

# ── Sandbox Metrics ──
sandbox_submissions = Counter(
    "idps_sandbox_submissions_total",
    "Files submitted to sandbox",
    ["verdict", "tenant_id"],
)

sandbox_analysis_time = Histogram(
    "idps_sandbox_analysis_seconds",
    "Sandbox analysis time",
    buckets=[1, 5, 10, 30, 60, 120, 300],
)

# ── Threat Hunting Metrics ──
active_hunts = Gauge("idps_active_hunts", "Currently active threat hunts")

hunts_completed = Counter(
    "idps_hunts_completed_total",
    "Completed threat hunts",
    ["outcome"],  # detections_found | no_findings | new_rules_created
)

# ── Compliance Metrics ──
compliance_score = Gauge(
    "idps_compliance_score",
    "Current compliance score by framework",
    ["framework"],
)

# ── System Health ──
message_bus_lag = Gauge(
    "idps_message_bus_lag",
    "Kafka consumer group lag",
    ["topic", "partition"],
)

pipeline_throughput = Counter(
    "idps_pipeline_events_per_second",
    "Pipeline throughput in events/second",
    ["layer"],
)


# ─── Timing Decorator ───────────────────────────────────────────────────────────

def timed(metric: Histogram, labels: dict[str, str] | None = None):
    """Decorator to measure function execution time with a Prometheus histogram."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            start = time.perf_counter()
            try:
                return await func(*args, **kwargs)
            finally:
                elapsed = time.perf_counter() - start
                if labels:
                    metric.labels(**labels).observe(elapsed)
                else:
                    metric.observe(elapsed)

        @wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            start = time.perf_counter()
            try:
                return func(*args, **kwargs)
            finally:
                elapsed = time.perf_counter() - start
                if labels:
                    metric.labels(**labels).observe(elapsed)
                else:
                    metric.observe(elapsed)

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
    return decorator


# ─── Tracing Context Manager ────────────────────────────────────────────────────

@asynccontextmanager
async def trace_operation(
    operation_name: str,
    attributes: dict[str, str] | None = None,
) -> AsyncGenerator[dict[str, Any], None]:
    """
    Context manager for tracing an operation.

    Usage:
        async with trace_operation("process_event", {"event_type": "dns"}) as span:
            # ... do work ...
            span["result"] = "success"
    """
    span_context: dict[str, Any] = {
        "operation": operation_name,
        "start_time": time.perf_counter(),
        "attributes": attributes or {},
    }

    try:
        # Try to use OpenTelemetry if available
        from opentelemetry import trace
        tracer = trace.get_tracer("idps")
        with tracer.start_as_current_span(
            operation_name,
            attributes=attributes or {},
        ) as span:
            span_context["trace_id"] = format(span.get_span_context().trace_id, "032x")
            span_context["span_id"] = format(span.get_span_context().span_id, "016x")
            yield span_context
    except ImportError:
        # Fallback: no-op tracing
        yield span_context
    finally:
        span_context["duration_ms"] = (time.perf_counter() - span_context["start_time"]) * 1000


# Need this import for the timed decorator check
import asyncio
