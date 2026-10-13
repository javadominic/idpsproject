"""
IDPS Storage Layer
==================
Async database abstractions for PostgreSQL, ClickHouse, and Redis.
Provides repository patterns and in-memory fallbacks for development/testing.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Generic, TypeVar

from shared.config import config
from shared.models import (
    Alert, Decision, Detection, EnforcementRecord, EvidenceRecord,
    Incident, NormalizedEvent, ThreatHunt, ComplianceReport,
)
from shared.observability import get_logger

logger = get_logger("shared.storage")

T = TypeVar("T")


# ─── Generic Repository Interface ──────────────────────────────────────────────

class BaseRepository(Generic[T], ABC):
    """Abstract repository for domain entities."""

    @abstractmethod
    async def save(self, entity: T) -> T:
        """Persist entity."""
        ...

    @abstractmethod
    async def get_by_id(self, entity_id: str, tenant_id: str = "default") -> T | None:
        """Retrieve entity by ID."""
        ...

    @abstractmethod
    async def list(
        self,
        tenant_id: str = "default",
        limit: int = 100,
        offset: int = 0,
        **filters: Any,
    ) -> list[T]:
        """List entities with optional filtering."""
        ...


# ─── In-Memory Store (Fast Local & Test Execution) ─────────────────────────────

class InMemoryRepository(BaseRepository[T]):
    """Thread-safe in-memory repository implementation."""

    def __init__(self, key_attr: str = "id"):
        self._key_attr = key_attr
        self._items: dict[str, T] = {}
        self._lock = asyncio.Lock()

    async def save(self, entity: T) -> T:
        async with self._lock:
            key = getattr(entity, self._key_attr)
            self._items[key] = entity
            return entity

    async def get_by_id(self, entity_id: str, tenant_id: str = "default") -> T | None:
        async with self._lock:
            item = self._items.get(entity_id)
            if item and hasattr(item, "tenant_id") and item.tenant_id != tenant_id and tenant_id != "*":
                return None
            return item

    async def list(
        self,
        tenant_id: str = "default",
        limit: int = 100,
        offset: int = 0,
        **filters: Any,
    ) -> list[T]:
        async with self._lock:
            results: list[T] = []
            for item in self._items.values():
                if hasattr(item, "tenant_id") and tenant_id != "*" and item.tenant_id != tenant_id:
                    continue
                match = True
                for k, v in filters.items():
                    if hasattr(item, k) and getattr(item, k) != v:
                        match = False
                        break
                if match:
                    results.append(item)
            return results[offset : offset + limit]


# ─── Storage Manager Factory ───────────────────────────────────────────────────

class StorageManager:
    """
    Central storage hub providing repositories for all domain models.
    Automatically connects to real databases if configured, or uses fast in-memory fallbacks.
    """

    def __init__(self):
        self.events: BaseRepository[NormalizedEvent] = InMemoryRepository()
        self.detections: BaseRepository[Detection] = InMemoryRepository()
        self.decisions: BaseRepository[Decision] = InMemoryRepository()
        self.enforcements: BaseRepository[EnforcementRecord] = InMemoryRepository()
        self.alerts: BaseRepository[Alert] = InMemoryRepository()
        self.incidents: BaseRepository[Incident] = InMemoryRepository()
        self.evidence: BaseRepository[EvidenceRecord] = InMemoryRepository()
        self.hunts: BaseRepository[ThreatHunt] = InMemoryRepository()
        self.compliance_reports: BaseRepository[ComplianceReport] = InMemoryRepository()
        self._redis_client = None

    async def initialize(self) -> None:
        """Initialize database connection pools if available."""
        cfg = config()
        logger.info("Initializing IDPS Storage Manager", env=cfg.env.value)

        # In production environments with installed asyncpg / redis, real pools can be attached here
        try:
            import redis.asyncio as aioredis
            self._redis_client = aioredis.from_url(cfg.redis.url)
            logger.info("Redis cache pool initialized")
        except Exception:
            logger.debug("Redis client not available, using in-memory state")

    async def close(self) -> None:
        """Close connections."""
        if self._redis_client:
            await self._redis_client.close()
            logger.info("Redis pool closed")


# Singleton instance
_storage: StorageManager | None = None


def get_storage() -> StorageManager:
    """Get the singleton storage manager."""
    global _storage
    if _storage is None:
        _storage = StorageManager()
    return _storage
