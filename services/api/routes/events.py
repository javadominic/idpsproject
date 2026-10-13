"""
IDPS API Routes — Events
=========================
Query normalized telemetry events and ingest external events via REST.
"""

from __future__ import annotations

from typing import Any
from fastapi import APIRouter, Depends, Query, status

from shared.auth import User, require_permission, Permission
from shared.models import NormalizedEvent
from shared.storage import get_storage
from services.api.middleware.auth import get_current_user

router = APIRouter(prefix="/events", tags=["Events"])


@router.get("", response_model=list[NormalizedEvent])
async def list_events(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
):
    """Retrieve normalized telemetry events for the tenant."""
    require_permission(current_user, Permission.EVENTS_READ)
    storage = get_storage()
    return await storage.events.list(tenant_id=current_user.tenant_id, limit=limit, offset=offset)


@router.post("", response_model=NormalizedEvent, status_code=status.HTTP_201_CREATED)
async def ingest_event(
    event: NormalizedEvent,
    current_user: User = Depends(get_current_user),
):
    """Ingest a normalized event directly through the REST API."""
    event.tenant_id = current_user.tenant_id
    storage = get_storage()
    await storage.events.save(event)
    return event
