"""
IDPS API Routes — Threat Hunting (★ NEW)
=========================================
Create, execute, and inspect proactive threat hunting sessions.
"""

from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from shared.auth import User, require_permission, Permission
from shared.models import ThreatHunt
from shared.storage import get_storage
from services.api.middleware.auth import get_current_user
from services.decision.threat_hunter import ThreatHunter

router = APIRouter(prefix="/hunting", tags=["Threat Hunting"])


class HuntCreatePayload(BaseModel):
    title: str
    hypothesis: str
    methodology: str = ""
    query: str = ""
    time_range_hours: int = 24


@router.get("", response_model=list[ThreatHunt])
async def list_hunts(
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
):
    """List historical and active threat hunting sessions."""
    require_permission(current_user, Permission.HUNTING_READ)
    storage = get_storage()
    return await storage.hunts.list(tenant_id=current_user.tenant_id, limit=limit)


@router.post("", response_model=ThreatHunt, status_code=status.HTTP_201_CREATED)
async def create_and_run_hunt(
    payload: HuntCreatePayload,
    current_user: User = Depends(get_current_user),
):
    """Launch a hypothesis-driven automated threat hunting session."""
    require_permission(current_user, Permission.HUNTING_EXECUTE)
    hunter = ThreatHunter(tenant_id=current_user.tenant_id)
    hunt = await hunter.create_hunt(
        title=payload.title,
        hypothesis=payload.hypothesis,
        methodology=payload.methodology,
        query=payload.query,
        analyst=current_user.username,
        time_range_hours=payload.time_range_hours,
    )
    # Execute immediately
    executed_hunt = await hunter.execute_hunt(hunt.id)
    return executed_hunt
