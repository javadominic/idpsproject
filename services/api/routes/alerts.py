"""
IDPS API Routes — Alerts & Incidents
====================================
Manage SOC alerts, perform triage updates, and inspect incident cases.
"""

from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from shared.auth import User, require_permission, Permission
from shared.models import Alert, AlertStatus, Incident, IncidentStatus
from shared.storage import get_storage
from services.api.middleware.auth import get_current_user
from services.alert.alert_manager import AlertManager
from services.alert.incident_manager import IncidentManager

router = APIRouter(prefix="/alerts", tags=["Alerts"])


class AlertUpdatePayload(BaseModel):
    status: AlertStatus
    assigned_to: Optional[str] = None
    notes: Optional[str] = None


@router.get("", response_model=list[Alert])
async def list_alerts(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
):
    """List security alerts for the current tenant."""
    require_permission(current_user, Permission.ALERTS_READ)
    storage = get_storage()
    return await storage.alerts.list(tenant_id=current_user.tenant_id, limit=limit, offset=offset)


@router.get("/{alert_id}", response_model=Alert)
async def get_alert(
    alert_id: str,
    current_user: User = Depends(get_current_user),
):
    """Get single alert details."""
    require_permission(current_user, Permission.ALERTS_READ)
    storage = get_storage()
    alert = await storage.alerts.get_by_id(alert_id, tenant_id=current_user.tenant_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/{alert_id}", response_model=Alert)
async def update_alert(
    alert_id: str,
    payload: AlertUpdatePayload,
    current_user: User = Depends(get_current_user),
):
    """Triage or update alert status (acknowledge, investigate, resolve)."""
    require_permission(current_user, Permission.ALERTS_MANAGE)
    mgr = AlertManager(tenant_id=current_user.tenant_id)
    updated = await mgr.update_status(
        alert_id=alert_id,
        new_status=payload.status,
        assigned_to=payload.assigned_to,
        notes=payload.notes,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Alert not found")
    return updated


@router.get("/incidents/all", response_model=list[Incident])
async def list_incidents(
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
):
    """List security incidents."""
    require_permission(current_user, Permission.INCIDENTS_READ)
    storage = get_storage()
    return await storage.incidents.list(tenant_id=current_user.tenant_id, limit=limit)
