"""
IDPS API Routes — Rules
========================
CRUD management for signature and behavioral detection rules.
"""

from __future__ import annotations

from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from shared.auth import User, require_permission, Permission
from services.api.middleware.auth import get_current_user
from services.detection.rule_loader import RuleLoader
from services.detection.engines import SignatureRule

router = APIRouter(prefix="/rules", tags=["Rules"])
loader = RuleLoader()


class RuleCreatePayload(BaseModel):
    rule_id: str
    name: str
    description: str = ""
    severity: str = "medium"
    category: str | None = None
    conditions: dict[str, Any]
    enabled: bool = True


@router.get("")
async def list_rules(current_user: User = Depends(get_current_user)):
    """List all loaded detection rules."""
    require_permission(current_user, Permission.RULES_READ)
    rules = loader.list_rules()
    return [
        {
            "rule_id": r.rule_id,
            "name": r.name,
            "description": r.description,
            "severity": r.severity.value,
            "category": r.category.value if r.category else None,
            "enabled": r.enabled,
            "version": r.version,
            "conditions": r.conditions,
        }
        for r in rules
    ]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_rule(
    payload: RuleCreatePayload,
    current_user: User = Depends(get_current_user),
):
    """Add a new signature detection rule dynamically."""
    require_permission(current_user, Permission.RULES_WRITE)
    rule = loader._parse_rule(payload.model_dump())
    loader._rules[rule.rule_id] = rule
    return {"message": "Rule created successfully", "rule_id": rule.rule_id}


@router.get("/suricata/status")
async def get_suricata_engine_status(current_user: User = Depends(get_current_user)):
    """Probe host for installed Suricata & Snort engines and report actual version/health."""
    from services.detection.suricata_engine import SuricataIntegration
    integration = SuricataIntegration()
    return integration.probe_engine()


class EVEIngestPayload(BaseModel):
    file_path: str


@router.post("/suricata/ingest_eve")
async def ingest_suricata_eve_log(
    payload: EVEIngestPayload,
    current_user: User = Depends(get_current_user),
):
    """Ingest an actual Suricata EVE JSON log file and store resulting events and detections."""
    require_permission(current_user, Permission.EVENTS_INGEST)
    from services.detection.suricata_engine import SuricataIntegration
    from shared.storage import get_storage

    integration = SuricataIntegration()
    records = integration.ingest_eve_file(payload.file_path)
    storage = get_storage()

    saved_events = 0
    saved_detections = 0
    for ev, det in records:
        await storage.events.save(ev)
        saved_events += 1
        if det:
            saved_detections += 1

    return {
        "status": "ingested",
        "file_path": payload.file_path,
        "total_records": len(records),
        "saved_events": saved_events,
        "saved_detections": saved_detections,
    }
