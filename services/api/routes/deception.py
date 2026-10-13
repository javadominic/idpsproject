"""
IDPS API Routes — Deception & Honeypots
=======================================
Manage network honeypots (SSH/HTTP) and generate/track canary tokens.
Tracks actual interactions with zero hardcoded mock hits.
"""

from __future__ import annotations

import socket
from datetime import datetime, timezone
from typing import Any
from fastapi import APIRouter, Depends, status
from pydantic import BaseModel

from shared.auth import User
from services.api.middleware.auth import get_current_user
from services.deception.canary_tokens import CanaryTokenManager

router = APIRouter(prefix="/deception", tags=["Deception"])
canary_mgr = CanaryTokenManager()

# Real list of honeypot hits (starts empty, only appended when real connections occur)
_honeypot_hits: list[dict[str, Any]] = []


class CanaryCreatePayload(BaseModel):
    token_type: str  # "aws" or "url"
    label: str


class HoneypotTriggerPayload(BaseModel):
    service: str
    attacker_ip: str
    attacker_port: int = 0
    payload: str = ""
    credentials: dict[str, str] = {}


def check_port_listening(port: int) -> bool:
    """Check if a local honeypot port is actually listening."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.2)
        result = s.connect_ex(("127.0.0.1", port))
        return result == 0


@router.get("/status")
async def get_deception_status(current_user: User = Depends(get_current_user)):
    """Return status of armed honeypots and canary tokens based on actual state."""
    ssh_listening = check_port_listening(2222)
    http_listening = check_port_listening(8088)

    return {
        "honeypots": [
            {
                "service": "SSH Decoy Server",
                "port": 2222,
                "status": "LISTENING" if ssh_listening else "STANDBY / UNBOUND",
                "protocol": "TCP",
            },
            {
                "service": "HTTP Admin Decoy",
                "port": 8088,
                "status": "LISTENING" if http_listening else "STANDBY / UNBOUND",
                "protocol": "HTTP",
            },
        ],
        "active_canary_tokens": len(canary_mgr._tokens),
        "honeypot_hits_total": len(_honeypot_hits),
    }


@router.get("/hits")
async def get_honeypot_hits(current_user: User = Depends(get_current_user)):
    """Return actual interactions captured by the honeypots."""
    return _honeypot_hits


@router.post("/hits/record")
async def record_honeypot_hit(payload: HoneypotTriggerPayload, current_user: User = Depends(get_current_user)):
    """Record an actual honeypot interaction from the honeypot daemon."""
    hit = {
        "id": f"hit-{len(_honeypot_hits) + 1}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "honeypot_service": payload.service,
        "attacker_ip": payload.attacker_ip,
        "attacker_port": payload.attacker_port,
        "interaction_type": "Unauthorized Honeypot Access",
        "payload": payload.payload,
        "credentials_attempted": payload.credentials,
        "verdict": "CRITICAL DECEPTION ALARM",
    }
    _honeypot_hits.append(hit)
    return hit


@router.get("/canaries")
async def list_canaries(current_user: User = Depends(get_current_user)):
    """List all deployed canary tokens."""
    return [
        {
            "id": token_id,
            "type": meta.get("type"),
            "label": meta.get("label"),
            "created_at": meta.get("created_at").isoformat() if hasattr(meta.get("created_at"), "isoformat") else str(meta.get("created_at")),
            "status": "ARMED",
        }
        for token_id, meta in canary_mgr._tokens.items()
    ]


@router.post("/canary", status_code=status.HTTP_201_CREATED)
async def create_canary_token(payload: CanaryCreatePayload, current_user: User = Depends(get_current_user)):
    """Generate a new canary token."""
    if payload.token_type == "aws":
        token_id, creds = canary_mgr.generate_aws_credentials_token(payload.label)
        return {"token_id": token_id, "type": "aws", "credentials": creds, "label": payload.label}
    else:
        token_id, url = canary_mgr.generate_web_bug_token(payload.label)
        return {"token_id": token_id, "type": "url", "canary_url": url, "label": payload.label}
