"""
IDPS API — Webhooks
===================
Bi-directional webhooks: Ingest alerts from third-party tools and export IDPS notifications.
"""

from __future__ import annotations

import hmac
import hashlib
from typing import Any
from fastapi import APIRouter, Header, HTTPException, Request, status

from shared.observability import get_logger

logger = get_logger("api.webhooks")
router = APIRouter(prefix="/webhooks", tags=["Webhooks"])


@router.post("/inbound")
async def handle_inbound_webhook(
    request: Request,
    x_signature: str | None = Header(None),
):
    """Receive third-party alerts (e.g. AWS GuardDuty, CrowdStrike, SentinelOne)."""
    body = await request.body()
    logger.info(f"Received inbound webhook: {len(body)} bytes")
    # Parse and normalize into NormalizedEvent in ingestion pipeline
    return {"status": "accepted", "bytes_received": len(body)}
