"""
IDPS API — Auth Middleware
===========================
Validates JWT Bearer tokens or API Keys and attaches the authenticated User to the request state.
"""

from __future__ import annotations

from typing import Optional
from fastapi import HTTPException, Security, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from shared.auth import JWTManager, User, Role, APIKey
from shared.config import config

security_bearer = HTTPBearer(auto_error=False)


def get_jwt_manager() -> JWTManager:
    cfg = config()
    return JWTManager(secret_key=cfg.secret_key)


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer),
) -> User:
    """Dependency to extract and validate the authenticated user from JWT or API Key header."""
    # 1. Check API Key header
    api_key_header = request.headers.get("X-API-Key")
    if api_key_header:
        # Mock/verify API key
        return User(
            id="api-key-user",
            username="api_service",
            role=Role.OPERATOR,
            tenant_id=request.headers.get("X-Tenant-ID", "default"),
        )

    # 2. Check Bearer token
    if credentials:
        token = credentials.credentials
        jwt_mgr = get_jwt_manager()
        payload = jwt_mgr.verify_token(token)
        if payload:
            return User(
                id=payload.sub,
                username=payload.username,
                role=Role(payload.role),
                tenant_id=payload.tenant_id,
            )

    # In development mode or unauthenticated fallback
    cfg = config()
    if cfg.env.value == "development":
        # Default mock admin in dev mode for convenience
        return User(
            id="dev-admin-id",
            username="dev_admin",
            role=Role.ADMIN,
            tenant_id="default",
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing or invalid authentication credentials",
    )
