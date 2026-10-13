"""
IDPS Auth & RBAC
================
Role-Based Access Control and multi-tenancy support.
Handles JWT token validation, permission checks, and tenant isolation.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any

import jwt
from pydantic import BaseModel, Field


# ─── Roles & Permissions ────────────────────────────────────────────────────────

class Role(str, Enum):
    """IDPS system roles following least-privilege principle."""
    VIEWER = "viewer"               # Read-only access to dashboards/alerts
    ANALYST = "analyst"             # Investigate, triage, manage alerts
    HUNTER = "hunter"               # Analyst + threat hunting capabilities
    OPERATOR = "operator"           # Manage rules, policies, enforcement
    ADMIN = "admin"                 # Full system administration
    SYSTEM = "system"               # Internal service-to-service


class Permission(str, Enum):
    """Granular permissions for RBAC enforcement."""
    # Events
    EVENTS_READ = "events:read"
    EVENTS_EXPORT = "events:export"
    EVENTS_INGEST = "events:ingest"

    # Detections
    DETECTIONS_READ = "detections:read"
    RULES_READ = "rules:read"
    RULES_WRITE = "rules:write"
    RULES_DELETE = "rules:delete"

    # Decisions
    DECISIONS_READ = "decisions:read"
    POLICIES_READ = "policies:read"
    POLICIES_WRITE = "policies:write"

    # Enforcement
    ENFORCEMENT_READ = "enforcement:read"
    ENFORCEMENT_APPROVE = "enforcement:approve"
    ENFORCEMENT_CONFIG = "enforcement:config"
    ENFORCEMENT_EXECUTE = "enforcement:execute"

    # Alerts & Incidents
    ALERTS_READ = "alerts:read"
    ALERTS_MANAGE = "alerts:manage"
    INCIDENTS_READ = "incidents:read"
    INCIDENTS_MANAGE = "incidents:manage"

    # Forensics
    FORENSICS_READ = "forensics:read"
    FORENSICS_COLLECT = "forensics:collect"
    FORENSICS_EXPORT = "forensics:export"

    # Threat Hunting
    HUNTING_READ = "hunting:read"
    HUNTING_EXECUTE = "hunting:execute"

    # Deception
    DECEPTION_READ = "deception:read"
    DECEPTION_MANAGE = "deception:manage"

    # Compliance
    COMPLIANCE_READ = "compliance:read"
    COMPLIANCE_GENERATE = "compliance:generate"

    # Administration
    USERS_READ = "users:read"
    USERS_MANAGE = "users:manage"
    CONFIG_READ = "config:read"
    CONFIG_WRITE = "config:write"
    TENANTS_MANAGE = "tenants:manage"
    AUDIT_READ = "audit:read"


# Role → Permission mappings
ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.VIEWER: {
        Permission.EVENTS_READ,
        Permission.DETECTIONS_READ,
        Permission.ALERTS_READ,
        Permission.INCIDENTS_READ,
        Permission.COMPLIANCE_READ,
    },
    Role.ANALYST: {
        Permission.EVENTS_READ,
        Permission.EVENTS_EXPORT,
        Permission.DETECTIONS_READ,
        Permission.RULES_READ,
        Permission.DECISIONS_READ,
        Permission.ENFORCEMENT_READ,
        Permission.ALERTS_READ,
        Permission.ALERTS_MANAGE,
        Permission.INCIDENTS_READ,
        Permission.INCIDENTS_MANAGE,
        Permission.FORENSICS_READ,
        Permission.COMPLIANCE_READ,
    },
    Role.HUNTER: {
        Permission.EVENTS_READ,
        Permission.EVENTS_EXPORT,
        Permission.DETECTIONS_READ,
        Permission.RULES_READ,
        Permission.DECISIONS_READ,
        Permission.ENFORCEMENT_READ,
        Permission.ALERTS_READ,
        Permission.ALERTS_MANAGE,
        Permission.INCIDENTS_READ,
        Permission.INCIDENTS_MANAGE,
        Permission.FORENSICS_READ,
        Permission.COMPLIANCE_READ,
        Permission.HUNTING_READ,
        Permission.HUNTING_EXECUTE,
        Permission.FORENSICS_COLLECT,
        Permission.FORENSICS_EXPORT,
        Permission.RULES_WRITE,   # Can create rules from hunt findings
        Permission.DECEPTION_READ,
    },
    Role.OPERATOR: {
        Permission.EVENTS_READ,
        Permission.EVENTS_EXPORT,
        Permission.EVENTS_INGEST,
        Permission.DETECTIONS_READ,
        Permission.RULES_READ,
        Permission.RULES_WRITE,
        Permission.RULES_DELETE,
        Permission.DECISIONS_READ,
        Permission.POLICIES_READ,
        Permission.POLICIES_WRITE,
        Permission.ENFORCEMENT_READ,
        Permission.ENFORCEMENT_APPROVE,
        Permission.ENFORCEMENT_CONFIG,
        Permission.ENFORCEMENT_EXECUTE,
        Permission.ALERTS_READ,
        Permission.ALERTS_MANAGE,
        Permission.INCIDENTS_READ,
        Permission.INCIDENTS_MANAGE,
        Permission.FORENSICS_READ,
        Permission.DECEPTION_READ,
        Permission.DECEPTION_MANAGE,
        Permission.COMPLIANCE_READ,
        Permission.COMPLIANCE_GENERATE,
        Permission.CONFIG_READ,
        Permission.CONFIG_WRITE,
    },
    Role.ADMIN: {p for p in Permission},   # All permissions
    Role.SYSTEM: {p for p in Permission},  # All permissions (internal)
}


# ─── User & Session Models ──────────────────────────────────────────────────────

class User(BaseModel):
    """IDPS system user."""
    id: str
    username: str
    email: str | None = None
    role: Role = Role.VIEWER
    tenant_id: str = "default"
    is_active: bool = True
    mfa_enabled: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_login: datetime | None = None

    @property
    def permissions(self) -> set[Permission]:
        return ROLE_PERMISSIONS.get(self.role, set())

    def has_permission(self, permission: Permission) -> bool:
        return permission in self.permissions


class TokenPayload(BaseModel):
    """JWT token payload."""
    sub: str           # User ID
    username: str
    role: str
    tenant_id: str
    permissions: list[str]
    exp: int           # Expiration timestamp
    iat: int           # Issued at timestamp
    jti: str           # Unique token ID


# ─── JWT Token Management ───────────────────────────────────────────────────────

class JWTManager:
    """
    JWT-based authentication for the API layer.
    Uses HS256 for simplicity; production should use RS256 with key rotation.
    """

    def __init__(self, secret_key: str, algorithm: str = "HS256"):
        self._secret_key = secret_key
        self._algorithm = algorithm
        self._access_token_ttl = timedelta(hours=1)
        self._refresh_token_ttl = timedelta(days=7)
        self._revoked_tokens: set[str] = set()  # In production, use Redis

    def create_access_token(self, user: User) -> str:
        """Create a JWT access token for a user."""
        now = datetime.now(timezone.utc)
        payload = TokenPayload(
            sub=user.id,
            username=user.username,
            role=user.role.value,
            tenant_id=user.tenant_id,
            permissions=[p.value for p in user.permissions],
            exp=int((now + self._access_token_ttl).timestamp()),
            iat=int(now.timestamp()),
            jti=secrets.token_hex(16),
        )
        return jwt.encode(
            payload.model_dump(),
            self._secret_key,
            algorithm=self._algorithm,
        )

    def verify_token(self, token: str) -> TokenPayload | None:
        """Verify and decode a JWT token."""
        try:
            decoded = jwt.decode(
                token,
                self._secret_key,
                algorithms=[self._algorithm],
            )
            payload = TokenPayload(**decoded)

            # Check if token is revoked
            if payload.jti in self._revoked_tokens:
                return None

            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def revoke_token(self, token_id: str) -> None:
        """Revoke a token by its JTI."""
        self._revoked_tokens.add(token_id)


# ─── API Key Management ─────────────────────────────────────────────────────────

class APIKey(BaseModel):
    """API key for programmatic access and service-to-service auth."""
    id: str
    key_hash: str            # SHA-256 hash of the actual key
    name: str
    role: Role
    tenant_id: str = "default"
    is_active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    last_used: datetime | None = None
    rate_limit: int = 1000   # Requests per minute

    @staticmethod
    def generate_key() -> tuple[str, str]:
        """Generate an API key and its hash. Returns (raw_key, key_hash)."""
        raw_key = f"idps_{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        return raw_key, key_hash

    @staticmethod
    def verify_key(raw_key: str, key_hash: str) -> bool:
        """Verify an API key against its stored hash."""
        computed_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        return hmac.compare_digest(computed_hash, key_hash)


# ─── Authorization Helpers ───────────────────────────────────────────────────────

def require_permission(user: User, permission: Permission) -> bool:
    """Check if a user has a required permission. Raises if not."""
    if not user.has_permission(permission):
        raise PermissionError(
            f"User '{user.username}' with role '{user.role.value}' "
            f"does not have permission '{permission.value}'"
        )
    return True


def require_tenant(user: User, resource_tenant_id: str) -> bool:
    """Ensure a user can only access resources in their tenant."""
    if user.role == Role.ADMIN:
        return True  # Admins can access all tenants
    if user.tenant_id != resource_tenant_id:
        raise PermissionError(
            f"User '{user.username}' in tenant '{user.tenant_id}' "
            f"cannot access resources in tenant '{resource_tenant_id}'"
        )
    return True
