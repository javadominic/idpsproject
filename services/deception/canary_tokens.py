"""
IDPS Deception Service — Canary Tokens
=======================================
Generates and tracks canary tokens (fake AWS keys, credentials, URLs, documents).
Any access to or use of a canary token indicates attacker reconnaissance or credential harvesting.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timezone
from typing import Any

from shared.models import DeceptionEvent
from shared.observability import deception_triggers, get_logger

logger = get_logger("deception.canary_tokens")


class CanaryTokenManager:
    """Manages creation, deployment, and trigger verification of canary tokens."""

    def __init__(self, tenant_id: str = "default"):
        self.tenant_id = tenant_id
        # Token ID -> token metadata
        self._tokens: dict[str, dict[str, Any]] = {}

    def generate_web_bug_token(self, label: str = "Confidential_PDF") -> tuple[str, str]:
        """
        Generate a Canary Web URL token.
        Returns: (token_id, url)
        """
        token_id = str(uuid.uuid4())
        token_key = secrets.token_urlsafe(16)
        url = f"http://idps-canary.internal/t/{token_id}/{token_key}"

        self._tokens[token_id] = {
            "type": "canary_url",
            "label": label,
            "created_at": datetime.now(timezone.utc),
            "key": token_key,
        }
        logger.info(f"Canary web token created: {label} ({token_id})")
        return token_id, url

    def generate_aws_credentials_token(self, label: str = "Prod_Backup_User") -> tuple[str, dict[str, str]]:
        """
        Generate fake AWS credentials canary.
        Returns: (token_id, credentials_dict)
        """
        token_id = str(uuid.uuid4())
        access_key = f"AKIA{secrets.token_hex(8).upper()}"
        secret_key = secrets.token_urlsafe(32)

        self._tokens[token_id] = {
            "type": "aws_credential",
            "label": label,
            "created_at": datetime.now(timezone.utc),
            "access_key": access_key,
        }
        logger.info(f"Canary AWS credential created: {label} ({token_id})")
        return token_id, {
            "aws_access_key_id": access_key,
            "aws_secret_access_key": secret_key,
            "region": "us-east-1",
        }

    def trigger_token(
        self,
        token_id: str,
        attacker_ip: str,
        interaction_type: str = "token_triggered",
        payload: str | None = None,
    ) -> DeceptionEvent | None:
        """Trigger an alert when a canary token is accessed."""
        token = self._tokens.get(token_id)
        if not token:
            logger.warning(f"Unknown canary token accessed: {token_id}")
            return None

        event = DeceptionEvent(
            deception_type="canary_token",
            service_emulated=token["type"],
            canary_token_id=token_id,
            attacker_ip=attacker_ip,
            interaction_type=interaction_type,
            payload=payload or f"Canary token '{token.get('label')}' triggered",
            tenant_id=self.tenant_id,
        )
        deception_triggers.labels(
            deception_type="canary_token",
            service_emulated=token["type"],
            tenant_id=self.tenant_id,
        ).inc()
        logger.warn(f"CANARY TRIGGERED! Token {token.get('label')} accessed by {attacker_ip}")
        return event
