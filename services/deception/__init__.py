"""
IDPS Deception Service (★ NEW)
==============================
Honeypots, canary tokens, and fake service emulation to detect adversaries with near-zero false positives.
"""

from services.deception.canary_tokens import CanaryTokenManager
from services.deception.honeypot import BaseHoneypot, SSHHoneypot, HTTPHoneypot
from services.deception.decoy_service import DecoyService

__all__ = [
    "CanaryTokenManager",
    "BaseHoneypot",
    "SSHHoneypot",
    "HTTPHoneypot",
    "DecoyService",
]
