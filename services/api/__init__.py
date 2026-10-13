"""
IDPS API Service
================
FastAPI Gateway and control plane.
"""

from services.api.main import app, create_app

__all__ = ["app", "create_app"]
