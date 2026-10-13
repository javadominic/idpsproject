"""
IDPS API Gateway — Main Application
====================================
FastAPI-based unified REST API and operational control plane.
Exposes full IDPS monitoring, hunting, rules, alerts, and compliance endpoints.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from shared.config import config
from shared.observability import get_logger
from shared.storage import get_storage
from idps_platform.ha.health_check import HealthChecker
from services.api.middleware.rate_limiter import RateLimitMiddleware
from services.api.routes.events import router as events_router
from services.api.routes.alerts import router as alerts_router
from services.api.routes.rules import router as rules_router
from services.api.routes.hunting import router as hunting_router
from services.api.routes.compliance import router as compliance_router
from services.api.webhooks import router as webhooks_router
from services.api.routes.network import router as network_router
from services.api.routes.waf import router as waf_router
from services.api.routes.deception import router as deception_router

logger = get_logger("api.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle hook for starting and stopping background resources."""
    logger.info("Starting IDPS API Gateway...")
    storage = get_storage()
    await storage.initialize()
    yield
    logger.info("Shutting down IDPS API Gateway...")
    await storage.close()


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    cfg = config()

    app = FastAPI(
        title="IDPS — Next-Generation Intrusion Detection & Prevention System",
        description=(
            "Enterprise-grade IDPS API supporting Multi-Engine Detection, "
            "Threat Hunting, Deception Technology, Inline Enforcement, and Compliance Auditing."
        ),
        version="2.0.0",
        lifespan=lifespan,
    )

    # CORS Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.api.cors_origins.split(","),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Rate Limiting
    app.add_middleware(RateLimitMiddleware, requests_per_minute=200)

    # Health Checks
    health_checker = HealthChecker()

    from fastapi.responses import HTMLResponse
    from services.api.dashboard_html import DASHBOARD_HTML

    @app.get("/", response_class=HTMLResponse, tags=["Dashboard"], include_in_schema=False)
    @app.get("/dashboard", response_class=HTMLResponse, tags=["Dashboard"], include_in_schema=False)
    async def dashboard():
        """Interactive IDPS Security Operations Center (SOC) Command Console."""
        return HTMLResponse(content=DASHBOARD_HTML)

    @app.get("/health", tags=["Health"])
    async def health():
        """Liveness & readiness probe."""
        return await health_checker.check_health()

    @app.get("/metrics", tags=["Metrics"])
    async def metrics():
        """Prometheus metrics scrape target."""
        return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

    # Mount API Routers
    api_prefix = "/api/v1"
    app.include_router(events_router, prefix=api_prefix)
    app.include_router(alerts_router, prefix=api_prefix)
    app.include_router(rules_router, prefix=api_prefix)
    app.include_router(hunting_router, prefix=api_prefix)
    app.include_router(compliance_router, prefix=api_prefix)
    app.include_router(webhooks_router, prefix=api_prefix)
    app.include_router(network_router, prefix=api_prefix)
    app.include_router(waf_router, prefix=api_prefix)
    app.include_router(deception_router, prefix=api_prefix)

    return app


app = create_app()
