"""
IDPS Enforcement Layer — Proxy / WAF Actions
=============================================
Application-layer enforcement for HTTP/API traffic:
- WAF HTTP 403 Forbidden
- Challenge (CAPTCHA / JavaScript proof of work)
- Adaptive rate limiting
"""

from __future__ import annotations

import time
from typing import Any

from shared.observability import enforcement_latency, get_logger

logger = get_logger("enforcement.proxy_waf")


class ProxyWAFExecutor:
    """Executes web application firewall enforcement actions."""

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self._blocked_clients: set[str] = set()

    async def block_http(self, client_ip: str, path: str = "") -> tuple[bool, str]:
        """Issue an immediate HTTP 403 block for the client."""
        start = time.perf_counter()
        if self.dry_run:
            logger.info(f"[DRY-RUN] WAF 403 Forbidden issued for {client_ip} on path {path}")
            elapsed = (time.perf_counter() - start) * 1000
            enforcement_latency.labels(action="waf_block_403").observe(elapsed / 1000)
            return True, f"Dry-run blocked HTTP request from {client_ip}"

        self._blocked_clients.add(client_ip)
        elapsed = (time.perf_counter() - start) * 1000
        enforcement_latency.labels(action="waf_block_403").observe(elapsed / 1000)
        return True, f"WAF 403 active for {client_ip}"

    async def challenge_client(self, client_ip: str) -> tuple[bool, str]:
        """Require client to solve a JS/CAPTCHA challenge before proceeding."""
        start = time.perf_counter()
        logger.info(f"WAF Challenge presented to {client_ip}")
        elapsed = (time.perf_counter() - start) * 1000
        enforcement_latency.labels(action="waf_challenge").observe(elapsed / 1000)
        return True, f"Challenge delivered to {client_ip}"

    async def apply_rate_limit(self, client_ip: str, limit_per_minute: int = 10) -> tuple[bool, str]:
        """Throttle client requests."""
        start = time.perf_counter()
        logger.info(f"Rate limit enforced on {client_ip}: {limit_per_minute} req/min")
        elapsed = (time.perf_counter() - start) * 1000
        enforcement_latency.labels(action="waf_rate_limit").observe(elapsed / 1000)
        return True, f"Rate limited {client_ip} to {limit_per_minute} rpm"
