"""
IDPS API — Rate Limiting Middleware
====================================
Token bucket in-memory rate limiter per client IP / API Key.
"""

from __future__ import annotations

import time
from collections import defaultdict
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiter middleware enforcing per-client request limits."""

    def __init__(self, app, requests_per_minute: int = 200):
        super().__init__(app)
        self.rpm = requests_per_minute
        self._history: dict[str, list[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        window_start = now - 60.0

        # Clean history
        self._history[client_ip] = [t for t in self._history[client_ip] if t > window_start]

        if len(self._history[client_ip]) >= self.rpm:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded: max {self.rpm} requests per minute",
            )

        self._history[client_ip].append(now)
        return await call_next(request)
