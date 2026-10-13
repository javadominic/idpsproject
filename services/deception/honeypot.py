"""
IDPS Deception Service — Honeypot Emulation
============================================
Lightweight honeypot services emulating SSH, Telnet, HTTP, and Redis to lure attackers.
"""

from __future__ import annotations

import asyncio
from typing import Callable, Awaitable

from shared.models import DeceptionEvent
from shared.observability import deception_triggers, get_logger

logger = get_logger("deception.honeypot")


class BaseHoneypot:
    """Base class for network honeypot listeners."""

    def __init__(self, port: int, service_name: str, tenant_id: str = "default"):
        self.port = port
        self.service_name = service_name
        self.tenant_id = tenant_id
        self._server: asyncio.Server | None = None
        self._on_event: Callable[[DeceptionEvent], Awaitable[None]] | None = None

    def set_event_handler(self, handler: Callable[[DeceptionEvent], Awaitable[None]]) -> None:
        self._on_event = handler

    async def start(self) -> None:
        """Start socket listener."""
        try:
            self._server = await asyncio.start_server(self.handle_connection, "0.0.0.0", self.port)
            logger.info(f"Honeypot {self.service_name} listening on port {self.port}")
        except OSError as e:
            logger.warning(f"Could not bind honeypot on port {self.port}: {e} (simulated mode)")

    async def stop(self) -> None:
        """Stop socket listener."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            logger.info(f"Honeypot {self.service_name} stopped")

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle incoming socket connection from attacker."""
        raise NotImplementedError


class SSHHoneypot(BaseHoneypot):
    """Emulates an OpenSSH daemon and logs credential brute-force."""

    def __init__(self, port: int = 2222, tenant_id: str = "default"):
        super().__init__(port, "ssh", tenant_id)

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        addr = writer.get_extra_info("peername")
        attacker_ip = addr[0] if addr else "unknown"
        attacker_port = addr[1] if addr else 0

        logger.warn(f"Honeypot connection detected from {attacker_ip}:{attacker_port} on SSH")

        try:
            # Banner send
            writer.write(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
            await writer.drain()

            # Read client banner/attempt
            data = await asyncio.wait_for(reader.read(1024), timeout=5.0)
            raw_payload = data.decode("utf-8", errors="replace")

            event = DeceptionEvent(
                deception_type="honeypot",
                service_emulated="ssh",
                honeypot_id=f"ssh_{self.port}",
                attacker_ip=attacker_ip,
                attacker_port=attacker_port,
                interaction_type="connection",
                payload=raw_payload[:500],
                tenant_id=self.tenant_id,
            )
            deception_triggers.labels(
                deception_type="honeypot",
                service_emulated="ssh",
                tenant_id=self.tenant_id,
            ).inc()

            if self._on_event:
                await self._on_event(event)

        except Exception as e:
            logger.debug(f"Honeypot connection closed: {e}")
        finally:
            writer.close()
            await writer.wait_closed()


class HTTPHoneypot(BaseHoneypot):
    """Emulates a web admin login or API endpoint."""

    def __init__(self, port: int = 8088, tenant_id: str = "default"):
        super().__init__(port, "http", tenant_id)

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        addr = writer.get_extra_info("peername")
        attacker_ip = addr[0] if addr else "unknown"
        attacker_port = addr[1] if addr else 0

        try:
            data = await asyncio.wait_for(reader.read(2048), timeout=5.0)
            req = data.decode("utf-8", errors="replace")

            # Emulate 401 Unauthorized to encourage credential retry
            response = (
                b"HTTP/1.1 401 Unauthorized\r\n"
                b"Server: Apache/2.4.52 (Ubuntu)\r\n"
                b'WWW-Authenticate: Basic realm="Restricted Admin Panel"\r\n'
                b"Content-Length: 26\r\n\r\n"
                b"401 Unauthorized - Access"
            )
            writer.write(response)
            await writer.drain()

            event = DeceptionEvent(
                deception_type="honeypot",
                service_emulated="http",
                honeypot_id=f"http_{self.port}",
                attacker_ip=attacker_ip,
                attacker_port=attacker_port,
                interaction_type="login_attempt",
                payload=req[:1000],
                tenant_id=self.tenant_id,
            )
            deception_triggers.labels(
                deception_type="honeypot",
                service_emulated="http",
                tenant_id=self.tenant_id,
            ).inc()

            if self._on_event:
                await self._on_event(event)

        except Exception as e:
            logger.debug(f"HTTP Honeypot connection closed: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
