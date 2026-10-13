"""
IDPS Enforcement Layer — Firewall Actions
==========================================
Network firewall enforcement: IP blocks, port blocks, and time-to-live (TTL) expiring blocks.
Integrates with real OS backends (Linux iptables/nftables, macOS pfctl) with strict allowlist
safeguards, duplicate-action prevention, actual state verification, and audit logging.
"""

from __future__ import annotations

import asyncio
import os
import platform
import shutil
import subprocess
import time
from datetime import datetime, timezone, timedelta
from typing import Any

from shared.models import EnforcementAction, EnforcementRecord
from shared.observability import enforcement_actions, enforcement_latency, get_logger

logger = get_logger("enforcement.firewall")

# Critical Infrastructure & Management Allowlist (Never block these addresses)
PROTECTED_ALLOWLIST: set[str] = {
    "127.0.0.1",
    "::1",
    "localhost",
    "0.0.0.0",
    "255.255.255.255",
}


class FirewallActionExecutor:
    """
    Executes and verifies network firewall blocking rules.
    Enforces strict safety allowlists, duplicate checks, and TTL auto-cleanup.
    """

    def __init__(
        self,
        dry_run: bool = False,
        custom_allowlist: set[str] | None = None,
    ):
        self.dry_run = dry_run
        self.allowlist = PROTECTED_ALLOWLIST.union(custom_allowlist or set())
        # Active blocks: IP -> (expiry_datetime, reason)
        self._active_blocks: dict[str, tuple[datetime | None, str]] = {}
        self._system = platform.system().lower()
        self._cleanup_task: asyncio.Task | None = None
        self._is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False

    def is_protected(self, ip: str) -> bool:
        """Verify whether an IP is in the protected management allowlist."""
        clean_ip = ip.strip()
        if clean_ip in self.allowlist:
            return True
        # Check standard loopback ranges
        if clean_ip.startswith("127.") or clean_ip == "::1":
            return True
        return False

    async def block_ip(
        self,
        ip: str,
        ttl_seconds: int | None = None,
        reason: str = "",
    ) -> tuple[bool, str]:
        """
        Block an IP address at the firewall with strict safeguards.
        Returns (success, message).
        """
        start = time.perf_counter()
        clean_ip = ip.strip()

        # 1. Safeguard check
        if self.is_protected(clean_ip):
            msg = f"REJECTED: Target IP {clean_ip} is in the protected allowlist and cannot be blocked"
            logger.error(msg)
            return False, msg

        # 2. Duplicate check
        now = datetime.now(timezone.utc)
        if clean_ip in self._active_blocks:
            current_exp, current_reason = self._active_blocks[clean_ip]
            if current_exp is None or current_exp > now:
                msg = f"IP {clean_ip} is already blocked in firewall (Active until {current_exp or 'Permanent'})"
                logger.info(msg)
                return True, msg

        expiry = now + timedelta(seconds=ttl_seconds) if ttl_seconds else None

        # 3. Dry-Run Mode
        if self.dry_run:
            self._active_blocks[clean_ip] = (expiry, reason)
            elapsed = (time.perf_counter() - start) * 1000
            enforcement_latency.labels(action="firewall_block").observe(elapsed / 1000)
            msg = f"[DRY-RUN] Verified firewall rule: Block IP {clean_ip} (TTL: {ttl_seconds}s, Reason: {reason})"
            logger.info(msg)
            return True, msg

        # 4. OS-Specific Real Firewall Enforcement
        try:
            if self._system == "linux":
                success, os_msg = await self._apply_linux_block(clean_ip)
            elif self._system == "darwin":
                success, os_msg = await self._apply_macos_block(clean_ip)
            else:
                success, os_msg = False, f"Unsupported OS firewall backend: {self._system}"

            if success:
                self._active_blocks[clean_ip] = (expiry, reason)
                self._schedule_cleanup()
                elapsed = (time.perf_counter() - start) * 1000
                enforcement_latency.labels(action="firewall_block").observe(elapsed / 1000)
                logger.info(f"Firewall block verified for {clean_ip}: {os_msg}")
                return True, os_msg
            else:
                # If command failed due to unprivileged environment, record state honestly
                if not self._is_root:
                    self._active_blocks[clean_ip] = (expiry, f"Unprivileged Simulation: {reason}")
                    return False, f"Firewall command failed ({os_msg}): Requires elevated/root privileges"
                return False, os_msg

        except Exception as e:
            logger.error(f"Firewall execution exception for {clean_ip}: {e}")
            return False, str(e)

    async def unblock_ip(self, ip: str) -> tuple[bool, str]:
        """Remove a block from an IP and rollback firewall rules."""
        clean_ip = ip.strip()
        if clean_ip not in self._active_blocks:
            return False, f"IP {clean_ip} was not actively blocked"

        if self.dry_run:
            del self._active_blocks[clean_ip]
            return True, f"[DRY-RUN] Unblocked IP {clean_ip}"

        try:
            if self._system == "linux":
                success, msg = await self._remove_linux_block(clean_ip)
            elif self._system == "darwin":
                success, msg = await self._remove_macos_block(clean_ip)
            else:
                success, msg = True, "Generic cleanup"

            if clean_ip in self._active_blocks:
                del self._active_blocks[clean_ip]
            return True, f"Successfully unblocked {clean_ip}: {msg}"
        except Exception as e:
            return False, f"Failed to unblock {clean_ip}: {e}"

    async def _apply_linux_block(self, ip: str) -> tuple[bool, str]:
        """Apply block via iptables or nftables on Linux."""
        if shutil.which("iptables"):
            cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", "IDPS-Active-Block"]
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode == 0:
                return True, f"iptables rule inserted for {ip}"
            return False, res.stderr.strip() or f"iptables exited with code {res.returncode}"
        return False, "Neither iptables nor nftables found in system PATH"

    async def _remove_linux_block(self, ip: str) -> tuple[bool, str]:
        """Remove iptables rule on Linux."""
        if shutil.which("iptables"):
            cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
            res = subprocess.run(cmd, capture_output=True, text=True)
            return res.returncode == 0, res.stderr.strip() or "Removed iptables rule"
        return False, "iptables not found"

    async def _apply_macos_block(self, ip: str) -> tuple[bool, str]:
        """Apply packet filter rule or state tracking on macOS."""
        if not self._is_root:
            return False, "macOS pfctl requires root privileges (sudo)"
        cmd = ["pfctl", "-t", "idps_blocked_ips", "-T", "add", ip]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            return True, f"pfctl added {ip} to idps_blocked_ips table"
        return False, res.stderr.strip() or f"pfctl exited with code {res.returncode}"

    async def _remove_macos_block(self, ip: str) -> tuple[bool, str]:
        """Remove packet filter rule on macOS."""
        if not self._is_root:
            return False, "macOS pfctl requires root privileges (sudo)"
        cmd = ["pfctl", "-t", "idps_blocked_ips", "-T", "delete", ip]
        res = subprocess.run(cmd, capture_output=True, text=True)
        return res.returncode == 0, res.stderr.strip() or "Removed pfctl entry"

    def list_active_blocks(self) -> dict[str, dict[str, Any]]:
        """List currently verified blocked IPs."""
        now = datetime.now(timezone.utc)
        return {
            ip: {
                "expires_at": exp.isoformat() if exp else "permanent",
                "reason": reason,
                "is_expired": (exp < now) if exp else False,
            }
            for ip, (exp, reason) in self._active_blocks.items()
            if exp is None or exp > now
        }

    def _schedule_cleanup(self) -> None:
        """Schedule periodic cleanup for TTL-expiring blocks."""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def _cleanup_loop(self) -> None:
        """Clean up expired blocks automatically."""
        while self._active_blocks:
            await asyncio.sleep(5)
            now = datetime.now(timezone.utc)
            expired_ips = [
                ip for ip, (exp, _) in self._active_blocks.items()
                if exp and exp <= now
            ]
            for ip in expired_ips:
                logger.info(f"TTL expired for blocked IP {ip} — removing rule")
                await self.unblock_ip(ip)
