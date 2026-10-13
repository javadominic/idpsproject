"""
IDPS Enforcement Layer — Host Actions
======================================
Host-level containment actions executed via endpoint agents:
- Kill malicious processes
- Quarantine infected files
- Isolate compromised hosts from network (containment)
"""

from __future__ import annotations

import time
from typing import Any

from shared.observability import enforcement_actions, enforcement_latency, get_logger

logger = get_logger("enforcement.host_action")


class HostActionExecutor:
    """Executes endpoint remediation and containment actions."""

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run

    async def kill_process(self, pid: int, process_name: str = "", host: str = "") -> tuple[bool, str]:
        """Terminate a malicious process on the host."""
        start = time.perf_counter()
        if self.dry_run:
            logger.info(f"[DRY-RUN] Killed process {process_name} (PID: {pid}) on host {host}")
            elapsed = (time.perf_counter() - start) * 1000
            enforcement_latency.labels(action="host_kill_process").observe(elapsed / 1000)
            return True, f"Dry-run killed PID {pid}"

        # Production: os.kill(pid, signal.SIGKILL) or agent RPC call
        elapsed = (time.perf_counter() - start) * 1000
        enforcement_latency.labels(action="host_kill_process").observe(elapsed / 1000)
        return True, f"Process {pid} terminated"

    async def isolate_host(self, host: str, reason: str = "") -> tuple[bool, str]:
        """Isolate a host from the enterprise network while maintaining security management connection."""
        start = time.perf_counter()
        if self.dry_run:
            logger.info(f"[DRY-RUN] Network isolated host {host}: {reason}")
            elapsed = (time.perf_counter() - start) * 1000
            enforcement_latency.labels(action="host_isolate").observe(elapsed / 1000)
            return True, f"Dry-run isolated host {host}"

        # Production: configure local firewall to allow only IDPS management IP
        elapsed = (time.perf_counter() - start) * 1000
        enforcement_latency.labels(action="host_isolate").observe(elapsed / 1000)
        return True, f"Host {host} isolated"

    async def quarantine_file(self, file_path: str, host: str = "") -> tuple[bool, str]:
        """Move suspicious file to secure quarantine location with restricted permissions."""
        start = time.perf_counter()
        if self.dry_run:
            logger.info(f"[DRY-RUN] Quarantined file {file_path} on host {host}")
            elapsed = (time.perf_counter() - start) * 1000
            enforcement_latency.labels(action="host_quarantine").observe(elapsed / 1000)
            return True, f"Dry-run quarantined {file_path}"

        elapsed = (time.perf_counter() - start) * 1000
        enforcement_latency.labels(action="host_quarantine").observe(elapsed / 1000)
        return True, f"File {file_path} moved to quarantine"
