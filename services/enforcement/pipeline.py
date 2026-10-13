"""
IDPS Enforcement Pipeline
==========================
Orchestrates active enforcement actions across firewalls, inline IPS, host agents, and WAFs.
Consumes approved decisions from the Decision Layer and produces EnforcementRecords.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from shared.config import config
from shared.messaging import MessageBus, Topic, MessageEnvelope, deserialize_message
from shared.models import Decision, EnforcementAction, EnforcementRecord
from shared.observability import enforcement_actions, pipeline_throughput, get_logger
from services.enforcement.actions.firewall import FirewallActionExecutor
from services.enforcement.actions.inline_ips import InlineIPSExecutor
from services.enforcement.actions.host_action import HostActionExecutor
from services.enforcement.actions.proxy_waf import ProxyWAFExecutor
from services.enforcement.fail_mode import FailModeController
from services.enforcement.audit_logger import EnforcementAuditLogger

logger = get_logger("enforcement.pipeline")


class EnforcementPipeline:
    """Main enforcement orchestrator."""

    def __init__(self, bus: MessageBus, tenant_id: str = "default"):
        self.bus = bus
        self.tenant_id = tenant_id

        cfg = config()
        dry_run = cfg.enforcement_dry_run

        self.firewall = FirewallActionExecutor(dry_run=dry_run)
        self.inline_ips = InlineIPSExecutor(dry_run=dry_run)
        self.host_action = HostActionExecutor(dry_run=dry_run)
        self.proxy_waf = ProxyWAFExecutor(dry_run=dry_run)

        self.fail_mode = FailModeController(tenant_id=tenant_id)
        self.audit_logger = EnforcementAuditLogger(bus=bus)
        self._running = False

    async def start(self) -> None:
        """Subscribe to approved action decisions."""
        self._running = True
        logger.info("Starting Enforcement Pipeline...")
        await self.bus.subscribe(
            Topic.APPROVED_ACTIONS,
            self.handle_action_message,
            group_id="idps-enforcement-group",
        )
        logger.info("Enforcement Pipeline running and listening for approved actions")

    async def stop(self) -> None:
        """Stop enforcement pipeline."""
        self._running = False
        logger.info("Enforcement Pipeline stopped")

    async def handle_action_message(self, envelope: MessageEnvelope) -> None:
        """Process an approved action message."""
        try:
            decision = deserialize_message(envelope.payload, Decision)
            await self.execute_decision(decision)
        except Exception as e:
            logger.error(f"Error handling decision in enforcement pipeline: {e}")

    async def execute_decision(self, decision: Decision) -> EnforcementRecord:
        """Execute the recommended enforcement action."""
        start = time.perf_counter()
        action = decision.recommended_action
        success = False
        reason = ""
        target = ""

        # Check Fail-Mode
        if self.fail_mode.is_fail_mode_active:
            fallback = self.fail_mode.get_fallback_action()
            logger.warn(f"Executing under fail-mode: {fallback}")
            if fallback == "allow_traffic":
                record = EnforcementRecord(
                    decision_id=decision.id,
                    detection_id=decision.detection_id,
                    event_id=decision.event_id,
                    action=EnforcementAction.LOG_ONLY,
                    action_target="all",
                    success=True,
                    failure_reason="Fail-Open bypass active",
                    was_fail_mode_active=True,
                    fail_mode_decision="fail-open",
                    tenant_id=decision.tenant_id,
                )
                await self.audit_logger.log_action(record)
                return record

        try:
            # Dispatch to appropriate action handler
            if action in (EnforcementAction.FIREWALL_BLOCK, EnforcementAction.FIREWALL_TTL_BLOCK):
                target = decision.metadata.get("target_ip") or decision.metadata.get("src_ip", "0.0.0.0")
                ttl = 3600 if action == EnforcementAction.FIREWALL_TTL_BLOCK else None
                success, reason = await self.firewall.block_ip(target, ttl_seconds=ttl, reason=decision.policy_justification)

            elif action == EnforcementAction.IPS_DROP:
                target = decision.metadata.get("flow_id", "flow-default")
                src_ip = decision.metadata.get("src_ip", "0.0.0.0")
                dst_ip = decision.metadata.get("dst_ip", "0.0.0.0")
                success, reason = await self.inline_ips.drop(target, src_ip, dst_ip)

            elif action == EnforcementAction.IPS_RESET:
                target = decision.metadata.get("src_ip", "0.0.0.0")
                success, reason = await self.inline_ips.reset(target, "0.0.0.0", 0, 0)

            elif action == EnforcementAction.HOST_KILL_PROCESS:
                pid = int(decision.metadata.get("pid", 0))
                target = f"pid:{pid}"
                success, reason = await self.host_action.kill_process(pid, host=decision.metadata.get("host", ""))

            elif action == EnforcementAction.HOST_ISOLATE:
                target = decision.metadata.get("host", "unknown-host")
                success, reason = await self.host_action.isolate_host(target, reason=decision.policy_justification)

            elif action == EnforcementAction.HOST_QUARANTINE:
                target = decision.metadata.get("file_path", "")
                success, reason = await self.host_action.quarantine_file(target)

            elif action == EnforcementAction.WAF_BLOCK_403:
                target = decision.metadata.get("client_ip", "0.0.0.0")
                success, reason = await self.proxy_waf.block_http(target)

            elif action == EnforcementAction.WAF_CHALLENGE:
                target = decision.metadata.get("client_ip", "0.0.0.0")
                success, reason = await self.proxy_waf.challenge_client(target)

            elif action == EnforcementAction.WAF_RATE_LIMIT:
                target = decision.metadata.get("client_ip", "0.0.0.0")
                success, reason = await self.proxy_waf.apply_rate_limit(target)

            else:
                # LOG_ONLY
                target = "event_log"
                success = True
                reason = "Logged without active blocking"

            self.fail_mode.record_success()

        except Exception as e:
            logger.error(f"Action execution failure: {e}")
            success = False
            reason = str(e)
            self.fail_mode.record_failure(str(e))

        elapsed_ms = (time.perf_counter() - start) * 1000

        record = EnforcementRecord(
            decision_id=decision.id,
            detection_id=decision.detection_id,
            event_id=decision.event_id,
            action=action,
            action_target=target,
            success=success,
            failure_reason=reason if not success else None,
            execution_time_ms=elapsed_ms,
            was_fail_mode_active=self.fail_mode.is_fail_mode_active,
            tenant_id=decision.tenant_id,
        )

        # 1. Log immutable audit trail
        await self.audit_logger.log_action(record)

        # 2. Publish results to ENFORCEMENT_RESULTS
        await self.bus.publish(
            Topic.ENFORCEMENT_RESULTS,
            record,
            key=record.decision_id,
            headers={"action": action.value, "success": str(success)},
        )
        enforcement_actions.labels(
            action=action.value,
            success=str(success).lower(),
            tenant_id=record.tenant_id,
        ).inc()
        pipeline_throughput.labels(layer="enforcement").inc()

        return record
