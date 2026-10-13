"""
IDPS Decision Layer — Policy Engine
====================================
Evaluates risk, threat context, and administrative policies to select
appropriate enforcement actions and manage staged rollouts (Shadow/Staged/Enforce).
"""

from __future__ import annotations

from typing import Any

from shared.config import config, EnforcementMode
from shared.models import (
    Decision, Detection, EnforcementAction, EnrichmentResult,
    PolicyMode, Severity, ThreatCategory,
)
from shared.observability import decisions_total, get_logger

logger = get_logger("decision.policy_engine")


class PolicyEngine:
    """Evaluates security policies to determine response actions."""

    def __init__(self, tenant_id: str = "default"):
        self.tenant_id = tenant_id

    def evaluate(
        self,
        detection: Detection,
        enrichment: EnrichmentResult,
        risk_score: float,
        confidence: float,
        severity: Severity,
    ) -> tuple[EnforcementAction, PolicyMode, bool, str]:
        """
        Evaluate policy and determine enforcement action.

        Returns:
            (recommended_action, policy_mode, is_approved, justification)
        """
        cfg = config()

        # Map config mode to model PolicyMode
        mode_map = {
            EnforcementMode.SHADOW: PolicyMode.SHADOW,
            EnforcementMode.STAGED: PolicyMode.STAGED,
            EnforcementMode.ENFORCE: PolicyMode.ENFORCE,
        }
        current_mode = mode_map.get(cfg.enforcement_mode, PolicyMode.SHADOW)

        # 1. Determine ideal action based on threat type and severity
        ideal_action = self._determine_ideal_action(detection, severity, risk_score)

        # 2. Check policy mode
        if current_mode == PolicyMode.SHADOW:
            # Shadow mode: Record ideal action, but do not approve actual blocking
            return (
                ideal_action,
                PolicyMode.SHADOW,
                False,
                f"Shadow mode active: would have applied {ideal_action.value} (Risk {risk_score})",
            )

        if current_mode == PolicyMode.STAGED:
            # Staged mode: Enforce only high confidence and high risk
            if risk_score >= 75.0 and confidence >= 0.80:
                return (
                    ideal_action,
                    PolicyMode.STAGED,
                    True,
                    f"Staged mode threshold met (Risk {risk_score} >= 75, Conf {confidence:.2f} >= 0.80)",
                )
            return (
                EnforcementAction.LOG_ONLY,
                PolicyMode.STAGED,
                False,
                f"Staged mode: Risk {risk_score} or Conf {confidence:.2f} below threshold for auto-enforcement",
            )

        # Full Enforce mode
        if severity in (Severity.HIGH, Severity.CRITICAL) or risk_score >= 50.0:
            return (
                ideal_action,
                PolicyMode.ENFORCE,
                True,
                f"Full enforcement applied: {ideal_action.value} justified by risk {risk_score}",
            )

        return (
            EnforcementAction.LOG_ONLY,
            PolicyMode.ENFORCE,
            False,
            f"Low severity finding; logged without active blocking (Risk {risk_score})",
        )

    def _determine_ideal_action(
        self,
        detection: Detection,
        severity: Severity,
        risk_score: float,
    ) -> EnforcementAction:
        """Select appropriate action based on MITRE tactic and severity."""
        category = detection.category

        if category == ThreatCategory.COMMAND_AND_CONTROL:
            return EnforcementAction.IPS_DROP if risk_score >= 80 else EnforcementAction.FIREWALL_TTL_BLOCK

        if category in (ThreatCategory.EXFILTRATION, ThreatCategory.IMPACT):
            return EnforcementAction.FIREWALL_BLOCK

        if category in (ThreatCategory.EXECUTION, ThreatCategory.PRIVILEGE_ESCALATION):
            if "process" in detection.rule_name.lower():
                return EnforcementAction.HOST_KILL_PROCESS
            return EnforcementAction.HOST_ISOLATE

        if category == ThreatCategory.LATERAL_MOVEMENT:
            return EnforcementAction.HOST_ISOLATE

        if category == ThreatCategory.CREDENTIAL_ACCESS:
            return EnforcementAction.WAF_BLOCK_403 if "http" in detection.rule_name.lower() else EnforcementAction.FIREWALL_TTL_BLOCK

        if severity == Severity.CRITICAL:
            return EnforcementAction.FIREWALL_BLOCK

        return EnforcementAction.LOG_ONLY
