"""
IDPS Decision Layer — Risk Scorer
==================================
Computes a composite risk score (0.0–100.0) combining detection severity,
detection confidence, threat intelligence signals, and asset criticality.
"""

from __future__ import annotations

from shared.models import Detection, EnrichmentResult, Severity
from shared.observability import risk_score_distribution, get_logger

logger = get_logger("decision.risk_scorer")


class RiskScorer:
    """Calculates unified risk scores for detections."""

    SEVERITY_BASE_SCORES = {
        Severity.INFO: 10.0,
        Severity.LOW: 25.0,
        Severity.MEDIUM: 50.0,
        Severity.HIGH: 75.0,
        Severity.CRITICAL: 90.0,
    }

    ASSET_MULTIPLIERS = {
        "critical": 1.35,
        "high": 1.20,
        "normal": 1.0,
        "low": 0.8,
    }

    def calculate_risk(
        self,
        detection: Detection,
        enrichment: EnrichmentResult,
    ) -> tuple[float, float, Severity]:
        """
        Calculate composite risk score.

        Returns:
            (risk_score, adjusted_confidence, adjusted_severity)
        """
        base_score = self.SEVERITY_BASE_SCORES.get(detection.severity, 50.0)
        confidence = detection.confidence

        # 1. Base weighted by confidence
        score = base_score * (0.5 + 0.5 * confidence)

        # 2. Threat Intel boost
        if enrichment.threat_intel_score > 0:
            score += enrichment.threat_intel_score * 25.0
            confidence = min(0.99, confidence + (enrichment.threat_intel_score * 0.2))

        # 3. Known IOC matches
        if enrichment.known_iocs_matched:
            score += 10.0

        # 4. Asset criticality multiplier
        multiplier = self.ASSET_MULTIPLIERS.get(enrichment.asset_criticality, 1.0)
        score *= multiplier

        # 5. Geo-risk boost
        if enrichment.geo_risk == "high-risk":
            score += 10.0

        # Cap between 0 and 100
        final_score = max(0.0, min(100.0, score))

        # Determine adjusted severity based on composite score
        if final_score >= 85.0:
            adjusted_sev = Severity.CRITICAL
        elif final_score >= 65.0:
            adjusted_sev = Severity.HIGH
        elif final_score >= 40.0:
            adjusted_sev = Severity.MEDIUM
        elif final_score >= 20.0:
            adjusted_sev = Severity.LOW
        else:
            adjusted_sev = Severity.INFO

        risk_score_distribution.labels(severity=adjusted_sev.value).observe(final_score)
        return round(final_score, 2), round(confidence, 3), adjusted_sev
