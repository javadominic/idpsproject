"""
IDPS Decision Layer — Enrichment
=================================
Enriches detections with external Threat Intelligence feeds, Asset Criticality,
GeoIP risk metrics, and identity/UEBA context.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from shared.models import Detection, EnrichmentResult, NormalizedEvent
from shared.observability import get_logger

logger = get_logger("decision.enrichment")


class ThreatIntelEnricher:
    """Enriches detections with Threat Intelligence and Asset data."""

    def __init__(self):
        # Known IOC databases (in production, populated via STIX/TAXII or MISP feeds)
        self._malicious_ips: dict[str, dict[str, Any]] = {
            "198.51.100.23": {"score": 0.95, "actor": "APT29", "category": "C2"},
            "203.0.113.50": {"score": 0.85, "actor": "Lazarus", "category": "Phishing"},
            "192.0.2.100": {"score": 0.75, "actor": "FIN7", "category": "Scanner"},
        }
        self._malicious_domains: dict[str, dict[str, Any]] = {
            "malware-c2.example.com": {"score": 0.98, "campaign": "Emotet"},
            "evil-dns.org": {"score": 0.90, "campaign": "DGA"},
        }
        self._high_risk_countries: set[str] = {"XX", "T1"}  # Mock high risk codes

        # Asset inventory (CMDB / Active Directory mock)
        self._critical_assets: dict[str, dict[str, Any]] = {
            "dc01.corp.internal": {"criticality": "critical", "owner": "secops", "env": "prod"},
            "db-prod-01": {"criticality": "critical", "owner": "dba", "env": "prod"},
            "pci-gw-01": {"criticality": "critical", "owner": "compliance", "env": "pci"},
        }

    async def enrich(self, detection: Detection, event: NormalizedEvent | None = None) -> EnrichmentResult:
        """Enrich detection context."""
        result = EnrichmentResult()
        matched_iocs: list[str] = []
        max_ti_score = 0.0

        # Extract indicators from detection evidence and event
        evidence = detection.evidence or {}
        ip_candidates = []
        if "src_ip" in evidence:
            ip_candidates.append(evidence["src_ip"])
        if "dst_ip" in evidence:
            ip_candidates.append(evidence["dst_ip"])
        if event and event.network:
            if event.network.src_ip:
                ip_candidates.append(event.network.src_ip)
            if event.network.dst_ip:
                ip_candidates.append(event.network.dst_ip)

        # Check IP threat intelligence
        for ip in ip_candidates:
            if ip in self._malicious_ips:
                ti_info = self._malicious_ips[ip]
                score = ti_info["score"]
                max_ti_score = max(max_ti_score, score)
                matched_iocs.append(f"IP:{ip} ({ti_info.get('actor', 'Malicious')})")

        # Check domain threat intelligence
        domain = evidence.get("domain") or (event.dns.query_name if event and event.dns else None)
        if domain and domain in self._malicious_domains:
            ti_info = self._malicious_domains[domain]
            score = ti_info["score"]
            max_ti_score = max(max_ti_score, score)
            matched_iocs.append(f"Domain:{domain} ({ti_info.get('campaign', 'Threat')})")

        # Check asset criticality
        hostname = event.hostname if event else None
        if not hostname:
            hostname = evidence.get("host") or evidence.get("hostname")

        if hostname and hostname in self._critical_assets:
            asset = self._critical_assets[hostname]
            result.asset_criticality = asset.get("criticality", "critical")
            result.asset_owner = asset.get("owner")
        elif any(kw in str(hostname).lower() for kw in ("dc", "prod", "vault", "pci", "auth")):
            result.asset_criticality = "high"

        # Geo-risk
        if event and event.geo_src:
            country = event.geo_src.get("country_code", "")
            if country in self._high_risk_countries:
                result.geo_risk = "high-risk"

        result.threat_intel_score = max_ti_score
        result.known_iocs_matched = matched_iocs
        return result
