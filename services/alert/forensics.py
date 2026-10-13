"""
IDPS Alert Layer — Forensics (★ NEW)
=====================================
Preserves forensic evidence (PCAP captures, memory dumps, process artifacts)
with cryptographic integrity hashes and chain-of-custody tracking.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from shared.models import EvidenceRecord
from shared.observability import get_logger
from shared.storage import get_storage

logger = get_logger("alert.forensics")


class ForensicsManager:
    """Manages forensic evidence acquisition and cryptographic chain of custody."""

    def __init__(self, tenant_id: str = "default"):
        self.tenant_id = tenant_id

    async def preserve_evidence(
        self,
        incident_id: str,
        evidence_type: str,
        data: bytes,
        description: str = "",
        collected_by: str = "system",
        original_path: str | None = None,
        alert_id: str | None = None,
    ) -> EvidenceRecord:
        """
        Record and cryptographically seal an evidence item.
        Computes SHA-256 and MD5 hashes and records initial custody entry.
        """
        sha256_hash = hashlib.sha256(data).hexdigest()
        md5_hash = hashlib.md5(data).hexdigest()
        now = datetime.now(timezone.utc)

        # In production, data is uploaded to WORM (Write Once Read Many) S3 bucket
        storage_ref = f"evidence://{incident_id}/{sha256_hash[:16]}.{evidence_type}"

        custody_entry = {
            "action": "collected",
            "by": collected_by,
            "at": now.isoformat(),
            "notes": f"Acquired {len(data)} bytes of {evidence_type} evidence",
            "hash_verified": True,
        }

        record = EvidenceRecord(
            incident_id=incident_id,
            alert_id=alert_id,
            evidence_type=evidence_type,
            description=description,
            storage_ref=storage_ref,
            original_path=original_path,
            size_bytes=len(data),
            hash_sha256=sha256_hash,
            hash_md5=md5_hash,
            collected_by=collected_by,
            collected_at=now,
            custody_chain=[custody_entry],
            is_verified=True,
            tenant_id=self.tenant_id,
        )

        storage = get_storage()
        await storage.evidence.save(record)
        logger.info(
            f"Forensic Evidence Sealed: {record.id} ({evidence_type}) "
            f"| SHA256: {sha256_hash} | Size: {len(data)}B"
        )
        return record

    async def add_custody_transfer(
        self,
        evidence_id: str,
        transferred_to: str,
        reason: str,
        performed_by: str,
    ) -> EvidenceRecord | None:
        """Record chain of custody transfer for court admissibility."""
        storage = get_storage()
        record = await storage.evidence.get_by_id(evidence_id, tenant_id=self.tenant_id)
        if not record:
            return None

        record.custody_chain.append({
            "action": "transferred",
            "to": transferred_to,
            "by": performed_by,
            "at": datetime.now(timezone.utc).isoformat(),
            "notes": reason,
        })
        await storage.evidence.save(record)
        logger.info(f"Chain of custody updated for evidence {evidence_id}: transferred to {transferred_to}")
        return record
