"""
IDPS API Routes — Compliance (★ NEW)
=====================================
Generate and view compliance audit reports for PCI-DSS, SOC2, HIPAA, and GDPR.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, status

from shared.auth import User, require_permission, Permission
from shared.models import ComplianceReport
from shared.storage import get_storage
from services.api.middleware.auth import get_current_user
from idps_platform.compliance.reporter import ComplianceEngine

router = APIRouter(prefix="/compliance", tags=["Compliance"])


@router.get("", response_model=list[ComplianceReport])
async def list_reports(
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
):
    """List historical compliance reports."""
    require_permission(current_user, Permission.COMPLIANCE_READ)
    storage = get_storage()
    return await storage.compliance_reports.list(tenant_id=current_user.tenant_id, limit=limit)


@router.post("/generate", response_model=ComplianceReport, status_code=status.HTTP_201_CREATED)
async def generate_compliance_report(
    framework: str = Query("pci-dss", pattern="^(pci-dss|pci_dss|soc2|hipaa|gdpr)$"),
    current_user: User = Depends(get_current_user),
):
    """Run real-time compliance evaluation and generate report."""
    require_permission(current_user, Permission.COMPLIANCE_GENERATE)
    normalized_framework = framework.replace("_", "-")
    engine = ComplianceEngine(tenant_id=current_user.tenant_id)
    return await engine.generate_report(framework=normalized_framework)
