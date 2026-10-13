"""
IDPS Alert & Response Service
==============================
SOC-facing alert management, SOAR playbooks, SIEM forwarding, and forensic evidence preservation.
"""

from services.alert.alert_manager import AlertManager
from services.alert.forensics import ForensicsManager
from services.alert.incident_manager import IncidentManager
from services.alert.notification import NotificationDispatcher
from services.alert.siem_integration import SIEMForwarder
from services.alert.soar_engine import SOAREngine
from services.alert.pipeline import AlertPipeline

__all__ = [
    "AlertManager",
    "ForensicsManager",
    "IncidentManager",
    "NotificationDispatcher",
    "SIEMForwarder",
    "SOAREngine",
    "AlertPipeline",
]
