"""
IDPS Detection Service
======================
Analysis and correlation of normalized events to identify threats.

Engines:
- Signature Engine (Rules, Suricata-compatible)
- Protocol/TLS Analyzer (JA4, DNS, HTTP analysis)
- Behavior Analyzer (Beacon detection, scan detection, anomaly)
- ML/Heuristics Engine (UEBA, anomaly detection, ML models)
- Sandbox Engine (★ NEW: Dynamic analysis / file detonation)

Correlation:
- Cross-engine correlation
- Kill-chain progression analysis
- Deception taint elevation
"""

from services.detection.engines import (
    BaseDetectionEngine,
    SignatureEngine,
    SignatureRule,
    ProtocolAnalyzer,
    BehaviorAnalyzer,
    MLEngine,
    SandboxEngine,
)
from services.detection.correlation import CorrelationEngine
from services.detection.rule_loader import RuleLoader
from services.detection.pipeline import DetectionPipeline

__all__ = [
    "BaseDetectionEngine",
    "SignatureEngine",
    "SignatureRule",
    "ProtocolAnalyzer",
    "BehaviorAnalyzer",
    "MLEngine",
    "SandboxEngine",
    "CorrelationEngine",
    "RuleLoader",
    "DetectionPipeline",
]
