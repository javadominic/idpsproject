"""
IDPS Core Data Models
=====================
Pydantic models representing the canonical data structures flowing through
every layer of the IDPS pipeline: Events → Detections → Decisions → Actions → Alerts.

All models include:
- Tenant isolation (tenant_id on every record)
- Immutable audit fields (created_at, source)
- Integrity hashing for forensic chain-of-custody
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import orjson
from pydantic import BaseModel, Field


# ─── Enums ──────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    """Alert/detection severity aligned with CVSS qualitative ratings."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(str, Enum):
    """Source classification for normalized events."""
    NETWORK_PACKET = "network_packet"
    NETWORK_FLOW = "network_flow"
    DNS_QUERY = "dns_query"
    HTTP_REQUEST = "http_request"
    TLS_HANDSHAKE = "tls_handshake"
    HOST_PROCESS = "host_process"
    HOST_FILE = "host_file"
    HOST_REGISTRY = "host_registry"
    HOST_NETWORK = "host_network"
    LOG_ENTRY = "log_entry"
    CLOUD_AUDIT = "cloud_audit"
    IDENTITY_EVENT = "identity_event"
    DECEPTION_TRIGGER = "deception_trigger"
    FILE_ARTIFACT = "file_artifact"


class DetectionMethod(str, Enum):
    """Which detection engine produced the finding."""
    SIGNATURE = "signature"
    PROTOCOL_ANALYSIS = "protocol_analysis"
    BEHAVIORAL = "behavioral"
    ML_HEURISTIC = "ml_heuristic"
    SANDBOX = "sandbox"
    CORRELATION = "correlation"
    DECEPTION = "deception"


class EnforcementAction(str, Enum):
    """Actions the enforcement layer can take."""
    LOG_ONLY = "log_only"           # Shadow mode — record but don't block
    FIREWALL_BLOCK = "firewall_block"
    FIREWALL_TTL_BLOCK = "firewall_ttl_block"
    IPS_DROP = "ips_drop"
    IPS_RESET = "ips_reset"
    IPS_REJECT = "ips_reject"
    HOST_KILL_PROCESS = "host_kill_process"
    HOST_ISOLATE = "host_isolate"
    HOST_QUARANTINE = "host_quarantine"
    WAF_CHALLENGE = "waf_challenge"
    WAF_BLOCK_403 = "waf_block_403"
    WAF_RATE_LIMIT = "waf_rate_limit"
    PROXY_REDIRECT = "proxy_redirect"


class AlertStatus(str, Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"


class IncidentStatus(str, Enum):
    OPEN = "open"
    TRIAGING = "triaging"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    POST_INCIDENT = "post_incident"
    CLOSED = "closed"


class ThreatCategory(str, Enum):
    """MITRE ATT&CK-aligned threat categories."""
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"


class PolicyMode(str, Enum):
    """Policy evaluation modes for staged rollout."""
    SHADOW = "shadow"       # Evaluate but don't enforce
    STAGED = "staged"       # Enforce only above confidence threshold
    ENFORCE = "enforce"     # Full enforcement


# ─── Base Model ─────────────────────────────────────────────────────────────────

class IDPSBaseModel(BaseModel):
    """Base for all IDPS data models with tenant isolation and audit fields."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)

    def integrity_hash(self) -> str:
        """SHA-256 hash of the model for forensic chain-of-custody."""
        data = orjson.dumps(self.model_dump(mode="json"), option=orjson.OPT_SORT_KEYS)
        return hashlib.sha256(data).hexdigest()

    model_config = {"from_attributes": True}


# ─── Sensor Layer: Normalized Event ─────────────────────────────────────────────

class NetworkInfo(BaseModel):
    """Network-layer metadata extracted from packets/flows."""
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None       # tcp, udp, icmp
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    direction: str = "unknown"        # inbound, outbound, lateral


class TLSInfo(BaseModel):
    """TLS handshake metadata (available in metadata mode without MITM)."""
    ja4_hash: str | None = None       # JA4 fingerprint
    ja4s_hash: str | None = None      # JA4 server fingerprint
    sni: str | None = None            # Server Name Indication
    cert_subject: str | None = None
    cert_issuer: str | None = None
    cert_serial: str | None = None
    cert_not_before: datetime | None = None
    cert_not_after: datetime | None = None
    tls_version: str | None = None
    cipher_suite: str | None = None
    is_self_signed: bool = False
    cert_chain_valid: bool = True


class DNSInfo(BaseModel):
    """DNS query/response metadata."""
    query_name: str | None = None
    query_type: str | None = None     # A, AAAA, CNAME, MX, TXT, etc.
    response_code: str | None = None  # NOERROR, NXDOMAIN, SERVFAIL
    resolved_ips: list[str] = Field(default_factory=list)
    ttl: int | None = None
    is_dga_suspect: bool = False      # Domain Generation Algorithm suspect


class ProcessInfo(BaseModel):
    """Host process metadata from eBPF/EDR sensors."""
    pid: int | None = None
    ppid: int | None = None
    name: str | None = None
    command_line: str | None = None
    executable_path: str | None = None
    user: str | None = None
    hash_sha256: str | None = None
    hash_md5: str | None = None
    is_elevated: bool = False
    parent_name: str | None = None


class FileInfo(BaseModel):
    """File metadata from FIM or artifact collection."""
    path: str | None = None
    name: str | None = None
    size_bytes: int | None = None
    hash_sha256: str | None = None
    hash_md5: str | None = None
    hash_ssdeep: str | None = None    # Fuzzy hash for similarity matching
    mime_type: str | None = None
    is_executable: bool = False
    is_packed: bool = False           # Packed/obfuscated binary
    entropy: float | None = None      # High entropy → likely encrypted/packed


class NormalizedEvent(IDPSBaseModel):
    """
    The canonical event format flowing through the entire IDPS pipeline.

    All sensors normalize their output to this format (CEF/JSON-inspired).
    This is the fundamental unit of data in the system.
    """
    event_type: EventType
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_sensor: str = ""           # e.g., "network_sensor_01", "host_agent_dc02"
    hostname: str | None = None
    asset_id: str | None = None       # Link to asset/identity context

    # Contextual data — populated based on event_type
    network: NetworkInfo | None = None
    tls: TLSInfo | None = None
    dns: DNSInfo | None = None
    process: ProcessInfo | None = None
    file: FileInfo | None = None

    # Raw data reference
    raw_log: str | None = None
    raw_payload_ref: str | None = None  # S3/object-store ref for PCAP/binary

    # Enrichment (populated by decision layer)
    geo_src: dict[str, Any] | None = None
    geo_dst: dict[str, Any] | None = None
    threat_intel_matches: list[dict[str, Any]] = Field(default_factory=list)
    asset_context: dict[str, Any] | None = None

    # Deception flag
    is_deception_trigger: bool = False


# ─── Detection Layer: Detection Result ──────────────────────────────────────────

class MITREMapping(BaseModel):
    """MITRE ATT&CK mapping for a detection."""
    tactic: str                       # e.g., "Lateral Movement"
    tactic_id: str                    # e.g., "TA0008"
    technique: str                    # e.g., "Remote Services"
    technique_id: str                 # e.g., "T1021"
    sub_technique: str | None = None  # e.g., "SMB/Windows Admin Shares"
    sub_technique_id: str | None = None  # e.g., "T1021.002"


class Detection(IDPSBaseModel):
    """
    Output from any detection engine.
    Multiple detections may correlate to a single alert.
    """
    event_id: str                     # The NormalizedEvent that triggered this
    detection_method: DetectionMethod
    rule_id: str | None = None        # Signature rule ID or ML model ID
    rule_name: str | None = None
    rule_version: str | None = None

    severity: Severity = Severity.MEDIUM
    confidence: float = 0.5           # 0.0–1.0 confidence score
    category: ThreatCategory | None = None
    mitre: MITREMapping | None = None

    description: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)

    # For sandbox results
    sandbox_verdict: str | None = None       # clean | suspicious | malicious
    sandbox_report_ref: str | None = None    # Reference to full sandbox report

    # Correlation
    related_event_ids: list[str] = Field(default_factory=list)
    correlation_group_id: str | None = None


# ─── Decision Layer: Decision Result ────────────────────────────────────────────

class EnrichmentResult(BaseModel):
    """Result of enriching a detection with external context."""
    threat_intel_score: float = 0.0   # 0.0–1.0 from threat feeds
    asset_criticality: str = "normal"  # low, normal, high, critical
    asset_owner: str | None = None
    known_iocs_matched: list[str] = Field(default_factory=list)
    geo_risk: str = "normal"          # normal, elevated, high-risk
    historical_alerts: int = 0        # Past alerts for this src/dst
    user_risk_score: float = 0.0      # UEBA user risk


class Decision(IDPSBaseModel):
    """
    The decision layer's output: whether to enforce, what action to take,
    and the policy justification.
    """
    detection_id: str
    event_id: str

    # Risk assessment
    risk_score: float = 0.0           # 0.0–100.0 composite risk
    confidence: float = 0.5           # Adjusted confidence after enrichment
    severity: Severity = Severity.MEDIUM

    # Policy evaluation
    policy_mode: PolicyMode = PolicyMode.SHADOW
    recommended_action: EnforcementAction = EnforcementAction.LOG_ONLY
    policy_id: str | None = None
    policy_justification: str = ""

    # Enrichment data
    enrichment: EnrichmentResult = Field(default_factory=EnrichmentResult)

    # Is this decision approved for enforcement?
    approved: bool = False
    approved_by: str = "system"       # "system" | "analyst:{username}"
    approved_at: datetime | None = None


# ─── Enforcement Layer: Action Record ───────────────────────────────────────────

class EnforcementRecord(IDPSBaseModel):
    """
    Immutable audit log of every enforcement action taken.
    Required for compliance (PCI-DSS 10.6, SOC2 CC7.2).
    """
    decision_id: str
    detection_id: str
    event_id: str

    action: EnforcementAction
    action_target: str = ""           # IP, hostname, process PID, URL
    action_details: dict[str, Any] = Field(default_factory=dict)

    success: bool = False
    failure_reason: str | None = None
    execution_time_ms: float = 0.0

    # Fail-mode tracking
    was_fail_mode_active: bool = False
    fail_mode_decision: str | None = None  # "fail-open" | "fail-closed"

    # Rollback info
    is_reversible: bool = False
    rollback_action: str | None = None
    ttl_seconds: int | None = None    # Auto-expire the block after TTL


# ─── Alert Layer: Alert & Incident ──────────────────────────────────────────────

class Alert(IDPSBaseModel):
    """
    SOC-facing alert combining one or more detections with enrichment context.
    """
    title: str
    description: str = ""
    severity: Severity = Severity.MEDIUM
    status: AlertStatus = AlertStatus.NEW

    # Linked objects
    detection_ids: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    enforcement_ids: list[str] = Field(default_factory=list)
    incident_id: str | None = None

    # Triage info
    assigned_to: str | None = None
    priority: int = 3                 # 1 (P1 Critical) – 5 (P5 Info)
    source_ips: list[str] = Field(default_factory=list)
    destination_ips: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)

    # MITRE mapping
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)

    # Kill chain position
    kill_chain_phase: str | None = None

    # Response tracking
    acknowledged_at: datetime | None = None
    resolved_at: datetime | None = None
    resolution_notes: str | None = None
    is_false_positive: bool = False


class Incident(IDPSBaseModel):
    """
    An incident groups multiple related alerts into a single case.
    Tracks the full incident response lifecycle.
    """
    title: str
    description: str = ""
    severity: Severity = Severity.HIGH
    status: IncidentStatus = IncidentStatus.OPEN

    # Linked alerts
    alert_ids: list[str] = Field(default_factory=list)

    # Incident response
    lead_analyst: str | None = None
    team_members: list[str] = Field(default_factory=list)
    playbook_id: str | None = None

    # Timeline
    detected_at: datetime | None = None
    contained_at: datetime | None = None
    eradicated_at: datetime | None = None
    recovered_at: datetime | None = None
    closed_at: datetime | None = None

    # Impact assessment
    affected_systems: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    data_compromised: bool = False
    business_impact: str = "unknown"

    # Post-incident
    root_cause: str | None = None
    lessons_learned: str | None = None
    action_items: list[dict[str, Any]] = Field(default_factory=list)


# ─── Forensics: Evidence Record ─────────────────────────────────────────────────

class EvidenceRecord(IDPSBaseModel):
    """
    Chain-of-custody record for forensic evidence preservation.
    Every evidence item is hashed for integrity verification.
    """
    incident_id: str
    alert_id: str | None = None

    # Evidence details
    evidence_type: str                # pcap, log, memory_dump, disk_image, screenshot
    description: str = ""
    storage_ref: str = ""             # S3/object-store path
    original_path: str | None = None
    size_bytes: int = 0

    # Integrity
    hash_sha256: str = ""
    hash_md5: str = ""
    collected_by: str = ""            # system | analyst:{username}
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Chain of custody
    custody_chain: list[dict[str, Any]] = Field(default_factory=list)
    # Each entry: {"action": "collected|transferred|analyzed", "by": "...", "at": "...", "notes": "..."}

    is_verified: bool = False         # Hash verified against original


# ─── Threat Hunting: Hunt Record ────────────────────────────────────────────────

class ThreatHunt(IDPSBaseModel):
    """Proactive threat hunting session record."""
    title: str
    hypothesis: str                   # What we're looking for and why
    methodology: str = ""             # How we're hunting
    status: str = "active"            # active | completed | archived
    analyst: str = ""

    # Scope
    data_sources: list[str] = Field(default_factory=list)
    time_range_start: datetime | None = None
    time_range_end: datetime | None = None
    query: str | None = None          # The search/query used

    # Results
    findings: list[dict[str, Any]] = Field(default_factory=list)
    detections_created: list[str] = Field(default_factory=list)  # New rules created
    alerts_generated: list[str] = Field(default_factory=list)

    # Outcome
    conclusion: str | None = None
    mitre_coverage_gaps: list[str] = Field(default_factory=list)  # ATT&CK gaps found


# ─── Compliance: Compliance Record ──────────────────────────────────────────────

class ComplianceCheck(BaseModel):
    """Individual compliance check result."""
    control_id: str           # e.g., "PCI-DSS-10.6.1"
    control_name: str
    framework: str            # pci-dss, hipaa, soc2, gdpr
    status: str               # pass | fail | partial | not_applicable
    evidence: str = ""
    remediation: str | None = None
    last_checked: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ComplianceReport(IDPSBaseModel):
    """Aggregated compliance report."""
    framework: str
    report_period_start: datetime
    report_period_end: datetime
    overall_score: float = 0.0        # 0.0–100.0 compliance percentage
    checks: list[ComplianceCheck] = Field(default_factory=list)
    total_controls: int = 0
    passing_controls: int = 0
    failing_controls: int = 0
    generated_by: str = "system"


# ─── Deception: Deception Event ─────────────────────────────────────────────────

class DeceptionEvent(IDPSBaseModel):
    """
    High-fidelity alert from deception technology.
    Any interaction with a honeypot/canary is suspicious by definition.
    """
    deception_type: str               # honeypot | canary_token | decoy_service
    service_emulated: str = ""        # ssh, http, smb, etc.
    honeypot_id: str = ""
    canary_token_id: str | None = None

    # Attacker info
    attacker_ip: str = ""
    attacker_port: int | None = None
    interaction_type: str = ""        # connection | login_attempt | file_access | token_triggered
    credentials_used: dict[str, str] = Field(default_factory=dict)  # username/password attempted
    payload: str | None = None        # Raw payload captured

    # Auto-generated event for the detection pipeline
    generated_event_id: str | None = None
