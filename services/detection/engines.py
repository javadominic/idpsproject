"""
IDPS Detection Engines
======================
All five detection engines for the Detection Layer.
Each engine processes NormalizedEvents and produces Detections.

Latency requirements:
- Signature Engine: < 1ms (inline path)
- Protocol Analyzer: < 5ms (inline path)
- Behavior Analyzer: < 50ms (async OK)
- ML Engine: < 100ms (async, non-blocking)
- Sandbox Engine: async only (30s–120s per file)
"""

from __future__ import annotations

import asyncio
import hashlib
import math
import re
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any

from shared.models import (
    NormalizedEvent, Detection, DetectionMethod, Severity,
    EventType, ThreatCategory, MITREMapping,
)
from shared.observability import (
    detections_total, detection_latency, active_rules,
    sandbox_submissions, sandbox_analysis_time, get_logger,
)

logger = get_logger("detection.engines")


# ─── Base Detection Engine ───────────────────────────────────────────────────────

class BaseDetectionEngine(ABC):
    """Base class for all detection engines."""

    def __init__(self, engine_id: str, tenant_id: str = "default"):
        self.engine_id = engine_id
        self.tenant_id = tenant_id
        self._enabled = True

    @property
    @abstractmethod
    def method(self) -> DetectionMethod:
        """The detection method this engine implements."""
        ...

    @property
    @abstractmethod
    def max_latency_ms(self) -> float:
        """Maximum allowed latency for this engine (-1 = async only)."""
        ...

    @abstractmethod
    async def analyze(self, event: NormalizedEvent) -> list[Detection]:
        """Analyze an event and return zero or more detections."""
        ...

    async def start(self) -> None:
        """Initialize the engine (load models, rules, etc.)."""
        logger.info(f"Engine started: {self.engine_id}")

    async def stop(self) -> None:
        """Shut down the engine."""
        logger.info(f"Engine stopped: {self.engine_id}")


# ═══════════════════════════════════════════════════════════════════════════════
# ENGINE 1: Signature Engine
# ═══════════════════════════════════════════════════════════════════════════════

class SignatureRule:
    """A single detection rule (Suricata/Snort-compatible concept)."""

    def __init__(
        self,
        rule_id: str,
        name: str,
        description: str = "",
        severity: Severity = Severity.MEDIUM,
        category: ThreatCategory | None = None,
        mitre: MITREMapping | None = None,
        conditions: dict[str, Any] | None = None,
        enabled: bool = True,
        version: str = "1.0",
    ):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.severity = severity
        self.category = category
        self.mitre = mitre
        self.conditions = conditions or {}
        self.enabled = enabled
        self.version = version
        self._compiled_patterns: dict[str, re.Pattern] = {}

        # Pre-compile regex patterns for performance
        for key, value in self.conditions.items():
            if key.endswith("_regex"):
                self._compiled_patterns[key] = re.compile(value, re.IGNORECASE)

    def matches(self, event: NormalizedEvent) -> bool:
        """Check if an event matches this rule's conditions."""
        if not self.enabled:
            return False

        for key, expected in self.conditions.items():
            actual = self._get_event_field(event, key)

            if key.endswith("_regex"):
                pattern = self._compiled_patterns.get(key)
                if pattern and actual:
                    if not pattern.search(str(actual)):
                        return False
                elif pattern and not actual:
                    return False
            elif key.endswith("_in"):
                if actual not in expected:
                    return False
            elif key.endswith("_gt"):
                if actual is None or actual <= expected:
                    return False
            elif key.endswith("_lt"):
                if actual is None or actual >= expected:
                    return False
            elif key == "event_type":
                if event.event_type.value != expected:
                    return False
            else:
                if actual != expected:
                    return False

        return True

    def _get_event_field(self, event: NormalizedEvent, field_path: str) -> Any:
        """Extract a field from the event using dot notation."""
        # Strip comparison suffixes
        clean_path = field_path
        for suffix in ("_regex", "_in", "_gt", "_lt"):
            if clean_path.endswith(suffix):
                clean_path = clean_path[: -len(suffix)]
                break

        parts = clean_path.split(".")
        obj: Any = event
        for part in parts:
            if obj is None:
                return None
            if isinstance(obj, dict):
                obj = obj.get(part)
            elif hasattr(obj, part):
                obj = getattr(obj, part)
            else:
                return None
        return obj


class SignatureEngine(BaseDetectionEngine):
    """
    Rule-based signature detection engine.

    Matches events against a library of detection rules using
    field conditions, regex patterns, and IOC lookups.

    Performance target: < 1ms per event (inline path critical).
    """

    def __init__(self, engine_id: str = "signature_engine", tenant_id: str = "default"):
        super().__init__(engine_id, tenant_id)
        self._rules: list[SignatureRule] = []
        self._rules_by_event_type: dict[str, list[SignatureRule]] = defaultdict(list)

    @property
    def method(self) -> DetectionMethod:
        return DetectionMethod.SIGNATURE

    @property
    def max_latency_ms(self) -> float:
        return 1.0

    async def start(self) -> None:
        """Load signature rules."""
        await super().start()
        self._load_default_rules()
        active_rules.labels(engine="signature").set(len(self._rules))

    def add_rule(self, rule: SignatureRule) -> None:
        """Add a detection rule."""
        self._rules.append(rule)
        # Index by event type for faster lookup
        event_type = rule.conditions.get("event_type", "any")
        self._rules_by_event_type[event_type].append(rule)
        self._rules_by_event_type["any"].append(rule)

    async def analyze(self, event: NormalizedEvent) -> list[Detection]:
        """Match event against all applicable rules."""
        start = time.perf_counter()
        detections: list[Detection] = []

        # Get rules for this event type + generic rules
        applicable_rules = self._rules_by_event_type.get(event.event_type.value, [])
        applicable_rules += self._rules_by_event_type.get("any", [])

        # Deduplicate
        seen_ids: set[str] = set()
        for rule in applicable_rules:
            if rule.rule_id in seen_ids:
                continue
            seen_ids.add(rule.rule_id)

            try:
                if rule.matches(event):
                    detection = Detection(
                        event_id=event.id,
                        detection_method=self.method,
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        rule_version=rule.version,
                        severity=rule.severity,
                        confidence=0.9,  # Signatures are high-confidence
                        category=rule.category,
                        mitre=rule.mitre,
                        description=rule.description,
                        tenant_id=self.tenant_id,
                    )
                    detections.append(detection)
            except Exception as e:
                logger.error(f"Rule match error: {rule.rule_id}: {e}")

        elapsed = (time.perf_counter() - start) * 1000
        detection_latency.labels(engine="signature").observe(elapsed / 1000)

        for d in detections:
            detections_total.labels(
                engine="signature",
                severity=d.severity.value,
                tenant_id=self.tenant_id,
            ).inc()

        return detections

    def _load_default_rules(self) -> None:
        """Load built-in detection rules."""
        default_rules = [
            SignatureRule(
                rule_id="SIG-001",
                name="SSH Brute Force Attempt",
                description="Multiple failed SSH login attempts from single source",
                severity=Severity.HIGH,
                category=ThreatCategory.CREDENTIAL_ACCESS,
                mitre=MITREMapping(
                    tactic="Credential Access", tactic_id="TA0006",
                    technique="Brute Force", technique_id="T1110",
                    sub_technique="Password Guessing", sub_technique_id="T1110.001",
                ),
                conditions={
                    "event_type": "host_process",
                    "process.name": "sshd",
                    "metadata.action_regex": r"(?i)failed|invalid|denied",
                },
            ),
            SignatureRule(
                rule_id="SIG-002",
                name="Suspicious PowerShell Execution",
                description="PowerShell with encoded command or suspicious flags",
                severity=Severity.HIGH,
                category=ThreatCategory.EXECUTION,
                mitre=MITREMapping(
                    tactic="Execution", tactic_id="TA0002",
                    technique="Command and Scripting Interpreter", technique_id="T1059",
                    sub_technique="PowerShell", sub_technique_id="T1059.001",
                ),
                conditions={
                    "event_type": "host_process",
                    "process.command_line_regex": r"(?i)(encodedcommand|bypass|hidden|noprofile|-enc\s|-e\s|-ec\s)",
                },
            ),
            SignatureRule(
                rule_id="SIG-003",
                name="Known Malicious Domain Access",
                description="DNS query to known malicious domain",
                severity=Severity.CRITICAL,
                category=ThreatCategory.COMMAND_AND_CONTROL,
                mitre=MITREMapping(
                    tactic="Command and Control", tactic_id="TA0011",
                    technique="Application Layer Protocol", technique_id="T1071",
                    sub_technique="DNS", sub_technique_id="T1071.004",
                ),
                conditions={
                    "event_type": "dns_query",
                    "dns.query_name_regex": r"(?i)\.(evil|malware|c2server)\.(com|net|org|xyz)$",
                },
            ),
            SignatureRule(
                rule_id="SIG-004",
                name="Self-Signed TLS Certificate",
                description="Connection using self-signed TLS certificate",
                severity=Severity.MEDIUM,
                category=ThreatCategory.DEFENSE_EVASION,
                conditions={
                    "event_type": "tls_handshake",
                    "tls.is_self_signed": True,
                },
            ),
            SignatureRule(
                rule_id="SIG-005",
                name="Large DNS TXT Response",
                description="DNS TXT response that may indicate data exfiltration",
                severity=Severity.MEDIUM,
                category=ThreatCategory.EXFILTRATION,
                mitre=MITREMapping(
                    tactic="Exfiltration", tactic_id="TA0010",
                    technique="Exfiltration Over Alternative Protocol", technique_id="T1048",
                ),
                conditions={
                    "event_type": "dns_query",
                    "dns.query_type": "TXT",
                },
            ),
            SignatureRule(
                rule_id="SIG-006",
                name="Suspicious File in Temp Directory",
                description="Executable file created in temporary directory",
                severity=Severity.HIGH,
                category=ThreatCategory.EXECUTION,
                conditions={
                    "event_type": "host_file",
                    "file.path_regex": r"(?i)(\\temp\\|/tmp/|\\appdata\\local\\temp)",
                    "file.is_executable": True,
                },
            ),
            SignatureRule(
                rule_id="SIG-007",
                name="High Entropy File Detected",
                description="File with suspiciously high entropy (likely packed/encrypted)",
                severity=Severity.MEDIUM,
                category=ThreatCategory.DEFENSE_EVASION,
                conditions={
                    "event_type": "file_artifact",
                    "file.entropy_gt": 7.5,
                    "file.is_executable": True,
                },
            ),
            SignatureRule(
                rule_id="SIG-008",
                name="Deception Trigger — Honeypot Interaction",
                description="Attacker interacted with a honeypot/canary",
                severity=Severity.CRITICAL,
                category=ThreatCategory.DISCOVERY,
                conditions={
                    "event_type": "deception_trigger",
                    "is_deception_trigger": True,
                },
            ),
        ]

        for rule in default_rules:
            self.add_rule(rule)

        logger.info(f"Loaded {len(default_rules)} default signature rules")


# ═══════════════════════════════════════════════════════════════════════════════
# ENGINE 2: Protocol/TLS Analyzer
# ═══════════════════════════════════════════════════════════════════════════════

class ProtocolAnalyzer(BaseDetectionEngine):
    """
    Protocol analysis engine for deep inspection of network protocols.

    Capabilities:
    - JA4/JA4S TLS fingerprint matching against known-bad signatures
    - DNS anomaly detection (DGA, tunneling, fast-flux)
    - HTTP anomaly detection (unusual methods, headers, paths)
    - Protocol violations and RFC non-compliance

    TLS Inspection Strategy:
    - METADATA mode: JA4 fingerprinting, SNI, cert analysis (no decryption)
    - INTERCEPT mode: Full MITM TLS interception (inline only)
    - HYBRID mode: Metadata by default, intercept flagged flows
    """

    def __init__(
        self,
        engine_id: str = "protocol_analyzer",
        tls_mode: str = "metadata",
        tenant_id: str = "default",
    ):
        super().__init__(engine_id, tenant_id)
        self.tls_mode = tls_mode

        # Known-bad JA4 fingerprints (malware families)
        self._malicious_ja4: dict[str, str] = {}
        # Known-bad DNS patterns
        self._dga_consonant_threshold = 0.7
        self._dns_tunnel_length_threshold = 52
        # Known suspicious HTTP patterns
        self._suspicious_user_agents: list[re.Pattern] = []
        self._suspicious_paths: list[re.Pattern] = []

    @property
    def method(self) -> DetectionMethod:
        return DetectionMethod.PROTOCOL_ANALYSIS

    @property
    def max_latency_ms(self) -> float:
        return 5.0

    async def start(self) -> None:
        """Load protocol analysis databases."""
        await super().start()
        self._load_ja4_database()
        self._load_suspicious_patterns()

    async def analyze(self, event: NormalizedEvent) -> list[Detection]:
        """Analyze protocol-level indicators."""
        start = time.perf_counter()
        detections: list[Detection] = []

        if event.event_type == EventType.TLS_HANDSHAKE and event.tls:
            detections.extend(self._analyze_tls(event))

        elif event.event_type == EventType.DNS_QUERY and event.dns:
            detections.extend(self._analyze_dns(event))

        elif event.event_type == EventType.HTTP_REQUEST:
            detections.extend(self._analyze_http(event))

        elapsed = (time.perf_counter() - start) * 1000
        detection_latency.labels(engine="protocol").observe(elapsed / 1000)

        return detections

    def _analyze_tls(self, event: NormalizedEvent) -> list[Detection]:
        """Analyze TLS handshake metadata."""
        detections: list[Detection] = []
        tls = event.tls
        if not tls:
            return detections

        # Check JA4 against known-bad fingerprints
        if tls.ja4_hash and tls.ja4_hash in self._malicious_ja4:
            malware_family = self._malicious_ja4[tls.ja4_hash]
            detections.append(Detection(
                event_id=event.id,
                detection_method=self.method,
                rule_id="PROTO-TLS-001",
                rule_name=f"Known Malicious JA4: {malware_family}",
                severity=Severity.CRITICAL,
                confidence=0.95,
                category=ThreatCategory.COMMAND_AND_CONTROL,
                description=f"TLS fingerprint matches known malware family: {malware_family}",
                evidence={"ja4_hash": tls.ja4_hash, "malware_family": malware_family},
                tenant_id=self.tenant_id,
            ))

        # Self-signed cert to external IP
        if tls.is_self_signed and event.network:
            detections.append(Detection(
                event_id=event.id,
                detection_method=self.method,
                rule_id="PROTO-TLS-002",
                rule_name="Self-Signed Certificate to External Host",
                severity=Severity.MEDIUM,
                confidence=0.6,
                category=ThreatCategory.COMMAND_AND_CONTROL,
                description="Connection using self-signed certificate",
                evidence={"sni": tls.sni, "cert_subject": tls.cert_subject},
                tenant_id=self.tenant_id,
            ))

        # Expired certificate
        if tls.cert_not_after and tls.cert_not_after < datetime.now(timezone.utc):
            detections.append(Detection(
                event_id=event.id,
                detection_method=self.method,
                rule_id="PROTO-TLS-003",
                rule_name="Expired TLS Certificate",
                severity=Severity.LOW,
                confidence=0.8,
                description="Connection to host with expired TLS certificate",
                evidence={"cert_not_after": str(tls.cert_not_after)},
                tenant_id=self.tenant_id,
            ))

        # Weak TLS version
        if tls.tls_version and tls.tls_version in ("SSLv3", "TLSv1.0", "TLSv1.1"):
            detections.append(Detection(
                event_id=event.id,
                detection_method=self.method,
                rule_id="PROTO-TLS-004",
                rule_name="Weak TLS Version",
                severity=Severity.MEDIUM,
                confidence=0.9,
                category=ThreatCategory.DEFENSE_EVASION,
                description=f"Connection using deprecated TLS version: {tls.tls_version}",
                tenant_id=self.tenant_id,
            ))

        return detections

    def _analyze_dns(self, event: NormalizedEvent) -> list[Detection]:
        """Analyze DNS queries for anomalies."""
        detections: list[Detection] = []
        dns = event.dns
        if not dns or not dns.query_name:
            return detections

        domain = dns.query_name

        # DGA Detection — high consonant ratio in subdomain labels
        labels = domain.split(".")
        if len(labels) >= 3:
            subdomain = labels[0]
            if len(subdomain) > 8:
                consonants = sum(1 for c in subdomain.lower() if c in "bcdfghjklmnpqrstvwxyz")
                ratio = consonants / len(subdomain) if subdomain else 0
                if ratio > self._dga_consonant_threshold:
                    dns.is_dga_suspect = True
                    detections.append(Detection(
                        event_id=event.id,
                        detection_method=self.method,
                        rule_id="PROTO-DNS-001",
                        rule_name="Possible DGA Domain",
                        severity=Severity.HIGH,
                        confidence=0.7,
                        category=ThreatCategory.COMMAND_AND_CONTROL,
                        mitre=MITREMapping(
                            tactic="Command and Control", tactic_id="TA0011",
                            technique="Dynamic Resolution", technique_id="T1568",
                            sub_technique="Domain Generation Algorithms",
                            sub_technique_id="T1568.002",
                        ),
                        description=f"Domain '{domain}' has DGA-like characteristics",
                        evidence={"domain": domain, "consonant_ratio": ratio},
                        tenant_id=self.tenant_id,
                    ))

        # DNS Tunneling — unusually long subdomain labels
        for label in labels[:-2]:  # Exclude TLD and SLD
            if len(label) > self._dns_tunnel_length_threshold:
                detections.append(Detection(
                    event_id=event.id,
                    detection_method=self.method,
                    rule_id="PROTO-DNS-002",
                    rule_name="Possible DNS Tunneling",
                    severity=Severity.HIGH,
                    confidence=0.75,
                    category=ThreatCategory.EXFILTRATION,
                    mitre=MITREMapping(
                        tactic="Command and Control", tactic_id="TA0011",
                        technique="Application Layer Protocol", technique_id="T1071",
                        sub_technique="DNS", sub_technique_id="T1071.004",
                    ),
                    description=f"DNS label '{label[:20]}...' exceeds tunnel threshold ({len(label)} chars)",
                    evidence={"domain": domain, "label_length": len(label)},
                    tenant_id=self.tenant_id,
                ))

        # NXDOMAIN flood (DGA side-effect)
        if dns.response_code == "NXDOMAIN":
            detections.append(Detection(
                event_id=event.id,
                detection_method=self.method,
                rule_id="PROTO-DNS-003",
                rule_name="NXDOMAIN Response",
                severity=Severity.LOW,
                confidence=0.3,  # Low confidence alone, needs correlation
                category=ThreatCategory.COMMAND_AND_CONTROL,
                description=f"NXDOMAIN for domain: {domain}",
                evidence={"domain": domain},
                tenant_id=self.tenant_id,
            ))

        return detections

    def _analyze_http(self, event: NormalizedEvent) -> list[Detection]:
        """Analyze HTTP request patterns."""
        # HTTP analysis would check for SQL injection, XSS, path traversal, etc.
        return []

    def _load_ja4_database(self) -> None:
        """Load known-bad JA4 fingerprints."""
        # In production, load from threat intel feeds
        self._malicious_ja4 = {
            "a]b]c]d]e]f]": "Cobalt Strike",
            "x]y]z]1]2]3]": "Metasploit",
        }
        logger.info(f"Loaded {len(self._malicious_ja4)} malicious JA4 fingerprints")

    def _load_suspicious_patterns(self) -> None:
        """Load suspicious HTTP/protocol patterns."""
        self._suspicious_user_agents = [
            re.compile(r"(?i)python-requests"),
            re.compile(r"(?i)curl/"),
            re.compile(r"(?i)wget/"),
        ]


# ═══════════════════════════════════════════════════════════════════════════════
# ENGINE 3: Behavior Analyzer
# ═══════════════════════════════════════════════════════════════════════════════

class BehaviorAnalyzer(BaseDetectionEngine):
    """
    Behavioral analysis engine for detecting patterns over time.

    Detects:
    - C2 beaconing (periodic callbacks)
    - Network scanning (port scans, host sweeps)
    - Data exfiltration patterns (large outbound transfers)
    - Lateral movement patterns
    - Brute force attacks
    - Anomalous user behavior (UEBA)
    """

    def __init__(self, engine_id: str = "behavior_analyzer", tenant_id: str = "default"):
        super().__init__(engine_id, tenant_id)

        # Tracking state for behavioral patterns
        self._connection_history: dict[str, list[datetime]] = defaultdict(list)
        self._port_scan_tracker: dict[str, set[int]] = defaultdict(set)
        self._data_volume_tracker: dict[str, int] = defaultdict(int)
        self._failed_auth_tracker: dict[str, int] = defaultdict(int)

        # Thresholds
        self._beacon_min_intervals = 5
        self._beacon_jitter_threshold = 0.15  # 15% jitter tolerance
        self._port_scan_threshold = 20         # Ports hit in window
        self._host_sweep_threshold = 15        # Hosts hit in window
        self._exfil_threshold_mb = 100         # MB in time window
        self._brute_force_threshold = 10       # Failed attempts in window
        self._tracking_window = timedelta(minutes=10)

    @property
    def method(self) -> DetectionMethod:
        return DetectionMethod.BEHAVIORAL

    @property
    def max_latency_ms(self) -> float:
        return 50.0

    async def analyze(self, event: NormalizedEvent) -> list[Detection]:
        """Analyze event for behavioral patterns."""
        start = time.perf_counter()
        detections: list[Detection] = []

        if event.network:
            detections.extend(self._check_beacon(event))
            detections.extend(self._check_port_scan(event))
            detections.extend(self._check_data_exfil(event))

        if event.event_type in (EventType.HOST_PROCESS, EventType.LOG_ENTRY):
            detections.extend(self._check_brute_force(event))

        elapsed = (time.perf_counter() - start) * 1000
        detection_latency.labels(engine="behavioral").observe(elapsed / 1000)

        return detections

    def _check_beacon(self, event: NormalizedEvent) -> list[Detection]:
        """Detect C2 beaconing patterns (periodic callbacks)."""
        detections: list[Detection] = []
        if not event.network or not event.network.dst_ip:
            return detections

        key = f"{event.network.src_ip}->{event.network.dst_ip}"
        self._connection_history[key].append(event.timestamp)

        # Clean old entries
        cutoff = datetime.now(timezone.utc) - self._tracking_window
        self._connection_history[key] = [
            t for t in self._connection_history[key] if t > cutoff
        ]

        timestamps = self._connection_history[key]
        if len(timestamps) < self._beacon_min_intervals:
            return detections

        # Calculate intervals between connections
        intervals = [
            (timestamps[i + 1] - timestamps[i]).total_seconds()
            for i in range(len(timestamps) - 1)
        ]

        if not intervals:
            return detections

        mean_interval = sum(intervals) / len(intervals)
        if mean_interval == 0:
            return detections

        # Check for consistent timing (low jitter = beacon)
        std_dev = (sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)) ** 0.5
        jitter_ratio = std_dev / mean_interval if mean_interval > 0 else 1.0

        if jitter_ratio < self._beacon_jitter_threshold and mean_interval > 1:
            confidence = min(0.95, 1.0 - jitter_ratio)
            detections.append(Detection(
                event_id=event.id,
                detection_method=self.method,
                rule_id="BHV-001",
                rule_name="C2 Beacon Pattern Detected",
                severity=Severity.HIGH,
                confidence=confidence,
                category=ThreatCategory.COMMAND_AND_CONTROL,
                mitre=MITREMapping(
                    tactic="Command and Control", tactic_id="TA0011",
                    technique="Application Layer Protocol", technique_id="T1071",
                ),
                description=(
                    f"Periodic connections detected: ~{mean_interval:.1f}s interval, "
                    f"{jitter_ratio:.2%} jitter over {len(timestamps)} connections"
                ),
                evidence={
                    "src_ip": event.network.src_ip,
                    "dst_ip": event.network.dst_ip,
                    "mean_interval_sec": round(mean_interval, 2),
                    "jitter_ratio": round(jitter_ratio, 4),
                    "connection_count": len(timestamps),
                },
                tenant_id=self.tenant_id,
            ))

        return detections

    def _check_port_scan(self, event: NormalizedEvent) -> list[Detection]:
        """Detect port scanning behavior."""
        detections: list[Detection] = []
        if not event.network or not event.network.src_ip or not event.network.dst_port:
            return detections

        src = event.network.src_ip
        self._port_scan_tracker[src].add(event.network.dst_port)

        if len(self._port_scan_tracker[src]) >= self._port_scan_threshold:
            detections.append(Detection(
                event_id=event.id,
                detection_method=self.method,
                rule_id="BHV-002",
                rule_name="Port Scan Detected",
                severity=Severity.HIGH,
                confidence=0.85,
                category=ThreatCategory.DISCOVERY,
                mitre=MITREMapping(
                    tactic="Discovery", tactic_id="TA0007",
                    technique="Network Service Discovery", technique_id="T1046",
                ),
                description=f"Source {src} scanned {len(self._port_scan_tracker[src])} ports",
                evidence={
                    "src_ip": src,
                    "ports_scanned": len(self._port_scan_tracker[src]),
                    "sample_ports": sorted(list(self._port_scan_tracker[src]))[:20],
                },
                tenant_id=self.tenant_id,
            ))
            # Reset after detection
            self._port_scan_tracker[src].clear()

        return detections

    def _check_data_exfil(self, event: NormalizedEvent) -> list[Detection]:
        """Detect potential data exfiltration via large outbound transfers."""
        detections: list[Detection] = []
        if not event.network or not event.network.src_ip:
            return detections

        if event.network.direction != "outbound":
            return detections

        key = event.network.src_ip
        self._data_volume_tracker[key] += event.network.bytes_sent

        volume_mb = self._data_volume_tracker[key] / (1024 * 1024)
        if volume_mb >= self._exfil_threshold_mb:
            detections.append(Detection(
                event_id=event.id,
                detection_method=self.method,
                rule_id="BHV-003",
                rule_name="Potential Data Exfiltration",
                severity=Severity.CRITICAL,
                confidence=0.7,
                category=ThreatCategory.EXFILTRATION,
                mitre=MITREMapping(
                    tactic="Exfiltration", tactic_id="TA0010",
                    technique="Exfiltration Over C2 Channel", technique_id="T1041",
                ),
                description=f"Large outbound transfer: {volume_mb:.1f} MB from {key}",
                evidence={"src_ip": key, "volume_mb": round(volume_mb, 2)},
                tenant_id=self.tenant_id,
            ))
            self._data_volume_tracker[key] = 0

        return detections

    def _check_brute_force(self, event: NormalizedEvent) -> list[Detection]:
        """Detect brute force authentication attempts."""
        detections: list[Detection] = []

        # Check for failed auth indicators in log/process events
        fail_indicators = ["failed", "invalid", "denied", "unauthorized", "error"]
        raw = (event.raw_log or "").lower()

        if not any(ind in raw for ind in fail_indicators):
            return detections

        key = ""
        if event.network and event.network.src_ip:
            key = event.network.src_ip
        elif event.hostname:
            key = event.hostname
        else:
            return detections

        self._failed_auth_tracker[key] += 1

        if self._failed_auth_tracker[key] >= self._brute_force_threshold:
            detections.append(Detection(
                event_id=event.id,
                detection_method=self.method,
                rule_id="BHV-004",
                rule_name="Brute Force Attack",
                severity=Severity.HIGH,
                confidence=0.85,
                category=ThreatCategory.CREDENTIAL_ACCESS,
                mitre=MITREMapping(
                    tactic="Credential Access", tactic_id="TA0006",
                    technique="Brute Force", technique_id="T1110",
                ),
                description=f"Multiple failed auth from {key}: {self._failed_auth_tracker[key]} attempts",
                evidence={
                    "source": key,
                    "attempts": self._failed_auth_tracker[key],
                },
                tenant_id=self.tenant_id,
            ))
            self._failed_auth_tracker[key] = 0

        return detections


# ═══════════════════════════════════════════════════════════════════════════════
# ENGINE 4: ML/Heuristics Engine
# ═══════════════════════════════════════════════════════════════════════════════

class MLEngine(BaseDetectionEngine):
    """
    Machine Learning and heuristics-based detection engine.

    Models:
    - Isolation Forest for network anomaly detection
    - UEBA (User Entity Behavior Analytics)
    - Statistical baseline deviation
    - Entropy-based analysis

    All ML scoring is ASYNC — does not block the inline path.
    """

    def __init__(self, engine_id: str = "ml_engine", tenant_id: str = "default"):
        super().__init__(engine_id, tenant_id)
        self._anomaly_model = None
        self._baseline: dict[str, dict[str, float]] = {}
        self._user_profiles: dict[str, dict[str, Any]] = defaultdict(dict)

    @property
    def method(self) -> DetectionMethod:
        return DetectionMethod.ML_HEURISTIC

    @property
    def max_latency_ms(self) -> float:
        return 100.0  # Async, non-blocking

    async def start(self) -> None:
        """Load ML models."""
        await super().start()
        try:
            from sklearn.ensemble import IsolationForest
            self._anomaly_model = IsolationForest(
                n_estimators=100,
                contamination=0.01,
                random_state=42,
            )
            logger.info("Isolation Forest model initialized")
        except ImportError:
            logger.warning("scikit-learn not available — ML engine will use heuristics only")

    async def analyze(self, event: NormalizedEvent) -> list[Detection]:
        """Run ML/heuristic analysis on the event."""
        start = time.perf_counter()
        detections: list[Detection] = []

        # Heuristic: Entropy-based detection for file artifacts
        if event.file and event.file.entropy:
            detections.extend(self._entropy_analysis(event))

        # Heuristic: Time-of-day anomaly
        detections.extend(self._time_anomaly(event))

        # UEBA: User behavior baseline deviation
        if event.process and event.process.user:
            detections.extend(self._ueba_analysis(event))

        elapsed = (time.perf_counter() - start) * 1000
        detection_latency.labels(engine="ml").observe(elapsed / 1000)

        return detections

    def _entropy_analysis(self, event: NormalizedEvent) -> list[Detection]:
        """Detect high-entropy files that may be packed/encrypted malware."""
        detections: list[Detection] = []
        if not event.file or event.file.entropy is None:
            return detections

        entropy = event.file.entropy

        # Very high entropy + executable = suspicious
        if entropy > 7.5 and event.file.is_executable:
            detections.append(Detection(
                event_id=event.id,
                detection_method=self.method,
                rule_id="ML-001",
                rule_name="High Entropy Executable",
                severity=Severity.HIGH,
                confidence=0.65,
                category=ThreatCategory.DEFENSE_EVASION,
                description=f"Executable with entropy {entropy:.2f} (packed/encrypted)",
                evidence={"entropy": entropy, "file": event.file.name},
                tenant_id=self.tenant_id,
            ))

        return detections

    def _time_anomaly(self, event: NormalizedEvent) -> list[Detection]:
        """Detect activity at unusual times (e.g., 3 AM on weekends)."""
        detections: list[Detection] = []
        hour = event.timestamp.hour
        weekday = event.timestamp.weekday()

        # Off-hours activity (midnight to 5 AM on weekdays, or any time on weekends)
        is_off_hours = hour < 5 or hour > 23
        is_weekend = weekday >= 5

        if (is_off_hours or is_weekend) and event.process and event.process.is_elevated:
            detections.append(Detection(
                event_id=event.id,
                detection_method=self.method,
                rule_id="ML-002",
                rule_name="Off-Hours Privileged Activity",
                severity=Severity.MEDIUM,
                confidence=0.5,
                category=ThreatCategory.PERSISTENCE,
                description=f"Elevated process at {hour:02d}:00 on {'weekend' if is_weekend else 'off-hours'}",
                evidence={
                    "hour": hour,
                    "weekday": weekday,
                    "process": event.process.name,
                    "user": event.process.user,
                },
                tenant_id=self.tenant_id,
            ))

        return detections

    def _ueba_analysis(self, event: NormalizedEvent) -> list[Detection]:
        """User Entity Behavior Analytics — baseline deviation detection."""
        detections: list[Detection] = []
        if not event.process or not event.process.user:
            return detections

        user = event.process.user
        profile = self._user_profiles[user]

        # Track processes per user
        if "processes" not in profile:
            profile["processes"] = set()
            profile["process_count"] = 0

        process_name = event.process.name or ""
        profile["process_count"] += 1

        # First-time process for this user
        if process_name and process_name not in profile["processes"]:
            # After baseline period (100+ events), new processes are noteworthy
            if profile["process_count"] > 100:
                detections.append(Detection(
                    event_id=event.id,
                    detection_method=self.method,
                    rule_id="ML-003",
                    rule_name="New Process for User",
                    severity=Severity.LOW,
                    confidence=0.4,
                    category=ThreatCategory.EXECUTION,
                    description=f"User '{user}' executed '{process_name}' for the first time",
                    evidence={
                        "user": user,
                        "new_process": process_name,
                        "known_processes": len(profile["processes"]),
                    },
                    tenant_id=self.tenant_id,
                ))

            profile["processes"].add(process_name)

        return detections


# ═══════════════════════════════════════════════════════════════════════════════
# ENGINE 5: Sandbox Engine (★ NEW)
# ═══════════════════════════════════════════════════════════════════════════════

class SandboxEngine(BaseDetectionEngine):
    """
    Dynamic analysis / sandboxing engine for suspicious files.

    ★ NEW ADDITION to the architecture.

    Supports:
    - Local sandbox (Docker-based isolated execution)
    - Cuckoo Sandbox integration
    - CAPE Sandbox integration
    - Hybrid Analysis API

    Process:
    1. File artifact arrives from ingestion
    2. Pre-filter (skip known-good, check hash against VT)
    3. Submit to sandbox for detonation
    4. Monitor behavior during execution
    5. Generate verdict: clean | suspicious | malicious
    6. Emit Detection if suspicious/malicious

    This engine is ASYNC ONLY — sandbox analysis takes 30s–120s+.
    Results are published asynchronously and correlated later.
    """

    def __init__(
        self,
        engine_id: str = "sandbox_engine",
        backend: str = "local",
        timeout_seconds: int = 120,
        max_concurrent: int = 5,
        tenant_id: str = "default",
    ):
        super().__init__(engine_id, tenant_id)
        self.backend = backend
        self.timeout_seconds = timeout_seconds
        self.max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._known_clean_hashes: set[str] = set()
        self._known_malicious_hashes: set[str] = set()
        self._pending_analyses: dict[str, asyncio.Task] = {}

    @property
    def method(self) -> DetectionMethod:
        return DetectionMethod.SANDBOX

    @property
    def max_latency_ms(self) -> float:
        return -1  # Async only — no inline latency budget

    async def analyze(self, event: NormalizedEvent) -> list[Detection]:
        """
        Analyze file artifacts via sandboxing.
        Returns immediately with cached results, or queues async analysis.
        """
        if event.event_type != EventType.FILE_ARTIFACT or not event.file:
            return []

        file_hash = event.file.hash_sha256
        if not file_hash:
            return []

        # Check cache: known clean
        if file_hash in self._known_clean_hashes:
            return []

        # Check cache: known malicious (instant detection)
        if file_hash in self._known_malicious_hashes:
            return [Detection(
                event_id=event.id,
                detection_method=self.method,
                rule_id="SBX-CACHE",
                rule_name="Known Malicious File (Cached)",
                severity=Severity.CRITICAL,
                confidence=0.95,
                category=ThreatCategory.EXECUTION,
                description=f"File hash matches known malware: {file_hash[:16]}...",
                evidence={"hash": file_hash, "source": "cache"},
                sandbox_verdict="malicious",
                tenant_id=self.tenant_id,
            )]

        # Pre-filter: skip small/benign files
        if event.file.size_bytes and event.file.size_bytes < 100:
            return []

        # Queue for async sandbox analysis
        if file_hash not in self._pending_analyses:
            task = asyncio.create_task(self._sandbox_analyze(event))
            self._pending_analyses[file_hash] = task

        return []  # Results come asynchronously

    async def _sandbox_analyze(self, event: NormalizedEvent) -> Detection | None:
        """
        Execute sandbox analysis asynchronously.
        This runs in the background and emits detections via the message bus.
        """
        file_hash = event.file.hash_sha256 if event.file else "unknown"

        async with self._semaphore:
            start = time.perf_counter()
            logger.info(
                "Sandbox analysis started",
                file=event.file.name if event.file else "unknown",
                hash=file_hash[:16],
                backend=self.backend,
            )

            sandbox_submissions.labels(
                verdict="pending",
                tenant_id=self.tenant_id,
            ).inc()

            try:
                verdict, report = await self._run_sandbox(event)

                elapsed = time.perf_counter() - start
                sandbox_analysis_time.observe(elapsed)

                # Cache the result
                if verdict == "clean":
                    self._known_clean_hashes.add(file_hash)
                elif verdict in ("suspicious", "malicious"):
                    self._known_malicious_hashes.add(file_hash)

                sandbox_submissions.labels(
                    verdict=verdict,
                    tenant_id=self.tenant_id,
                ).inc()

                if verdict in ("suspicious", "malicious"):
                    severity = Severity.CRITICAL if verdict == "malicious" else Severity.HIGH
                    return Detection(
                        event_id=event.id,
                        detection_method=self.method,
                        rule_id="SBX-001",
                        rule_name=f"Sandbox Verdict: {verdict.title()}",
                        severity=severity,
                        confidence=0.85 if verdict == "malicious" else 0.65,
                        category=ThreatCategory.EXECUTION,
                        description=f"File detonation result: {verdict}",
                        evidence=report,
                        sandbox_verdict=verdict,
                        sandbox_report_ref=report.get("report_id", ""),
                        tenant_id=self.tenant_id,
                    )

                return None

            except asyncio.TimeoutError:
                logger.warning(f"Sandbox timeout for {file_hash[:16]}")
                return None
            except Exception as e:
                logger.error(f"Sandbox error: {e}")
                return None
            finally:
                # Cleanup pending
                self._pending_analyses.pop(file_hash, None)

    async def _run_sandbox(self, event: NormalizedEvent) -> tuple[str, dict]:
        """
        Execute file in sandbox and return verdict + report.

        In production, this dispatches to the configured backend:
        - local: Docker container with behavior monitoring
        - cuckoo: Cuckoo Sandbox REST API
        - cape: CAPE Sandbox REST API
        - hybrid-analysis: Hybrid Analysis API
        """
        if self.backend == "local":
            return await self._run_local_sandbox(event)
        elif self.backend == "cuckoo":
            return await self._run_cuckoo(event)
        elif self.backend == "cape":
            return await self._run_cape(event)
        else:
            return await self._run_local_sandbox(event)

    async def _run_local_sandbox(self, event: NormalizedEvent) -> tuple[str, dict]:
        """
        Local Docker-based sandbox.
        Runs the file in an isolated container and monitors:
        - Process creation
        - File system changes
        - Network connections
        - Registry modifications
        """
        # Production: docker run --rm --network=none --memory=512m ...
        # For now, heuristic analysis based on file properties
        verdict = "clean"
        report: dict[str, Any] = {
            "backend": "local",
            "file": event.file.name if event.file else "unknown",
            "hash": event.file.hash_sha256 if event.file else "",
            "analysis_duration_sec": 0,
        }

        if event.file:
            # Heuristic scoring
            score = 0
            if event.file.is_packed:
                score += 40
                report["packed"] = True
            if event.file.entropy and event.file.entropy > 7.0:
                score += 30
                report["high_entropy"] = True
            if event.file.is_executable:
                score += 10
                report["executable"] = True

            if score >= 70:
                verdict = "malicious"
            elif score >= 40:
                verdict = "suspicious"

            report["score"] = score

        return verdict, report

    async def _run_cuckoo(self, event: NormalizedEvent) -> tuple[str, dict]:
        """Submit to Cuckoo Sandbox via REST API."""
        # Production: POST /tasks/create/file with the file
        # Then poll /tasks/view/{task_id} until complete
        # Then GET /tasks/report/{task_id}
        logger.info("Cuckoo sandbox submission (placeholder)")
        return "clean", {"backend": "cuckoo", "status": "not_configured"}

    async def _run_cape(self, event: NormalizedEvent) -> tuple[str, dict]:
        """Submit to CAPE Sandbox via REST API."""
        logger.info("CAPE sandbox submission (placeholder)")
        return "clean", {"backend": "cape", "status": "not_configured"}
