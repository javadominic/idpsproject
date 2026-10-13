# 🛡️ Next-Generation Enterprise IDPS

An enterprise-grade, modular, scalable, observable **Intrusion Detection & Prevention System (IDPS)** built with Python 3.12, FastAPI, Kafka, and OpenTelemetry.

---

## 🌟 Key Architecture Improvements Over Traditional IDPS

| # | Capability | Description |
|---|---|---|
| 1 | **Dynamic Sandbox Detonation** | Automated malware detonation engine for suspicious binary & file artifacts. |
| 2 | **Active Deception Technology** | Built-in honeypots (SSH, HTTP) and canary tokens (AWS credentials, web bugs) for near-zero false positive lure detection. |
| 3 | **Advanced TLS Inspection** | Supports **Metadata mode** (JA4/JA4S fingerprinting without MITM decryption), **Intercept mode**, and **Hybrid mode**. |
| 4 | **Proactive Threat Hunting** | Hypothesis-driven automated queries searching for stealthy threats, LOLBins, and rare parent-child executions. |
| 5 | **Cryptographic Forensics** | WORM-compliant evidence preservation with immutable SHA-256 chain-of-custody tracking. |
| 6 | **High Availability & Fail-Mode** | Latency SLA budgeting with automated **Fail-Open** (availability priority) and **Fail-Closed** (security priority) protection. |
| 7 | **Automated Compliance Engine** | Real-time audit control evaluation and report generation for **PCI-DSS 4.0**, **SOC2**, **HIPAA**, and **GDPR**. |
| 8 | **Strict Latency Budgets** | Annotated inline path latency budgets (< 1ms signature, < 5ms protocol, < 2ms inline IPS) with non-blocking async ML & behavioral pipelines. |
| 9 | **Tenant Isolation & RBAC** | Multi-tenant domain models with Role-Based Access Control (`Viewer`, `Analyst`, `Hunter`, `Operator`, `Admin`). |
| 10 | **Unified REST & Webhook API** | Comprehensive OpenAPI control plane with rate limiting, JWT auth, and bidirectional webhooks. |

---

## 🏛️ Pipeline Architecture

```
  External Data Sources
    ├─ Network Traffic (PCAP, NetFlow, DNS)
    ├─ Endpoints (Host agents, eBPF telemetry)
    ├─ Logs & Cloud Audits (Syslog, CloudTrail)
    ├─ Threat Intel Feeds (STIX/TAXII, IOCs)
    └─ Deception Traps (Honeypots, Canary Tokens)
         │
         ▼  Ingest & Normalize
  ┌────────────────────────────────────────────────────────┐
  │ Sensor Layer: Collection & Normalization (CEF / JSON) │
  └──────────────────────────┬─────────────────────────────┘
                             │ Kafka: idps.sensor.normalized-events
                             ▼
  ┌────────────────────────────────────────────────────────┐
  │ Detection Layer: Multi-Engine Analysis & Correlation    │
  │   ├─ Signature Engine (< 1ms, Suricata compatible)     │
  │   ├─ Protocol Analyzer (< 5ms, JA4 / DNS DGA / HTTP)   │
  │   ├─ Behavioral Analyzer (< 50ms, Beacons / Port Scans)│
  │   ├─ ML / Heuristic Engine (UEBA / Anomaly Detection)  │
  │   ├─ Sandbox Detonation Engine (Dynamic Detonation)    │
  │   └─ Cross-Engine Correlation & Kill Chain Progression │
  └──────────────────────────┬─────────────────────────────┘
                             │ Kafka: idps.detection.detections
                             ▼
  ┌────────────────────────────────────────────────────────┐
  │ Decision Layer: Enrichment, Scoring & Policy           │
  │   ├─ Threat Intel & Asset Criticality Enrichment       │
  │   ├─ Composite Risk Scoring (0.0 – 100.0)              │
  │   ├─ Policy Engine (Shadow / Staged / Enforce Modes)   │
  │   └─ Proactive Threat Hunter Engine                    │
  └──────────────────────────┬─────────────────────────────┘
                             │ Kafka: idps.decision.approved-actions
                             ▼
  ┌────────────────────────────────────────────────────────┐
  │ Enforcement Layer: Active Intervention & Fail-Mode     │
  │   ├─ Perimeter Firewall (IP & Expiring TTL Blocks)     │
  │   ├─ Inline IPS (Drop, TCP Reset, ICMP Reject)         │
  │   ├─ Host Containment (Kill Process, Isolate Host)     │
  │   ├─ WAF (HTTP 403, Client Challenge, Rate Limit)      │
  │   ├─ High-Availability Fail-Mode (Fail-Open / Closed)  │
  │   └─ Immutable Enforcement Audit Trail                 │
  └──────────────────────────┬─────────────────────────────┘
                             │ Kafka: idps.alert.alerts
                             ▼
  ┌────────────────────────────────────────────────────────┐
  │ SOC Alert & Response Layer                             │
  │   ├─ Prioritized Alert Management (P1 – P5)            │
  │   ├─ Cryptographic Forensics & Chain of Custody        │
  │   ├─ Automated SOAR Playbooks (Ransomware Containment) │
  │   ├─ Incident Response Case Lifecycle                  │
  │   ├─ SIEM Forwarding (CEF / Syslog / Elastic / Splunk) │
  │   └─ Multi-Channel Notifications (Slack, PagerDuty)    │
  └────────────────────────────────────────────────────────┘
```

---

## 📁 Repository Structure

```
idps/
├── pyproject.toml              # Dependencies and build configuration
├── docker-compose.yml          # Kafka, Postgres, Redis, ClickHouse, IDPS containers
├── Makefile                    # Standard operations & developer targets
├── configs/
│   ├── config.yaml             # Global system configuration
│   ├── rules/
│   │   ├── signatures.yaml     # Suricata/Snort-compatible signature rules
│   │   ├── behavioral.yaml     # Behavioral anomaly rules
│   │   └── correlation.yaml    # Cross-engine attack progression rules
│   └── policies/
│       ├── enforcement.yaml    # Enforcement thresholds & rollout policies
│       └── compliance.yaml     # Regulatory control mappings
│
├── shared/                     # Shared Foundation Library
│   ├── models/                 # Canonical Pydantic models (Event, Alert, Decision)
│   ├── messaging/              # Kafka MessageBus abstraction with fallback
│   ├── storage/                # Repository pattern (Postgres, ClickHouse, Memory)
│   ├── observability/          # OpenTelemetry, Prometheus metrics, structured logs
│   ├── auth/                   # RBAC, JWT validation, multi-tenancy
│   └── config/                 # Pydantic Settings & YAML loader
│
├── services/
│   ├── ingestion/              # Sensor collection & normalization
│   │   ├── sensors.py          # Network, Host, Log, File collectors
│   │   └── pipeline.py         # Batch normalization & streaming
│   ├── detection/              # Detection Engines
│   │   ├── engines.py          # Signature, Protocol, Behavioral, ML, Sandbox
│   │   ├── correlation.py      # Cross-engine kill-chain correlation
│   │   ├── rule_loader.py      # Dynamic YAML rule loader
│   │   └── pipeline.py         # Engine dispatch & latency orchestration
│   ├── decision/               # Intelligence & Evaluation
│   │   ├── enrichment.py       # Threat intel IOCs & CMDB asset context
│   │   ├── risk_scorer.py      # Composite risk scoring (0-100)
│   │   ├── policy_engine.py    # Shadow / Staged / Enforce decisions
│   │   ├── correlator.py       # Alert deduplication & suppression
│   │   ├── threat_hunter.py    # Proactive hypothesis-driven hunting
│   │   └── pipeline.py         # Decision pipeline orchestrator
│   ├── deception/              # Deception Technology
│   │   ├── honeypot.py         # SSH & HTTP network traps
│   │   ├── canary_tokens.py    # Canary credentials & web bug tokens
│   │   └── decoy_service.py    # Deception-to-pipeline bridge
│   ├── enforcement/            # Active Response
│   │   ├── actions/            # Firewall, Inline IPS, Host, WAF
│   │   ├── fail_mode.py        # Fail-Open & Fail-Closed protection
│   │   ├── audit_logger.py     # Regulatory audit trail
│   │   └── pipeline.py         # Enforcement orchestrator
│   ├── alert/                  # SOC & Incident Management
│   │   ├── alert_manager.py    # Alert triage & prioritization
│   │   ├── forensics.py        # Cryptographic evidence chain-of-custody
│   │   ├── incident_manager.py # IR lifecycle cases
│   │   ├── soar_engine.py      # Automated response playbooks
│   │   ├── siem_integration.py # CEF & Syslog forwarding
│   │   ├── notification.py     # Slack, PagerDuty, Webhook alerts
│   │   └── pipeline.py         # Alert pipeline orchestrator
│   └── api/                    # REST Control Plane
│       ├── main.py             # FastAPI entrypoint
│       ├── middleware/         # Auth, Rate limiting
│       ├── routes/             # Events, Alerts, Rules, Hunting, Compliance
│       └── webhooks.py         # Bi-directional webhook integration
│
├── platform/
│   ├── compliance/             # PCI-DSS, SOC2, HIPAA, GDPR reports
│   └── ha/                     # Liveness, readiness, failover probes
│
├── deploy/
│   ├── docker/Dockerfile       # Multi-stage container build
│   └── k8s/                    # Kubernetes manifests
│
└── tests/
    ├── unit/                   # Unit test suite
    └── integration/            # End-to-end pipeline test
```

---

## 🚀 Quick Start

### 1. Run with Docker Compose (Recommended)
```bash
docker-compose up --build -d
```
Services available:
- **SOC Command Console (Web UI)**: `http://localhost:8080/`
- **Interactive OpenAPI Docs**: `http://localhost:8080/docs`
- **Health Diagnostics**: `http://localhost:8080/health`
- **Prometheus Metrics**: `http://localhost:8080/metrics`
- **SSH Honeypot**: Port `2222`
- **HTTP Honeypot**: Port `8088`

### 2. Local Python Development (macOS / Linux)
Because macOS does not ship with standalone `pip` in `$PATH`, activate a virtual environment first:
```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install package and dependencies
pip install -e .

# Run API server
uvicorn services.api.main:app --reload --port 8080

# Run automated tests
pytest tests/ -v
```

---

## 📡 API Reference & Operations

### Health & Liveness
```bash
curl http://localhost:8080/health
```

### Ingest Security Event
```bash
curl -X POST http://localhost:8080/api/v1/events \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "host_process",
    "source_sensor": "edr_agent",
    "hostname": "dc01.corp.internal",
    "process": {
      "name": "powershell.exe",
      "command_line": "powershell.exe -enc SQBFAFgA...",
      "is_elevated": true
    }
  }'
```

### Query SOC Alerts
```bash
curl http://localhost:8080/api/v1/alerts
```

### Launch Proactive Threat Hunt
```bash
curl -X POST http://localhost:8080/api/v1/hunting \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Hunt for LOLBin certutil downloads",
    "hypothesis": "Adversaries using certutil to stage external binaries",
    "query": "certutil"
  }'
```

### Generate Regulatory Compliance Report
```bash
curl -X POST "http://localhost:8080/api/v1/compliance/generate?framework=pci-dss"
```

---

## 📜 Compliance & Audit Trails
Every enforcement action and forensic artifact is signed with a SHA-256 digest ensuring legal non-repudiation and satisfying **PCI-DSS 10.6**, **SOC2 CC7.2**, and **HIPAA §164.312**.
