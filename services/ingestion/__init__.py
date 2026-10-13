"""
IDPS Ingestion Service — Sensor Layer
======================================
Collection and normalization of security events from all data sources.

Sensors:
- Network Sensor (AF_XDP, tap, inline)
- Host Agent (eBPF, FIM, process monitoring)
- Log Collector (Syslog, cloud, application logs)
- File/Artifact Collector (PCAP, logs, binaries)

Data Flow:
  External Sources → Sensors → Normalizer → Kafka (normalized-events)
"""
