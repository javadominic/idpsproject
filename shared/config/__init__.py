"""
IDPS Configuration Loader
=========================
Centralized configuration management with environment variable overrides,
YAML file loading, and per-tenant configuration support.
"""

from __future__ import annotations

import os
from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings


class Environment(str, Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class TLSInspectionMode(str, Enum):
    """TLS inspection strategy — one of the key architectural decisions."""
    METADATA = "metadata"        # JA4 fingerprinting, cert analysis, SNI only
    INTERCEPT = "intercept"      # Full MITM TLS interception (inline mode)
    HYBRID = "hybrid"            # Metadata by default, intercept for flagged flows


class EnforcementMode(str, Enum):
    """Controls how enforcement actions are applied."""
    SHADOW = "shadow"            # Log only, no blocking — safe for initial deployment
    STAGED = "staged"            # Block only high-confidence detections
    ENFORCE = "enforce"          # Full enforcement — block all policy violations


class FailMode(str, Enum):
    """Behavior when inline IPS fails."""
    FAIL_OPEN = "fail-open"      # Allow traffic through (availability > security)
    FAIL_CLOSED = "fail-closed"  # Block all traffic (security > availability)


class TenantIsolation(str, Enum):
    LOGICAL = "logical"          # Shared infra, tenant ID column filtering
    PHYSICAL = "physical"        # Separate databases/namespaces per tenant


# ─── Kafka Configuration ────────────────────────────────────────────────────────

class KafkaConfig(BaseSettings):
    bootstrap_servers: str = "localhost:9092"
    group_id: str = "idps-cluster"
    auto_offset_reset: str = "latest"

    model_config = {"env_prefix": "KAFKA_"}


# ─── PostgreSQL Configuration ───────────────────────────────────────────────────

class PostgresConfig(BaseSettings):
    host: str = "localhost"
    port: int = 5432
    db: str = "idps"
    user: str = "idps"
    password: str = "change-me-in-production"

    model_config = {"env_prefix": "POSTGRES_"}

    @property
    def dsn(self) -> str:
        return f"postgresql+asyncpg://{self.user}:{self.password}@{self.host}:{self.port}/{self.db}"


# ─── ClickHouse Configuration ───────────────────────────────────────────────────

class ClickHouseConfig(BaseSettings):
    host: str = "localhost"
    port: int = 8123
    db: str = "idps_analytics"
    user: str = "idps"
    password: str = "change-me-in-production"

    model_config = {"env_prefix": "CLICKHOUSE_"}


# ─── Redis Configuration ────────────────────────────────────────────────────────

class RedisConfig(BaseSettings):
    url: str = "redis://localhost:6379/0"
    password: str = ""

    model_config = {"env_prefix": "REDIS_"}


# ─── Sandbox Configuration ──────────────────────────────────────────────────────

class SandboxConfig(BaseSettings):
    enabled: bool = True
    backend: str = "local"  # local | cuckoo | cape | hybrid-analysis
    timeout_seconds: int = 120
    max_concurrent: int = 5

    model_config = {"env_prefix": "SANDBOX_"}


# ─── Deception Configuration ────────────────────────────────────────────────────

class DeceptionConfig(BaseSettings):
    enabled: bool = True
    honeypot_bind_address: str = "0.0.0.0"
    honeypot_ports: str = "22,23,80,443,445,3389,8080"

    model_config = {"env_prefix": "DECEPTION_", "extra": "ignore"}

    @property
    def ports_list(self) -> list[int]:
        return [int(p.strip()) for p in self.honeypot_ports.split(",")]


# ─── Compliance Configuration ───────────────────────────────────────────────────

class ComplianceConfig(BaseSettings):
    frameworks: str = "pci-dss,soc2"
    report_schedule: str = "0 0 * * 0"
    retention_days: int = 365

    model_config = {"env_prefix": "COMPLIANCE_"}

    @property
    def frameworks_list(self) -> list[str]:
        return [f.strip() for f in self.frameworks.split(",")]


# ─── API Configuration ──────────────────────────────────────────────────────────

class APIConfig(BaseSettings):
    host: str = "0.0.0.0"
    port: int = 8080
    workers: int = 4
    rate_limit: str = "100/minute"
    cors_origins: str = "http://localhost:3000"

    model_config = {"env_prefix": "API_"}


# ─── Master Configuration ───────────────────────────────────────────────────────

class IDPSConfig(BaseSettings):
    """
    Master configuration aggregating all subsystem configs.
    Loaded from environment variables (.env) with optional YAML overrides.
    """
    # Application
    env: Environment = Environment.DEVELOPMENT
    log_level: str = "INFO"
    secret_key: str = "change-me-in-production"
    tenant_id: str = "default"

    # TLS Strategy
    tls_inspection_mode: TLSInspectionMode = TLSInspectionMode.METADATA

    # Enforcement
    enforcement_mode: EnforcementMode = EnforcementMode.SHADOW
    enforcement_fail_mode: FailMode = FailMode.FAIL_OPEN
    enforcement_dry_run: bool = True

    # Multi-tenancy
    multi_tenant_enabled: bool = False
    tenant_isolation_mode: TenantIsolation = TenantIsolation.LOGICAL

    # Sub-configs
    kafka: KafkaConfig = Field(default_factory=KafkaConfig)
    postgres: PostgresConfig = Field(default_factory=PostgresConfig)
    clickhouse: ClickHouseConfig = Field(default_factory=ClickHouseConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    deception: DeceptionConfig = Field(default_factory=DeceptionConfig)
    compliance: ComplianceConfig = Field(default_factory=ComplianceConfig)
    api: APIConfig = Field(default_factory=APIConfig)

    model_config = {"env_prefix": "IDPS_"}

    # ─── Latency Budget Annotations ─────────────────────────────────────────
    # These define the maximum acceptable latency per layer.
    # Inline IPS MUST respond within budget or the enforcement layer
    # falls back to fail_mode behavior.

    @property
    def latency_budgets_ms(self) -> dict[str, float]:
        """Per-layer latency budgets in milliseconds."""
        return {
            "sensor_layer": 5.0,         # Collection + normalization
            "detection_signature": 1.0,   # Signature matching (inline path)
            "detection_behavioral": 50.0, # Behavioral analysis (can be async)
            "detection_ml": 100.0,        # ML scoring (async, non-blocking)
            "detection_sandbox": -1,      # Async only, no inline budget
            "decision_layer": 10.0,       # Enrichment + policy evaluation
            "enforcement_inline": 2.0,    # Inline IPS decision (CRITICAL)
            "enforcement_host": 500.0,    # Host isolation (async)
            "alert_layer": -1,            # Fully async, no budget
        }


def load_yaml_config(path: str | Path) -> dict[str, Any]:
    """Load a YAML configuration file."""
    path = Path(path)
    if not path.exists():
        return {}
    with open(path) as f:
        return yaml.safe_load(f) or {}


def get_config() -> IDPSConfig:
    """
    Load IDPS configuration.

    Priority (highest to lowest):
    1. Environment variables
    2. .env file
    3. configs/config.yaml
    4. Defaults
    """
    # Load YAML config for reference (env vars always override)
    yaml_path = Path(os.getenv("IDPS_CONFIG_PATH", "configs/config.yaml"))
    _yaml_config = load_yaml_config(yaml_path)

    return IDPSConfig()


# Singleton for convenience
_config: IDPSConfig | None = None


def config() -> IDPSConfig:
    """Get the cached singleton configuration."""
    global _config
    if _config is None:
        _config = get_config()
    return _config
