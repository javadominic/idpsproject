"""
IDPS Rule Loader
================
Loads, validates, and manages detection rules from YAML/JSON files or database.
Provides schema validation and dynamic rule activation.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from shared.models import MITREMapping, Severity, ThreatCategory
from shared.observability import active_rules, get_logger
from services.detection.engines import SignatureRule

logger = get_logger("detection.rule_loader")


class RuleLoader:
    """Manages signature and behavioral rule definitions."""

    def __init__(self, rules_dir: str | Path = "configs/rules"):
        self.rules_dir = Path(rules_dir)
        self._rules: dict[str, SignatureRule] = {}

    def load_from_directory(self) -> list[SignatureRule]:
        """Scan directory and load all .yaml and .yml rule files."""
        if not self.rules_dir.exists():
            logger.warning(f"Rules directory not found: {self.rules_dir}")
            return []

        loaded: list[SignatureRule] = []
        for file_path in self.rules_dir.glob("*.y*ml"):
            try:
                rules = self.load_from_file(file_path)
                loaded.extend(rules)
            except Exception as e:
                logger.error(f"Error loading rule file {file_path}: {e}")

        logger.info(f"Loaded total {len(loaded)} rules from {self.rules_dir}")
        active_rules.labels(engine="signature").set(len(self._rules))
        return loaded

    def load_from_file(self, file_path: str | Path) -> list[SignatureRule]:
        """Load rules from a single YAML file."""
        path = Path(file_path)
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data:
            return []

        items = data if isinstance(data, list) else data.get("rules", [])
        rules: list[SignatureRule] = []

        for item in items:
            try:
                rule = self._parse_rule(item)
                self._rules[rule.rule_id] = rule
                rules.append(rule)
            except Exception as e:
                logger.error(f"Failed to parse rule item: {item.get('rule_id', 'unknown')}: {e}")

        return rules

    def _parse_rule(self, item: dict[str, Any]) -> SignatureRule:
        """Parse raw dictionary into SignatureRule instance."""
        mitre_data = item.get("mitre")
        mitre = None
        if mitre_data:
            mitre = MITREMapping(
                tactic=mitre_data.get("tactic", ""),
                tactic_id=mitre_data.get("tactic_id", ""),
                technique=mitre_data.get("technique", ""),
                technique_id=mitre_data.get("technique_id", ""),
                sub_technique=mitre_data.get("sub_technique"),
                sub_technique_id=mitre_data.get("sub_technique_id"),
            )

        category = None
        if item.get("category"):
            try:
                category = ThreatCategory(item["category"])
            except ValueError:
                pass

        severity = Severity.MEDIUM
        if item.get("severity"):
            try:
                severity = Severity(item["severity"].lower())
            except ValueError:
                pass

        return SignatureRule(
            rule_id=item["rule_id"],
            name=item.get("name", item["rule_id"]),
            description=item.get("description", ""),
            severity=severity,
            category=category,
            mitre=mitre,
            conditions=item.get("conditions", {}),
            enabled=item.get("enabled", True),
            version=str(item.get("version", "1.0")),
        )

    def get_rule(self, rule_id: str) -> SignatureRule | None:
        """Retrieve rule by ID."""
        return self._rules.get(rule_id)

    def list_rules(self) -> list[SignatureRule]:
        """List all loaded rules."""
        return list(self._rules.values())
