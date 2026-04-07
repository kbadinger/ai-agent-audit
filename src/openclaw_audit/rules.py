"""YAML-based custom rule engine.

Users define detection rules in YAML files under ~/.openclaw/.audit/rules/.
Each rule specifies a target (file_content, config_value, process_name),
a regex pattern, severity, and optional MITRE/OWASP mappings.

This lets security engineers extend detection without writing Python.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from .config import AUDIT_DIR, OPENCLAW_CONFIG, OPENCLAW_HOME
from .models import Finding, ModuleResult, Severity
from .sweeps.base import BaseSweep

logger = logging.getLogger(__name__)

RULES_DIR = AUDIT_DIR / "rules"

_SEVERITY_MAP = {
    "info": Severity.INFO,
    "warning": Severity.WARNING,
    "critical": Severity.CRITICAL,
}

# Safe subset of yaml parsing (no external dependency — use simple parser)
# We parse a restricted YAML subset: key: value pairs and lists


def _parse_yaml(text: str) -> dict:
    """Parse a minimal YAML document (flat key-value pairs, no nesting).

    Supports: string values, booleans, lists (- item), and quoted strings.
    This avoids adding PyYAML as a dependency.
    """
    result: dict = {}
    current_key: str | None = None
    current_list: list | None = None

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # List item
        if stripped.startswith("- ") and current_key is not None:
            if current_list is None:
                current_list = []
                result[current_key] = current_list
            current_list.append(stripped[2:].strip())
            continue

        # Key: value pair
        if ":" in stripped:
            current_list = None
            key, _, value = stripped.partition(":")
            key = key.strip()
            value = value.strip()

            # Strip quotes
            if value and value[0] in ('"', "'") and value[-1] == value[0]:
                value = value[1:-1]

            current_key = key
            if value:
                # Type coercion
                if value.lower() == "true":
                    result[key] = True
                elif value.lower() == "false":
                    result[key] = False
                else:
                    result[key] = value
            # If no value, might be start of a list
            continue

    return result


def load_rules() -> list[dict]:
    """Load all YAML rules from the rules directory."""
    if not RULES_DIR.exists():
        return []

    rules = []
    for rule_file in sorted(RULES_DIR.glob("*.yaml")) + sorted(RULES_DIR.glob("*.yml")):
        try:
            data = _parse_yaml(rule_file.read_text())
            if not data.get("name") or not data.get("pattern"):
                logger.warning("Rule %s missing name or pattern, skipping", rule_file.name)
                continue
            data["_source"] = str(rule_file)
            rules.append(data)
        except Exception as exc:
            logger.warning("Failed to parse rule %s: %s", rule_file.name, exc)

    return rules


def _get_nested(data: dict, key_path: str):
    """Traverse nested dict with dot-separated key path."""
    parts = key_path.split(".")
    val = data
    for part in parts:
        if isinstance(val, dict):
            val = val.get(part)
        else:
            return None
    return val


class CustomRulesSweep(BaseSweep):
    """Evaluate user-defined YAML rules against the environment."""

    name = "custom_rules"

    def run(self) -> ModuleResult:
        findings: list[Finding] = []
        rules = load_rules()

        if not rules:
            return ModuleResult(module_name=self.name, findings=findings)

        for rule in rules:
            try:
                self._evaluate_rule(rule, findings)
            except Exception as exc:
                logger.warning("Rule '%s' failed: %s", rule.get("name", "?"), exc)

        return ModuleResult(module_name=self.name, findings=findings)

    def _evaluate_rule(self, rule: dict, findings: list[Finding]) -> None:
        target = rule.get("target", "file_content")
        pattern = rule["pattern"]
        severity = _SEVERITY_MAP.get(rule.get("severity", "warning"), Severity.WARNING)

        try:
            compiled = re.compile(pattern, re.IGNORECASE if rule.get("case_insensitive") else 0)
        except re.error as exc:
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title=f"Invalid regex in rule: {rule['name']}",
                detail=f"Pattern '{pattern}' failed to compile: {exc}",
                path=rule.get("_source"),
            ))
            return

        if target == "file_content":
            self._check_file_content(rule, compiled, severity, findings)
        elif target == "config_value":
            self._check_config_value(rule, compiled, severity, findings)
        elif target == "file_exists":
            self._check_file_exists(rule, compiled, severity, findings)

    def _check_file_content(self, rule: dict, pattern: re.Pattern, severity: Severity,
                            findings: list[Finding]) -> None:
        """Scan files matching a glob for content matching the pattern."""
        scan_paths = rule.get("paths")
        if isinstance(scan_paths, list):
            paths = scan_paths
        elif isinstance(scan_paths, str):
            paths = [scan_paths]
        else:
            # Default: scan common config/memory files
            paths = [str(OPENCLAW_HOME)]

        for path_str in paths:
            base = Path(path_str)
            if not base.exists():
                continue

            glob_pattern = rule.get("glob", "*")
            files = [base] if base.is_file() else list(base.rglob(glob_pattern))

            for fpath in files[:100]:  # Cap to avoid scanning huge trees
                if not fpath.is_file() or fpath.stat().st_size > 1_000_000:
                    continue
                try:
                    content = fpath.read_text(errors="replace")
                except OSError:
                    continue

                if pattern.search(content):
                    findings.append(Finding(
                        module=self.name,
                        severity=severity,
                        title=rule["name"],
                        detail=rule.get("description", f"Custom rule '{rule['name']}' matched."),
                        path=str(fpath),
                        mitre_attack=rule.get("mitre_attack"),
                        owasp_asi=rule.get("owasp_asi"),
                        remediation=rule.get("remediation"),
                    ))

    def _check_config_value(self, rule: dict, pattern: re.Pattern, severity: Severity,
                            findings: list[Finding]) -> None:
        """Check a specific config key against the pattern."""
        config_key = rule.get("config_key", "")
        if not config_key or not OPENCLAW_CONFIG.exists():
            return

        try:
            data = json.loads(OPENCLAW_CONFIG.read_text())
        except (json.JSONDecodeError, OSError):
            return

        value = _get_nested(data, config_key)
        if value is not None and pattern.search(str(value)):
            findings.append(Finding(
                module=self.name,
                severity=severity,
                title=rule["name"],
                detail=rule.get("description", f"Config key '{config_key}' matches rule."),
                path=str(OPENCLAW_CONFIG),
                mitre_attack=rule.get("mitre_attack"),
                owasp_asi=rule.get("owasp_asi"),
                remediation=rule.get("remediation"),
            ))

    def _check_file_exists(self, rule: dict, pattern: re.Pattern, severity: Severity,
                           findings: list[Finding]) -> None:
        """Check if files matching the pattern exist."""
        scan_paths = rule.get("paths", [str(OPENCLAW_HOME)])
        if isinstance(scan_paths, str):
            scan_paths = [scan_paths]

        for path_str in scan_paths:
            base = Path(path_str)
            if not base.exists():
                continue
            for fpath in base.rglob("*"):
                if pattern.search(fpath.name):
                    findings.append(Finding(
                        module=self.name,
                        severity=severity,
                        title=rule["name"],
                        detail=rule.get("description", f"File matching rule found: {fpath.name}"),
                        path=str(fpath),
                        mitre_attack=rule.get("mitre_attack"),
                        owasp_asi=rule.get("owasp_asi"),
                        remediation=rule.get("remediation"),
                    ))
                    break  # One finding per rule per path
