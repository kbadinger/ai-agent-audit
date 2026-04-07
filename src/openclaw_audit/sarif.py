"""SARIF v2.1.0 output formatter for audit findings.

Converts findings to the Static Analysis Results Interchange Format,
compatible with GitHub Code Scanning and other SARIF consumers.
"""

from __future__ import annotations

import json
from typing import Any

from .models import Severity

# SARIF severity mapping: OpenClaw severity -> SARIF level
_SEVERITY_MAP = {
    Severity.INFO: "note",
    Severity.WARNING: "warning",
    Severity.CRITICAL: "error",
}


def findings_to_sarif(findings: list[dict], tool_version: str = "0.1.0") -> dict[str, Any]:
    """Convert a list of finding dicts (from FindingsDB) to a SARIF v2.1.0 document."""
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for f in findings:
        rule_id = f["dedup_hash"]
        severity = f.get("severity", 0)
        level = _SEVERITY_MAP.get(severity, "note")

        # Build rule if not seen before
        if rule_id not in rules:
            rule: dict[str, Any] = {
                "id": rule_id,
                "name": f["title"],
                "shortDescription": {"text": f["title"]},
                "fullDescription": {"text": f["detail"][:1000]},
                "defaultConfiguration": {"level": level},
            }
            # Add help text from remediation if available
            if f.get("remediation"):
                rule["help"] = {"text": f["remediation"]}
            # Add tags for MITRE/OWASP
            tags = []
            if f.get("mitre_attack"):
                tags.append(f"mitre:{f['mitre_attack']}")
            if f.get("owasp_asi"):
                tags.append(f"owasp:{f['owasp_asi']}")
            if f.get("eu_ai_act"):
                tags.append(f"eu-ai-act:{f['eu_ai_act']}")
            if f.get("nist_rmf"):
                tags.append(f"nist-rmf:{f['nist_rmf']}")
            if tags:
                rule["properties"] = {"tags": tags}
            rules[rule_id] = rule

        # Build result
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f["detail"]},
            "properties": {
                "module": f["module"],
                "confidence": f.get("confidence", 0.5),
                "firstSeen": f.get("first_seen"),
                "lastSeen": f.get("last_seen"),
                "timesSeen": f.get("times_seen", 1),
            },
        }

        # Add MITRE/OWASP to properties
        if f.get("mitre_attack"):
            result["properties"]["mitreAttack"] = f["mitre_attack"]
        if f.get("owasp_asi"):
            result["properties"]["owaspAsi"] = f["owasp_asi"]

        # Add triage status if present
        if f.get("triage_status"):
            result["properties"]["triageStatus"] = f["triage_status"]

        # Add location if path is available
        if f.get("path"):
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f["path"]},
                    }
                }
            ]

        results.append(result)

    return {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "openclaw-audit",
                        "version": tool_version,
                        "informationUri": "https://github.com/kbadinger/openclaw-audit",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def sarif_to_json(sarif: dict[str, Any], indent: int = 2) -> str:
    """Serialize a SARIF document to JSON string."""
    return json.dumps(sarif, indent=indent)
