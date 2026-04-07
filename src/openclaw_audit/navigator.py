"""MITRE ATT&CK Navigator layer export.

Generates a Navigator-compatible JSON layer from findings,
mapping technique IDs to colors based on finding severity.
Importable at https://mitre-attack.github.io/attack-navigator/
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from .models import Severity

# Color mapping: severity -> Navigator color
_SEVERITY_COLORS = {
    Severity.CRITICAL: "#ff6666",  # Red
    Severity.WARNING: "#ffcc00",   # Yellow
    Severity.INFO: "#99ccff",      # Light blue
}

# Score mapping for Navigator
_SEVERITY_SCORES = {
    Severity.CRITICAL: 100,
    Severity.WARNING: 50,
    Severity.INFO: 10,
}


def findings_to_navigator(
    findings: list[dict],
    layer_name: str = "openclaw-audit",
    description: str = "Security findings from openclaw-audit",
    domain: str = "enterprise-attack",
) -> dict[str, Any]:
    """Convert findings to a MITRE ATT&CK Navigator layer.

    Args:
        findings: List of finding dicts from FindingsDB.
        layer_name: Name shown in Navigator.
        description: Layer description.
        domain: ATT&CK domain (enterprise-attack, mobile-attack, ics-attack).

    Returns:
        Navigator layer JSON structure.
    """
    # Group findings by technique ID, keep highest severity
    techniques: dict[str, dict] = {}

    for f in findings:
        technique_id = f.get("mitre_attack")
        if not technique_id:
            continue

        severity = f.get("severity", 0)
        score = _SEVERITY_SCORES.get(severity, 0)
        color = _SEVERITY_COLORS.get(severity, "#ffffff")

        # Handle sub-techniques (T1059.004 -> tactic T1059, sub .004)
        base_id = technique_id.split(".")[0]
        full_id = technique_id

        if full_id not in techniques or score > techniques[full_id].get("score", 0):
            techniques[full_id] = {
                "techniqueID": full_id,
                "score": score,
                "color": color,
                "comment": _build_comment(f),
                "enabled": True,
                "showSubtechniques": "." in full_id,
            }
        else:
            # Append to existing comment
            existing = techniques[full_id]
            existing["comment"] += f"\n---\n{_build_comment(f)}"

    # Build the layer
    layer: dict[str, Any] = {
        "name": layer_name,
        "versions": {
            "attack": "16",
            "navigator": "5.1.0",
            "layer": "4.5",
        },
        "domain": domain,
        "description": description,
        "filters": {
            "platforms": ["Linux", "macOS", "Windows"],
        },
        "sorting": 3,  # Sort by score descending
        "layout": {
            "layout": "side",
            "aggregateFunction": "max",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": list(techniques.values()),
        "gradient": {
            "colors": ["#99ccff", "#ffcc00", "#ff6666"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Critical Finding", "color": "#ff6666"},
            {"label": "Warning Finding", "color": "#ffcc00"},
            {"label": "Info Finding", "color": "#99ccff"},
        ],
        "metadata": [],
        "links": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }

    return layer


def _build_comment(finding: dict) -> str:
    """Build a comment string for a technique from a finding."""
    parts = [f"[{finding.get('module', '?')}] {finding.get('title', '?')}"]
    if finding.get("owasp_asi"):
        parts.append(f"OWASP: {finding['owasp_asi']}")
    if finding.get("confidence") is not None:
        parts.append(f"Confidence: {finding['confidence']:.2f}")
    return " | ".join(parts)


def navigator_to_json(layer: dict[str, Any], indent: int = 2) -> str:
    """Serialize a Navigator layer to JSON string."""
    return json.dumps(layer, indent=indent)
