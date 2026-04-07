"""Unified export module — SARIF, JSONL, and CSV output formats."""

from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path
from typing import TextIO

from .db import FindingsDB
from .navigator import findings_to_navigator, navigator_to_json
from .sarif import findings_to_sarif, sarif_to_json
from .sbom import generate_sbom, sbom_to_json
from .stix import findings_to_stix, ioc_to_stix, stix_to_json

_SEVERITY_LABELS = {0: "INFO", 1: "WARNING", 2: "CRITICAL"}

_CSV_COLUMNS = [
    "id", "module", "severity", "title", "detail", "path",
    "confidence", "mitre_attack", "owasp_asi", "remediation",
    "eu_ai_act", "nist_rmf",
    "triage_status", "first_seen", "last_seen", "times_seen",
]


def export_sarif(db: FindingsDB, output: TextIO | None = None) -> str:
    """Export findings as SARIF v2.1.0 JSON."""
    findings = db.get_active_findings()
    sarif = findings_to_sarif(findings)
    text = sarif_to_json(sarif)
    if output:
        output.write(text + "\n")
    return text


def export_jsonl(db: FindingsDB, output: TextIO | None = None) -> str:
    """Export findings as JSONL (one JSON object per line)."""
    findings = db.get_active_findings()
    lines = []
    for f in findings:
        record = {
            "id": f["id"],
            "module": f["module"],
            "severity": _SEVERITY_LABELS.get(f["severity"], "UNKNOWN"),
            "severity_int": f["severity"],
            "title": f["title"],
            "detail": f["detail"],
            "path": f.get("path"),
            "confidence": f.get("confidence", 0.5),
            "mitre_attack": f.get("mitre_attack"),
            "owasp_asi": f.get("owasp_asi"),
            "remediation": f.get("remediation"),
            "triage_status": f.get("triage_status"),
            "eu_ai_act": f.get("eu_ai_act"),
            "nist_rmf": f.get("nist_rmf"),
            "first_seen": f.get("first_seen"),
            "last_seen": f.get("last_seen"),
            "times_seen": f.get("times_seen", 1),
            "dedup_hash": f.get("dedup_hash"),
        }
        lines.append(json.dumps(record))
    text = "\n".join(lines)
    if output and lines:
        output.write(text + "\n")
    return text


def export_csv(db: FindingsDB, output: TextIO | None = None) -> str:
    """Export findings as CSV."""
    findings = db.get_active_findings()
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for f in findings:
        row = dict(f)
        row["severity"] = _SEVERITY_LABELS.get(row.get("severity", 0), "UNKNOWN")
        writer.writerow(row)
    text = buf.getvalue()
    if output:
        output.write(text)
    return text


def export_navigator(db: FindingsDB, output: TextIO | None = None) -> str:
    """Export findings as MITRE ATT&CK Navigator layer."""
    findings = db.get_active_findings()
    layer = findings_to_navigator(findings)
    text = navigator_to_json(layer)
    if output:
        output.write(text + "\n")
    return text


def export_stix(db: FindingsDB, output: TextIO | None = None) -> str:
    """Export findings as STIX 2.1 Bundle."""
    findings = db.get_active_findings()
    bundle = findings_to_stix(findings)
    text = stix_to_json(bundle)
    if output:
        output.write(text + "\n")
    return text


def export_stix_ioc(db: FindingsDB, output: TextIO | None = None) -> str:
    """Export IOC database as STIX 2.1 Bundle."""
    bundle = ioc_to_stix()
    text = stix_to_json(bundle)
    if output:
        output.write(text + "\n")
    return text


def export_sbom(db: FindingsDB, output: TextIO | None = None) -> str:
    """Export CycloneDX SBOM for agent dependencies."""
    sbom = generate_sbom()
    text = sbom_to_json(sbom)
    if output:
        output.write(text + "\n")
    return text


def export_findings(db: FindingsDB, fmt: str = "jsonl", output_path: str | None = None) -> str:
    """Export findings in the specified format.

    Args:
        db: FindingsDB instance.
        fmt: Output format — "sarif", "jsonl", or "csv".
        output_path: File path to write to. None = return string only.

    Returns:
        The exported content as a string.
    """
    exporters = {
        "sarif": export_sarif,
        "jsonl": export_jsonl,
        "csv": export_csv,
        "navigator": export_navigator,
        "stix": export_stix,
        "stix-ioc": export_stix_ioc,
        "sbom": export_sbom,
    }
    exporter = exporters.get(fmt)
    if not exporter:
        raise ValueError(f"Unknown format '{fmt}'. Supported: {list(exporters.keys())}")

    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            return exporter(db, f)
    else:
        return exporter(db, None)
