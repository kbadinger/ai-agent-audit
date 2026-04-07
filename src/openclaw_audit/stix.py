"""STIX 2.1 export for IOC sharing and finding reports.

Converts findings to STIX Indicator objects and IOCs to STIX
Observed-Data / Indicator objects. Produces a STIX 2.1 Bundle
for threat intelligence sharing via TAXII or file exchange.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from .ioc import C2_IPS, MALICIOUS_DOMAINS, MALICIOUS_HASHES, MALICIOUS_PUBLISHERS
from .models import Severity

# STIX 2.1 spec version
_STIX_VERSION = "2.1"

# TLP marking
_TLP_WHITE = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"

_SEVERITY_TO_PATTERN_TYPE = {
    Severity.CRITICAL: "stix",
    Severity.WARNING: "stix",
    Severity.INFO: "stix",
}


def _stix_id(stype: str, seed: str) -> str:
    """Generate a deterministic STIX ID from type and seed."""
    ns = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # URL namespace
    return f"{stype}--{uuid.uuid5(ns, seed)}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def findings_to_stix(findings: list[dict]) -> dict[str, Any]:
    """Convert findings to a STIX 2.1 Bundle with Indicator objects."""
    objects: list[dict] = []
    now = _now_iso()

    # Identity for openclaw-audit
    identity_id = _stix_id("identity", "openclaw-audit")
    objects.append({
        "type": "identity",
        "spec_version": _STIX_VERSION,
        "id": identity_id,
        "created": now,
        "modified": now,
        "name": "openclaw-audit",
        "identity_class": "system",
        "description": "Security audit daemon for OpenClaw installations",
    })

    for f in findings:
        indicator_id = _stix_id("indicator", f.get("dedup_hash", str(f.get("id", ""))))

        indicator: dict[str, Any] = {
            "type": "indicator",
            "spec_version": _STIX_VERSION,
            "id": indicator_id,
            "created": now,
            "modified": now,
            "name": f.get("title", "Unknown finding"),
            "description": f.get("detail", ""),
            "indicator_types": ["anomalous-activity"],
            "pattern_type": "stix",
            "pattern": _finding_to_pattern(f),
            "valid_from": now,
            "created_by_ref": identity_id,
            "object_marking_refs": [_TLP_WHITE],
            "confidence": int((f.get("confidence", 0.5)) * 100),
        }

        # Add external references
        ext_refs = []
        if f.get("mitre_attack"):
            ext_refs.append({
                "source_name": "mitre-attack",
                "external_id": f["mitre_attack"],
                "url": f"https://attack.mitre.org/techniques/{f['mitre_attack'].replace('.', '/')}/",
            })
        if f.get("owasp_asi"):
            ext_refs.append({
                "source_name": "owasp-agentic-top-10",
                "external_id": f["owasp_asi"],
            })
        if ext_refs:
            indicator["external_references"] = ext_refs

        # Add labels
        labels = [f.get("module", "unknown")]
        severity = f.get("severity", 0)
        if severity == 2:
            labels.append("critical")
        elif severity == 1:
            labels.append("warning")
        indicator["labels"] = labels

        objects.append(indicator)

    return {
        "type": "bundle",
        "id": _stix_id("bundle", f"openclaw-audit-{now}"),
        "objects": objects,
    }


def ioc_to_stix() -> dict[str, Any]:
    """Convert the IOC database to a STIX 2.1 Bundle."""
    objects: list[dict] = []
    now = _now_iso()

    identity_id = _stix_id("identity", "openclaw-audit-ioc")
    objects.append({
        "type": "identity",
        "spec_version": _STIX_VERSION,
        "id": identity_id,
        "created": now,
        "modified": now,
        "name": "openclaw-audit IOC database",
        "identity_class": "system",
    })

    # C2 IPs as indicators
    for ip in sorted(C2_IPS):
        objects.append({
            "type": "indicator",
            "spec_version": _STIX_VERSION,
            "id": _stix_id("indicator", f"c2-ip-{ip}"),
            "created": now,
            "modified": now,
            "name": f"C2 IP: {ip}",
            "description": "Known command-and-control IP address",
            "indicator_types": ["malicious-activity"],
            "pattern_type": "stix",
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "valid_from": now,
            "created_by_ref": identity_id,
            "labels": ["c2", "network"],
        })

    # Malicious domains as indicators
    for domain in sorted(MALICIOUS_DOMAINS):
        objects.append({
            "type": "indicator",
            "spec_version": _STIX_VERSION,
            "id": _stix_id("indicator", f"domain-{domain}"),
            "created": now,
            "modified": now,
            "name": f"Malicious domain: {domain}",
            "description": "Known malicious or exfiltration domain",
            "indicator_types": ["malicious-activity"],
            "pattern_type": "stix",
            "pattern": f"[domain-name:value = '{domain}']",
            "valid_from": now,
            "created_by_ref": identity_id,
            "labels": ["malicious-domain", "exfiltration"],
        })

    # Malicious hashes as indicators
    for hash_val, desc in MALICIOUS_HASHES.items():
        objects.append({
            "type": "indicator",
            "spec_version": _STIX_VERSION,
            "id": _stix_id("indicator", f"hash-{hash_val}"),
            "created": now,
            "modified": now,
            "name": f"Malicious file: {desc}",
            "description": desc,
            "indicator_types": ["malicious-activity"],
            "pattern_type": "stix",
            "pattern": f"[file:hashes.'SHA-1' = '{hash_val}']",
            "valid_from": now,
            "created_by_ref": identity_id,
            "labels": ["malware", "file-hash"],
        })

    # Malicious publishers as threat actors
    for pub_name, desc in MALICIOUS_PUBLISHERS.items():
        objects.append({
            "type": "threat-actor",
            "spec_version": _STIX_VERSION,
            "id": _stix_id("threat-actor", f"publisher-{pub_name}"),
            "created": now,
            "modified": now,
            "name": pub_name,
            "description": desc,
            "threat_actor_types": ["criminal"],
            "created_by_ref": identity_id,
            "labels": ["malicious-publisher", "supply-chain"],
        })

    return {
        "type": "bundle",
        "id": _stix_id("bundle", f"openclaw-audit-ioc-{now}"),
        "objects": objects,
    }


def _finding_to_pattern(f: dict) -> str:
    """Convert a finding to a STIX pattern string."""
    path = f.get("path")
    if path:
        return f"[file:name = '{path.split('/')[-1]}']"
    module = f.get("module", "unknown")
    return f"[x-openclaw-finding:module = '{module}']"


def stix_to_json(bundle: dict[str, Any], indent: int = 2) -> str:
    """Serialize a STIX bundle to JSON."""
    return json.dumps(bundle, indent=indent)
