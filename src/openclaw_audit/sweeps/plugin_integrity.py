"""Extension/plugin integrity verification via SHA-256 baselines."""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

from ..config import AUDIT_BASELINES, OPENCLAW_EXTENSIONS
from ..models import Finding, ModuleResult, Severity
from .base import BaseSweep

logger = logging.getLogger(__name__)

BASELINE_FILE = AUDIT_BASELINES / "extensions.json"

SUSPICIOUS_SCRIPTS = {"preinstall", "postinstall", "preuninstall", "postuninstall"}
SUSPICIOUS_COMMANDS = {"curl", "wget", "eval"}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _hash_all_files(root: Path) -> dict[str, str]:
    """Return {relative_path: sha256} for all files under root."""
    hashes: dict[str, str] = {}
    if not root.is_dir():
        return hashes
    for path in sorted(root.rglob("*")):
        if path.is_file():
            try:
                rel = str(path.relative_to(root))
                hashes[rel] = _sha256(path)
            except OSError:
                continue
    return hashes


class PluginIntegritySweep(BaseSweep):
    name = "plugin_integrity"

    def run(self) -> ModuleResult:
        findings: list[Finding] = []

        if not OPENCLAW_EXTENSIONS.exists():
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title="Extensions directory not found",
                detail=f"{OPENCLAW_EXTENSIONS} does not exist.",
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        current_hashes = _hash_all_files(OPENCLAW_EXTENSIONS)

        # Check package.json files for suspicious scripts
        for pkg_json in OPENCLAW_EXTENSIONS.rglob("package.json"):
            try:
                data = json.loads(pkg_json.read_text())
            except (json.JSONDecodeError, OSError):
                continue
            scripts = data.get("scripts", {})
            for script_name, script_cmd in scripts.items():
                if script_name in SUSPICIOUS_SCRIPTS:
                    cmd_lower = script_cmd.lower()
                    for suspicious in SUSPICIOUS_COMMANDS:
                        if suspicious in cmd_lower:
                            findings.append(Finding(
                                module=self.name,
                                severity=Severity.CRITICAL,
                                title=f"Suspicious {script_name} script",
                                detail=(
                                    f"'{suspicious}' found in {script_name}: "
                                    f"{script_cmd[:200]}"
                                ),
                                path=str(pkg_json),
                            ))

        # Compare against baseline
        if not BASELINE_FILE.exists():
            # First run: create the baseline
            BASELINE_FILE.parent.mkdir(parents=True, exist_ok=True)
            BASELINE_FILE.write_text(json.dumps(current_hashes, indent=2))
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title="Baseline created",
                detail=f"Initial baseline saved with {len(current_hashes)} files.",
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        try:
            baseline = json.loads(BASELINE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            findings.append(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title="Baseline file corrupt",
                detail=f"Could not read {BASELINE_FILE}.",
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        baseline_keys = set(baseline.keys())
        current_keys = set(current_hashes.keys())

        # New files
        for f in sorted(current_keys - baseline_keys):
            findings.append(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title="New extension file",
                detail=f"File added since baseline.",
                path=str(OPENCLAW_EXTENSIONS / f),
            ))

        # Removed files
        for f in sorted(baseline_keys - current_keys):
            findings.append(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title="Extension file removed",
                detail=f"File present in baseline is now missing.",
                path=str(OPENCLAW_EXTENSIONS / f),
            ))

        # Changed files
        for f in sorted(baseline_keys & current_keys):
            if baseline[f] != current_hashes[f]:
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title="Extension file modified",
                    detail=(
                        f"Hash changed from {baseline[f][:16]}... "
                        f"to {current_hashes[f][:16]}..."
                    ),
                    path=str(OPENCLAW_EXTENSIONS / f),
                ))

        # Update baseline with current state
        try:
            BASELINE_FILE.write_text(json.dumps(current_hashes, indent=2))
        except OSError:
            logger.warning("Failed to update plugin baseline")

        return ModuleResult(module_name=self.name, findings=findings)
