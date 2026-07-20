"""Credential rotation tracking — alerts on stale or recently changed credentials."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from ..config import (
    AGENT_SENSITIVE_FILES,
    AUDIT_BASELINES,
    OPENCLAW_CREDENTIALS,
    OPENCLAW_ENV,
    OPENCLAW_HOME,
)
from ..models import Finding, ModuleResult, Severity
from .base import BaseSweep

logger = logging.getLogger(__name__)

BASELINE_FILE = AUDIT_BASELINES / "credential-ages.json"

# Thresholds in seconds
_STALE_THRESHOLD = 180 * 86400  # 180 days
_AGING_THRESHOLD = 90 * 86400   # 90 days
_RECENT_THRESHOLD = 3600        # 1 hour


def _credential_paths() -> list[Path]:
    """Gather all credential file paths to track."""
    paths: list[Path] = []

    # .env file
    if OPENCLAW_ENV.is_file():
        paths.append(OPENCLAW_ENV)

    paths.extend(path for path in AGENT_SENSITIVE_FILES if path.is_file())

    # All files in credentials directory
    if OPENCLAW_CREDENTIALS.is_dir():
        for p in OPENCLAW_CREDENTIALS.iterdir():
            if p.is_file():
                paths.append(p)

    # Auth profile files
    for p in OPENCLAW_HOME.glob("agents/*/agent/auth-profiles.json"):
        if p.is_file():
            paths.append(p)

    # SSH keys
    ssh_dir = Path.home() / ".ssh"
    if ssh_dir.is_dir():
        for p in ssh_dir.glob("id_*"):
            if p.is_file() and not p.suffix == ".pub":
                paths.append(p)

    return paths


class CredentialRotationSweep(BaseSweep):
    name = "credential_rotation"

    def run(self) -> ModuleResult:
        findings: list[Finding] = []
        now = time.time()

        # Load existing baseline
        baseline: dict[str, dict] = {}
        if BASELINE_FILE.exists():
            try:
                baseline = json.loads(BASELINE_FILE.read_text())
            except (json.JSONDecodeError, OSError):
                logger.warning("Could not read credential baseline, starting fresh")

        paths = _credential_paths()

        # Update baseline with current mtimes
        updated: dict[str, dict] = {}
        for p in paths:
            key = str(p)
            try:
                mtime = p.stat().st_mtime
            except OSError:
                continue

            if key in baseline:
                entry = baseline[key].copy()
                entry["mtime"] = mtime
            else:
                entry = {"mtime": mtime, "first_seen": now}

            updated[key] = entry

        # Generate findings
        for path_str, entry in updated.items():
            mtime = entry["mtime"]
            age_seconds = now - mtime

            if age_seconds > _STALE_THRESHOLD:
                days = int(age_seconds / 86400)
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title=f"Stale credential: {path_str} ({days} days old)",
                    detail=f"Credential has not been rotated in {days} days.",
                    path=path_str,
                ))
            elif age_seconds > _AGING_THRESHOLD:
                days = int(age_seconds / 86400)
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.WARNING,
                    title=f"Aging credential: {path_str} ({days} days old)",
                    detail=f"Credential has not been rotated in {days} days.",
                    path=path_str,
                ))

            if age_seconds < _RECENT_THRESHOLD:
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.INFO,
                    title=f"Recent credential change: {path_str}",
                    detail="Credential file was modified in the last hour.",
                    path=path_str,
                ))

        # Summary finding
        if updated:
            ages = [(now - e["mtime"]) / 86400 for e in updated.values()]
            oldest = int(max(ages))
            newest = int(min(ages))
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title=(
                    f"Credential rotation: tracking {len(updated)} files, "
                    f"oldest {oldest} days, newest {newest} days"
                ),
                detail="Summary of tracked credential files.",
            ))
        else:
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title="Credential rotation: no credential files found",
                detail="No credential files were found to track.",
            ))

        # Persist baseline
        BASELINE_FILE.parent.mkdir(parents=True, exist_ok=True)
        BASELINE_FILE.write_text(json.dumps(updated, indent=2))

        return ModuleResult(module_name=self.name, findings=findings)
