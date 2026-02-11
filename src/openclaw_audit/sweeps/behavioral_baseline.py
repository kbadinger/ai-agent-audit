"""Behavioral baseline & anomaly detection sweep."""

from __future__ import annotations

import json
import logging
import time

from ..config import (
    AUDIT_BASELINES,
    OPENCLAW_CREDENTIALS,
    OPENCLAW_EXTENSIONS,
    OPENCLAW_SKILLS,
)
from ..models import Finding, ModuleResult, Severity
from .base import BaseSweep

logger = logging.getLogger(__name__)

try:
    import psutil

    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

BASELINE_FILE = AUDIT_BASELINES / "behavioral.json"


def _count_files(directory) -> int:
    """Count files in a directory, returning 0 if it doesn't exist."""
    try:
        if not directory.exists():
            return 0
        return sum(1 for f in directory.rglob("*") if f.is_file())
    except OSError:
        return 0


def _count_dirs(directory) -> int:
    """Count immediate subdirectories, returning 0 if it doesn't exist."""
    try:
        if not directory.exists():
            return 0
        return sum(1 for d in directory.iterdir() if d.is_dir())
    except OSError:
        return 0


def _gather_current_state() -> dict:
    """Collect current behavioral metrics."""
    process_count = 0
    connection_count = 0
    listening_ports: list[int] = []

    if HAS_PSUTIL:
        for proc in psutil.process_iter(["pid", "cmdline"]):
            try:
                cmdline = " ".join(proc.info.get("cmdline") or []).lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if "openclaw" not in cmdline:
                continue
            process_count += 1
            try:
                for conn in proc.net_connections(kind="inet"):
                    connection_count += 1
                    if conn.status == "LISTEN" and conn.laddr:
                        listening_ports.append(conn.laddr.port)
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue

    return {
        "process_count": process_count,
        "connection_count": connection_count,
        "listening_ports": sorted(set(listening_ports)),
        "extension_file_count": _count_files(OPENCLAW_EXTENSIONS),
        "credential_file_count": _count_files(OPENCLAW_CREDENTIALS),
        "skill_count": _count_dirs(OPENCLAW_SKILLS),
        "timestamp": time.time(),
    }


def _load_baseline() -> dict | None:
    """Load stored baseline from disk, or None if it doesn't exist."""
    try:
        if BASELINE_FILE.exists():
            return json.loads(BASELINE_FILE.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to read baseline: %s", exc)
    return None


def _save_baseline(state: dict) -> None:
    """Save current state as the new baseline."""
    try:
        BASELINE_FILE.parent.mkdir(parents=True, exist_ok=True)
        BASELINE_FILE.write_text(json.dumps(state, indent=2))
    except OSError as exc:
        logger.warning("Failed to save baseline: %s", exc)


class BehavioralBaselineSweep(BaseSweep):
    name = "behavioral_baseline"

    def run(self) -> ModuleResult:
        findings: list[Finding] = []
        current = _gather_current_state()
        baseline = _load_baseline()

        if baseline is None:
            # First run: establish baseline
            _save_baseline(current)
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title="Behavioral baseline established",
                detail=(
                    f"{current['process_count']} processes, "
                    f"{current['connection_count']} connections, "
                    f"{current['extension_file_count']} extensions, "
                    f"{current['credential_file_count']} credentials, "
                    f"{current['skill_count']} skills"
                ),
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        # Compare current state to baseline
        anomaly_found = False

        # Process count 3x+ higher
        bl_procs = baseline.get("process_count", 0)
        if bl_procs > 0 and current["process_count"] >= bl_procs * 3:
            anomaly_found = True
            findings.append(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title="Process count spike",
                detail=(
                    f"Current: {current['process_count']}, "
                    f"baseline: {bl_procs} (3x+ increase)"
                ),
            ))

        # New listening ports
        bl_ports = set(baseline.get("listening_ports", []))
        new_ports = set(current["listening_ports"]) - bl_ports
        if new_ports:
            anomaly_found = True
            findings.append(Finding(
                module=self.name,
                severity=Severity.CRITICAL,
                title="New listening ports detected",
                detail=f"Ports not in baseline: {sorted(new_ports)}",
            ))

        # Extension file count changed >20%
        bl_ext = baseline.get("extension_file_count", 0)
        cur_ext = current["extension_file_count"]
        if bl_ext > 0 and abs(cur_ext - bl_ext) / bl_ext > 0.20:
            anomaly_found = True
            findings.append(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title="Extension file count changed significantly",
                detail=f"Current: {cur_ext}, baseline: {bl_ext} (>20% change)",
            ))

        # Credential file count changed at all
        bl_creds = baseline.get("credential_file_count", 0)
        cur_creds = current["credential_file_count"]
        if cur_creds != bl_creds:
            anomaly_found = True
            findings.append(Finding(
                module=self.name,
                severity=Severity.CRITICAL,
                title="Credential file count changed",
                detail=f"Current: {cur_creds}, baseline: {bl_creds}",
            ))

        # Skill count increased
        bl_skills = baseline.get("skill_count", 0)
        cur_skills = current["skill_count"]
        if cur_skills > bl_skills:
            anomaly_found = True
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title="New skills installed",
                detail=f"Current: {cur_skills}, baseline: {bl_skills}",
            ))

        # Connection count 5x+ higher
        bl_conns = baseline.get("connection_count", 0)
        if bl_conns > 0 and current["connection_count"] >= bl_conns * 5:
            anomaly_found = True
            findings.append(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title="Connection count spike",
                detail=(
                    f"Current: {current['connection_count']}, "
                    f"baseline: {bl_conns} (5x+ increase)"
                ),
            ))

        # No anomalies
        if not anomaly_found:
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title="Behavioral baseline: no anomalies",
                detail=(
                    f"{current['process_count']} processes, "
                    f"{current['connection_count']} connections, "
                    f"{current['extension_file_count']} extensions"
                ),
            ))

        # Update baseline with current values
        _save_baseline(current)

        return ModuleResult(module_name=self.name, findings=findings)
