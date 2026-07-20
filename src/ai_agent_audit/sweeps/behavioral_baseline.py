"""Behavioral baseline & anomaly detection sweep with rolling window."""

from __future__ import annotations

import json
import logging
import math
import time

from ..config import (
    ACTIVE_PROFILE,
    AUDIT_BASELINES,
    OPENCLAW_CREDENTIALS,
    OPENCLAW_EXTENSIONS,
    OPENCLAW_SKILLS,
)
from ..models import Finding, ModuleResult, ModuleStatus, Severity
from .base import BaseSweep

logger = logging.getLogger(__name__)

try:
    import psutil

    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

BASELINE_FILE = AUDIT_BASELINES / "behavioral.json"
WINDOW_SIZE = 7  # Rolling window: keep last 7 snapshots
_PROCESS_KEYWORDS = tuple(kw.lower() for kw in ACTIVE_PROFILE.process_keywords)


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
    process_visible = HAS_PSUTIL

    if HAS_PSUTIL:
        try:
            processes = list(psutil.process_iter(["pid", "cmdline"]))
        except (psutil.Error, OSError):
            processes = []
            process_visible = False
        for proc in processes:
            try:
                cmdline = " ".join(proc.info.get("cmdline") or []).lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if not any(kw in cmdline for kw in _PROCESS_KEYWORDS):
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
        "process_visible": process_visible,
        "extension_file_count": _count_files(OPENCLAW_EXTENSIONS),
        "credential_file_count": _count_files(OPENCLAW_CREDENTIALS),
        "skill_count": _count_dirs(OPENCLAW_SKILLS),
        "timestamp": time.time(),
    }


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _stddev(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    m = _mean(values)
    variance = sum((v - m) ** 2 for v in values) / (len(values) - 1)
    return math.sqrt(variance)


def _load_window() -> list[dict]:
    """Load rolling window from disk. Handles migration from old single-snapshot format."""
    try:
        if not BASELINE_FILE.exists():
            return []
        data = json.loads(BASELINE_FILE.read_text())
        # Migration: old format was a single dict, new format is a list
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return data
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to read baseline: %s", exc)
    return []


def _save_window(window: list[dict]) -> None:
    """Save rolling window to disk, trimmed to WINDOW_SIZE."""
    trimmed = window[-WINDOW_SIZE:]
    try:
        BASELINE_FILE.parent.mkdir(parents=True, exist_ok=True)
        BASELINE_FILE.write_text(json.dumps(trimmed, indent=2))
    except OSError as exc:
        logger.warning("Failed to save baseline: %s", exc)


def _is_anomaly(current: float, history: list[float]) -> bool:
    """Return True if current value is > mean + 2*stddev of history."""
    if len(history) < 2:
        return False
    m = _mean(history)
    sd = _stddev(history)
    # If stddev is 0 (all same values), any increase is anomalous
    if sd == 0:
        return current > m
    return current > m + 2 * sd


class BehavioralBaselineSweep(BaseSweep):
    name = "behavioral_baseline"

    def run(self) -> ModuleResult:
        findings: list[Finding] = []
        current = _gather_current_state()
        window = _load_window()

        if not window:
            # First run: establish baseline
            _save_window([current])
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
            return ModuleResult(
                module_name=self.name,
                findings=findings,
                status=ModuleStatus.OK if current["process_visible"] else ModuleStatus.DEGRADED,
                message=None if current["process_visible"] else "Process visibility unavailable",
            )

        anomaly_found = False

        # Extract historical values for each metric
        visible_history = [s for s in window if s.get("process_visible", True)]
        hist_procs = [s.get("process_count", 0) for s in visible_history]
        hist_conns = [s.get("connection_count", 0) for s in visible_history]
        hist_ext = [s.get("extension_file_count", 0) for s in window]
        hist_creds = [s.get("credential_file_count", 0) for s in window]
        hist_skills = [s.get("skill_count", 0) for s in window]

        # Process count anomaly (mean + 2σ)
        if current["process_visible"] and hist_procs and _is_anomaly(current["process_count"], hist_procs):
            anomaly_found = True
            findings.append(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title="Process count spike",
                detail=(
                    f"Current: {current['process_count']}, "
                    f"rolling avg: {_mean(hist_procs):.1f} ± {_stddev(hist_procs):.1f}"
                ),
            ))

        # New listening ports (still set-based — ports are categorical, not numeric)
        all_hist_ports: set[int] = set()
        for s in window:
            all_hist_ports.update(s.get("listening_ports", []))
        new_ports = set(current["listening_ports"]) - all_hist_ports
        if current["process_visible"] and new_ports:
            anomaly_found = True
            findings.append(Finding(
                module=self.name,
                severity=Severity.CRITICAL,
                title="New listening ports detected",
                detail=f"Ports not in baseline: {sorted(new_ports)}",
            ))

        # Extension file count anomaly
        if hist_ext and _is_anomaly(current["extension_file_count"], hist_ext):
            anomaly_found = True
            findings.append(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title="Extension file count changed significantly",
                detail=(
                    f"Current: {current['extension_file_count']}, "
                    f"rolling avg: {_mean(hist_ext):.1f} ± {_stddev(hist_ext):.1f}"
                ),
            ))

        # Credential file count — any change is significant
        if hist_creds and current["credential_file_count"] != hist_creds[-1]:
            anomaly_found = True
            findings.append(Finding(
                module=self.name,
                severity=Severity.CRITICAL,
                title="Credential file count changed",
                detail=f"Current: {current['credential_file_count']}, previous: {hist_creds[-1]}",
            ))

        # Skill count increased
        if hist_skills and current["skill_count"] > hist_skills[-1]:
            anomaly_found = True
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title="New skills installed",
                detail=f"Current: {current['skill_count']}, previous: {hist_skills[-1]}",
            ))

        # Connection count anomaly
        if current["process_visible"] and hist_conns and _is_anomaly(current["connection_count"], hist_conns):
            anomaly_found = True
            findings.append(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title="Connection count spike",
                detail=(
                    f"Current: {current['connection_count']}, "
                    f"rolling avg: {_mean(hist_conns):.1f} ± {_stddev(hist_conns):.1f}"
                ),
            ))

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

        # Append current to rolling window and save
        window.append(current)
        _save_window(window)

        return ModuleResult(
            module_name=self.name,
            findings=findings,
            status=ModuleStatus.OK if current["process_visible"] else ModuleStatus.DEGRADED,
            message=None if current["process_visible"] else "Process visibility unavailable",
        )
