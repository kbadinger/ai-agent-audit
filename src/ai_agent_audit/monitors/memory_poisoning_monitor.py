"""Monitor memory/identity files for prompt injection attacks."""

from __future__ import annotations

import json
import logging
import re
import threading
from pathlib import Path

from watchdog.events import FileSystemEventHandler, FileModifiedEvent
from watchdog.observers import Observer

from ..config import (
    INJECTION_PATTERNS,
    MEMORY_FILES,
    MONITOR_POLL_INTERVAL_SECONDS,
    OPENCLAW_CONFIG,
    OPENCLAW_WORKSPACE,
)
from ..models import Finding, Severity
from .base import BaseMonitor

logger = logging.getLogger(__name__)

# Additional injection markers beyond those in config.INJECTION_PATTERNS
_EXTRA_MARKERS = [
    {"name": "Ignore previous", "pattern": r"(?i)ignore\s+previous"},
    {"name": "System prompt marker", "pattern": r"(?i)\[system\s*prompt\]"},
    {"name": "Role override (assistant)", "pattern": r"(?i)you\s+are\s+(an?\s+)?(evil|malicious|unrestricted|unfiltered)"},
    {"name": "Hidden instruction", "pattern": r"(?i)<hidden>|<!--\s*(instruction|inject|override)"},
]

# "Promptware" / C2-brainworm markers: memory-file instructions that make the
# agent register with, beacon to, or phone home to an external controller.
_PROMPTWARE_MARKERS = [
    {"name": "C2 registration instruction",
     "pattern": r"(?i)(register|check[\s\-]?in|enroll|sign[\s\-]?in)\s+(with|to|at)\s+(https?://|[\w.\-]+\.[a-z]{2,}|the\s+(c2|server|controller))"},
    {"name": "Beacon / phone-home instruction",
     "pattern": r"(?i)(beacon|phone[\s\-]?home|report\s+back|call\s+home|ping)\s+(to|back\s+to|home\s+to|the)\b"},
    {"name": "Startup connect-out instruction",
     "pattern": r"(?i)(on|at)\s+(startup|launch|boot|every\s+(session|run))[^\n]{0,60}(connect|contact|fetch|download|execute|post|send)"},
    {"name": "Exfil-to-endpoint instruction",
     "pattern": r"(?i)(send|post|upload|exfiltrate|transmit)\s+[^\n]{0,60}(to\s+)?(https?://|c2\b|command[\s&]+control)"},
]


class _MemoryFileHandler(FileSystemEventHandler):
    def __init__(self, monitor: MemoryPoisoningMonitor):
        self._monitor = monitor

    def on_modified(self, event: FileModifiedEvent) -> None:  # type: ignore[override]
        path = Path(event.src_path)
        if path.name in MEMORY_FILES:
            self._monitor._check_file(path)


class MemoryPoisoningMonitor(BaseMonitor):
    """Watches workspace memory files for injection patterns."""

    # Must match the mappings.py module key so findings are enriched (MITRE/OWASP).
    name = "memory_poisoning_monitor"

    def __init__(self, on_finding, workspace: Path | None = None):
        super().__init__(on_finding)
        self._workspace = workspace or OPENCLAW_WORKSPACE
        self._observer: Observer | None = None
        self._poll_thread: threading.Thread | None = None

    def start(self) -> None:
        self._running.set()

        # Initial scan
        self._scan_all()

        # Try watchdog-based monitoring
        if self._workspace.exists():
            try:
                self._observer = Observer()
                self._observer.schedule(
                    _MemoryFileHandler(self),
                    str(self._workspace),
                    recursive=True,
                )
                self._observer.daemon = True
                self._observer.start()
                logger.info("[%s] Watchdog observer started for %s", self.name, self._workspace)
                return
            except Exception as exc:
                logger.warning("[%s] Watchdog failed, falling back to polling: %s", self.name, exc)

        # Fallback: poll-based monitoring
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._poll_thread.start()

    def stop(self) -> None:
        self._running.clear()
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None
        if self._poll_thread:
            self._poll_thread.join(timeout=5)
            self._poll_thread = None

    def _poll_loop(self) -> None:
        """Poll memory files at regular intervals."""
        while self._running.is_set():
            self._scan_all()
            self._running.wait(MONITOR_POLL_INTERVAL_SECONDS)

    def _scan_all(self) -> None:
        """Scan all known memory files and config extra paths."""
        self._check_extra_paths()
        if not self._workspace.exists():
            return
        for fname in MEMORY_FILES:
            fpath = self._workspace / fname
            if fpath.exists():
                self._check_file(fpath)

    def _check_extra_paths(self) -> None:
        """Check memory.extraPaths for path traversal escaping the workspace."""
        if not OPENCLAW_CONFIG.exists():
            return
        try:
            data = json.loads(OPENCLAW_CONFIG.read_text())
        except (json.JSONDecodeError, OSError):
            return
        extra_paths = (data.get("memory") or {}).get("extraPaths") or []
        if not isinstance(extra_paths, list):
            return
        workspace = str(self._workspace.resolve())
        for p in extra_paths:
            if not isinstance(p, str):
                continue
            try:
                resolved = str((self._workspace / p).resolve())
            except (OSError, ValueError):
                continue
            if not resolved.startswith(workspace + "/") and resolved != workspace:
                self.report_finding(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title="Memory extraPaths escapes workspace",
                    detail=(
                        f"memory.extraPaths entry '{p}' resolves to '{resolved}' "
                        f"which is outside the workspace '{workspace}'. "
                        "An attacker could read or poison files outside the workspace."
                    ),
                    path=str(OPENCLAW_CONFIG),
                ))

    def _check_file(self, fpath: Path) -> None:
        """Check a single file for injection patterns."""
        try:
            content = fpath.read_text(errors="ignore")
        except OSError:
            return

        # Check patterns from config
        for rule in INJECTION_PATTERNS:
            if re.search(rule["pattern"], content):
                self.report_finding(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title=f"Injection pattern in {fpath.name}: {rule['name']}",
                    detail=f"Pattern '{rule['name']}' detected in memory file.",
                    path=str(fpath),
                ))

        # Check extra markers
        for marker in _EXTRA_MARKERS:
            if re.search(marker["pattern"], content):
                self.report_finding(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title=f"Injection marker in {fpath.name}: {marker['name']}",
                    detail=f"Injection marker '{marker['name']}' detected in memory file.",
                    path=str(fpath),
                ))

        # Check promptware / C2-registration markers
        for marker in _PROMPTWARE_MARKERS:
            if re.search(marker["pattern"], content):
                self.report_finding(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title=f"Promptware C2 instruction in {fpath.name}: {marker['name']}",
                    detail=(
                        f"Memory file instructs the agent to {marker['name'].lower()} "
                        "— a promptware / C2-brainworm pattern. Treat the host as "
                        "potentially compromised and remove the injected content."
                    ),
                    path=str(fpath),
                ))
