"""Monitor file permissions under OPENCLAW_HOME."""

from __future__ import annotations

import logging
import os
import stat
import threading
from fnmatch import fnmatch
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from ..config import (
    EXPECTED_PERMISSIONS,
    MONITOR_POLL_INTERVAL_SECONDS,
    OPENCLAW_HOME,
    SENSITIVE_FILE_PATTERNS,
)
from ..models import Finding, Severity
from .base import BaseMonitor

logger = logging.getLogger(__name__)


class _PermissionHandler(FileSystemEventHandler):
    def __init__(self, monitor: PermissionMonitor):
        self._monitor = monitor

    def on_any_event(self, event) -> None:
        if event.is_directory and event.event_type not in ("created", "modified"):
            return
        self._monitor._check_path(Path(event.src_path))


class PermissionMonitor(BaseMonitor):
    """Flags files with permissions looser than expected."""

    name = "permission_monitor"

    def __init__(self, on_finding, home_path: Path | None = None):
        super().__init__(on_finding)
        self._home = home_path or OPENCLAW_HOME
        self._observer: Observer | None = None
        self._poll_thread: threading.Thread | None = None

    def start(self) -> None:
        self._running.set()

        if not self._home.exists():
            logger.warning("OpenClaw home %s does not exist, skipping permission monitor", self._home)
            return

        # Initial full scan
        self._full_scan()

        # Watchdog for real-time events
        self._observer = Observer()
        self._observer.schedule(_PermissionHandler(self), str(self._home), recursive=True)
        self._observer.daemon = True
        self._observer.start()

        # Polling thread for periodic re-check
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
        while self._running.is_set():
            self._running.wait(timeout=MONITOR_POLL_INTERVAL_SECONDS)
            if not self._running.is_set():
                break
            self._full_scan()

    def _full_scan(self) -> None:
        if not self._home.exists():
            return
        for path in self._home.rglob("*"):
            if not self._running.is_set():
                break
            self._check_path(path)

    def _check_path(self, path: Path) -> None:
        if not path.exists():
            return

        try:
            mode = path.stat().st_mode
        except OSError:
            return

        file_perm = stat.S_IMODE(mode)

        # Check against explicit path rules
        for expected_path, max_perm in EXPECTED_PERMISSIONS.items():
            if path == expected_path:
                if file_perm & ~max_perm:
                    self.report_finding(Finding(
                        module=self.name,
                        severity=Severity.WARNING,
                        title=f"Overly permissive: {path.name}",
                        detail=f"{path} has permissions {oct(file_perm)}, expected at most {oct(max_perm)}.",
                        path=str(path),
                    ))
                return

        # Check against sensitive file glob patterns
        try:
            rel = path.relative_to(self._home)
        except ValueError:
            return

        for pattern in SENSITIVE_FILE_PATTERNS:
            if fnmatch(str(rel), pattern):
                if file_perm & ~0o600:
                    self.report_finding(Finding(
                        module=self.name,
                        severity=Severity.WARNING,
                        title=f"Sensitive file too open: {path.name}",
                        detail=f"{path} has permissions {oct(file_perm)}, expected at most 0o600.",
                        path=str(path),
                    ))
                break
