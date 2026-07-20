"""Monitor credential files for unexpected changes and hardcoded secrets."""

from __future__ import annotations

import hashlib
import logging
import re
import threading
from pathlib import Path

from ..config import (
    AGENT_SENSITIVE_FILES,
    MONITOR_POLL_INTERVAL_SECONDS,
    OPENCLAW_CREDENTIALS,
    OPENCLAW_ENV,
    SECRET_PATTERNS,
)
from ..models import Finding, Severity
from .base import BaseMonitor

logger = logging.getLogger(__name__)


def _hash_file(path: Path) -> str | None:
    """Return SHA-256 hex digest of a file, or None if unreadable."""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


class CredentialGuard(BaseMonitor):
    """Detects credential file tampering and hardcoded secrets."""

    name = "credential_guard"

    def __init__(
        self,
        on_finding,
        creds_dir: Path | None = None,
        env_path: Path | None = None,
        sensitive_files: tuple[Path, ...] | None = None,
    ):
        super().__init__(on_finding)
        self._creds_dir = creds_dir or OPENCLAW_CREDENTIALS
        self._env_path = env_path or OPENCLAW_ENV
        self._sensitive_files = sensitive_files if sensitive_files is not None else AGENT_SENSITIVE_FILES
        self._hashes: dict[str, str] = {}
        self._poll_thread: threading.Thread | None = None

    def start(self) -> None:
        self._running.set()
        # Build initial baseline
        self._hashes = self._snapshot()
        # Scan for secrets on start
        self._scan_secrets()

        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._poll_thread.start()

    def stop(self) -> None:
        self._running.clear()
        if self._poll_thread:
            self._poll_thread.join(timeout=5)
            self._poll_thread = None

    def _poll_loop(self) -> None:
        while self._running.is_set():
            self._running.wait(timeout=MONITOR_POLL_INTERVAL_SECONDS)
            if not self._running.is_set():
                break
            self._check_changes()
            self._scan_secrets()

    def _watched_files(self) -> list[Path]:
        """Return all files we should track."""
        files: list[Path] = []
        if self._env_path.exists():
            files.append(self._env_path)
        files.extend(path for path in self._sensitive_files if path.is_file())
        if self._creds_dir.exists():
            files.extend(f for f in self._creds_dir.rglob("*") if f.is_file())
        return files

    def _snapshot(self) -> dict[str, str]:
        """Hash all watched files."""
        result: dict[str, str] = {}
        for f in self._watched_files():
            h = _hash_file(f)
            if h is not None:
                result[str(f)] = h
        return result

    def _check_changes(self) -> None:
        current = self._snapshot()

        # Check for modified or deleted files
        for path_str, old_hash in self._hashes.items():
            new_hash = current.get(path_str)
            if new_hash is None:
                self.report_finding(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title="Credential file deleted",
                    detail=f"{path_str} was removed.",
                    path=path_str,
                ))
            elif new_hash != old_hash:
                self.report_finding(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title="Credential file modified",
                    detail=f"{path_str} hash changed unexpectedly.",
                    path=path_str,
                ))

        # Check for new files
        for path_str in current:
            if path_str not in self._hashes:
                self.report_finding(Finding(
                    module=self.name,
                    severity=Severity.WARNING,
                    title="New credential file",
                    detail=f"{path_str} appeared in credentials directory.",
                    path=path_str,
                ))

        self._hashes = current

    def _scan_secrets(self) -> None:
        """Scan file contents for hardcoded secrets."""
        for f in self._watched_files():
            try:
                content = f.read_text(errors="replace")
            except OSError:
                continue
            for secret_name, pattern in SECRET_PATTERNS.items():
                if re.search(pattern, content):
                    self.report_finding(Finding(
                        module=self.name,
                        severity=Severity.CRITICAL,
                        title=f"Hardcoded secret: {secret_name}",
                        detail=f"Pattern for '{secret_name}' found in {f.name}.",
                        path=str(f),
                    ))
