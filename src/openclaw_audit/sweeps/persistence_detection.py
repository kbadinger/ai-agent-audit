"""Detect unauthorized persistence mechanisms (LaunchAgents, cron, systemd)."""

from __future__ import annotations

import logging
import os
import platform
import subprocess
from pathlib import Path

from ..models import Finding, ModuleResult, Severity
from .base import BaseSweep

logger = logging.getLogger(__name__)

# Keywords that indicate OpenClaw-related persistence
_OPENCLAW_KEYWORDS = {"openclaw", "clawdbot", "moltbot"}

# Our own audit daemon name (expected, not a threat)
_OUR_DAEMON = "openclaw-audit"


def _mentions_openclaw(text: str) -> bool:
    """Check if text mentions any OpenClaw-related keywords."""
    lower = text.lower()
    return any(kw in lower for kw in _OPENCLAW_KEYWORDS)


def _is_our_audit_daemon(text: str) -> bool:
    """Check if persistence entry is our own audit daemon."""
    return _OUR_DAEMON in text.lower()


class PersistenceDetectionSweep(BaseSweep):
    name = "persistence_detection"

    def run(self) -> ModuleResult:
        findings: list[Finding] = []
        system = platform.system()

        if system == "Darwin":
            self._check_launch_agents(findings)
            self._check_launch_daemons(findings)
        elif system == "Linux":
            self._check_systemd(findings)

        self._check_crontab(findings)

        return ModuleResult(module_name=self.name, findings=findings)

    def _check_launch_agents(self, findings: list[Finding]) -> None:
        """Check ~/Library/LaunchAgents for OpenClaw-related plists."""
        agents_dir = Path.home() / "Library" / "LaunchAgents"
        if not agents_dir.is_dir():
            return

        try:
            for plist in agents_dir.iterdir():
                if not plist.is_file():
                    continue
                try:
                    content = plist.read_text(errors="ignore")
                except OSError:
                    continue
                if _mentions_openclaw(content):
                    if _is_our_audit_daemon(content):
                        continue
                    findings.append(Finding(
                        module=self.name,
                        severity=Severity.WARNING,
                        title=f"OpenClaw LaunchAgent: {plist.name}",
                        detail="Plist referencing OpenClaw found in user LaunchAgents.",
                        path=str(plist),
                    ))
        except OSError:
            pass

    def _check_launch_daemons(self, findings: list[Finding]) -> None:
        """Check /Library/LaunchDaemons for OpenClaw-related plists."""
        daemons_dir = Path("/Library/LaunchDaemons")
        if not daemons_dir.is_dir():
            return

        try:
            for plist in daemons_dir.iterdir():
                if not plist.is_file():
                    continue
                try:
                    content = plist.read_text(errors="ignore")
                except OSError:
                    continue
                if _mentions_openclaw(content):
                    if _is_our_audit_daemon(content):
                        continue
                    findings.append(Finding(
                        module=self.name,
                        severity=Severity.WARNING,
                        title=f"OpenClaw LaunchDaemon: {plist.name}",
                        detail="Plist referencing OpenClaw found in system LaunchDaemons.",
                        path=str(plist),
                    ))
        except OSError:
            pass

    def _check_systemd(self, findings: list[Finding]) -> None:
        """Check systemd user units for OpenClaw references."""
        try:
            result = subprocess.run(
                ["systemctl", "--user", "list-unit-files"],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                if _mentions_openclaw(line) and not _is_our_audit_daemon(line):
                    findings.append(Finding(
                        module=self.name,
                        severity=Severity.WARNING,
                        title=f"OpenClaw systemd unit: {line.split()[0]}",
                        detail=f"Systemd user unit referencing OpenClaw: {line.strip()}",
                    ))
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

    def _check_crontab(self, findings: list[Finding]) -> None:
        """Check crontab for OpenClaw references."""
        try:
            result = subprocess.run(
                ["crontab", "-l"],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                line_stripped = line.strip()
                if line_stripped.startswith("#"):
                    continue
                if _mentions_openclaw(line_stripped) and not _is_our_audit_daemon(line_stripped):
                    findings.append(Finding(
                        module=self.name,
                        severity=Severity.WARNING,
                        title="OpenClaw crontab entry",
                        detail=f"Cron job referencing OpenClaw: {line_stripped[:200]}",
                    ))
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
