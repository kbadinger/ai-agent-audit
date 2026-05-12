"""Detect unauthorized persistence mechanisms (LaunchAgents, cron, systemd)."""

from __future__ import annotations

import logging
import os
import platform
import subprocess
from pathlib import Path

from ..config import ACTIVE_PROFILE
from ..models import Finding, ModuleResult, Severity
from .base import BaseSweep

logger = logging.getLogger(__name__)

# Keywords that indicate active-agent-related persistence
_AGENT_KEYWORDS = {kw.lower() for kw in ACTIVE_PROFILE.persistence_keywords}

# Our own audit daemon name (expected, not a threat)
_OUR_DAEMON = "ai-agent-audit"


def _mentions_agent(text: str) -> bool:
    """Check if text mentions any of the active agent's persistence keywords."""
    lower = text.lower()
    return any(kw in lower for kw in _AGENT_KEYWORDS)


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
        """Check ~/Library/LaunchAgents for active-agent-related plists."""
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
                if _mentions_agent(content):
                    if _is_our_audit_daemon(content):
                        continue
                    findings.append(Finding(
                        module=self.name,
                        severity=Severity.WARNING,
                        title=f"{ACTIVE_PROFILE.display_name} LaunchAgent: {plist.name}",
                        detail=f"Plist referencing {ACTIVE_PROFILE.display_name} found in user LaunchAgents.",
                        path=str(plist),
                    ))
        except OSError:
            pass

    def _check_launch_daemons(self, findings: list[Finding]) -> None:
        """Check /Library/LaunchDaemons for active-agent-related plists."""
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
                if _mentions_agent(content):
                    if _is_our_audit_daemon(content):
                        continue
                    findings.append(Finding(
                        module=self.name,
                        severity=Severity.WARNING,
                        title=f"{ACTIVE_PROFILE.display_name} LaunchDaemon: {plist.name}",
                        detail=f"Plist referencing {ACTIVE_PROFILE.display_name} found in system LaunchDaemons.",
                        path=str(plist),
                    ))
        except OSError:
            pass

    def _check_systemd(self, findings: list[Finding]) -> None:
        """Check systemd user units for active-agent references."""
        try:
            result = subprocess.run(
                ["systemctl", "--user", "list-unit-files"],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                if _mentions_agent(line) and not _is_our_audit_daemon(line):
                    findings.append(Finding(
                        module=self.name,
                        severity=Severity.WARNING,
                        title=f"{ACTIVE_PROFILE.display_name} systemd unit: {line.split()[0]}",
                        detail=f"Systemd user unit referencing {ACTIVE_PROFILE.display_name}: {line.strip()}",
                    ))
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

    def _check_crontab(self, findings: list[Finding]) -> None:
        """Check crontab for active-agent references."""
        try:
            result = subprocess.run(
                ["crontab", "-l"],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                line_stripped = line.strip()
                if line_stripped.startswith("#"):
                    continue
                if _mentions_agent(line_stripped) and not _is_our_audit_daemon(line_stripped):
                    findings.append(Finding(
                        module=self.name,
                        severity=Severity.WARNING,
                        title=f"{ACTIVE_PROFILE.display_name} crontab entry",
                        detail=f"Cron job referencing {ACTIVE_PROFILE.display_name}: {line_stripped[:200]}",
                    ))
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
