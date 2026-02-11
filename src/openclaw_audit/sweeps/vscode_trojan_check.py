"""VS Code fake extension / trojan detection sweep."""

from __future__ import annotations

import logging
from pathlib import Path

from ..models import Finding, ModuleResult, Severity
from .base import BaseSweep

logger = logging.getLogger(__name__)

# Patterns to match in VS Code extension directory names
_EXTENSION_PATTERNS = ["clawdbot", "openclaw", "moltbot"]

# VS Code extension directories to scan
_EXTENSION_DIRS = [
    Path.home() / ".vscode" / "extensions",
    Path.home() / ".vscode-server" / "extensions",
]

# Known remote-access trojans disguised as apps
_TROJAN_APP_PATTERNS = [
    "ScreenConnect",
    "ConnectWise",
]

# Application directories to check
_APP_DIRS = [
    Path("/Applications"),
    Path.home() / "Applications",
]


class VSCodeTrojanCheckSweep(BaseSweep):
    name = "vscode_trojan_check"

    def run(self) -> ModuleResult:
        findings: list[Finding] = []

        # Scan VS Code extension directories for fake extensions
        for ext_dir in _EXTENSION_DIRS:
            if not ext_dir.is_dir():
                continue
            try:
                entries = list(ext_dir.iterdir())
            except OSError:
                continue
            for entry in entries:
                name_lower = entry.name.lower()
                for pattern in _EXTENSION_PATTERNS:
                    if pattern in name_lower:
                        findings.append(Finding(
                            module=self.name,
                            severity=Severity.CRITICAL,
                            title=f"Fake OpenClaw VS Code extension: {entry.name}",
                            detail=(
                                "OpenClaw has no official VS Code extension. "
                                "This is a known trojan distribution method. "
                                "Remove this extension immediately."
                            ),
                            path=str(entry),
                        ))
                        break

        # Check for ScreenConnect/ConnectWise artifacts
        for app_dir in _APP_DIRS:
            if not app_dir.is_dir():
                continue
            try:
                entries = list(app_dir.iterdir())
            except OSError:
                continue
            for entry in entries:
                name_lower = entry.name.lower()
                for pattern in _TROJAN_APP_PATTERNS:
                    if pattern.lower() in name_lower:
                        findings.append(Finding(
                            module=self.name,
                            severity=Severity.CRITICAL,
                            title=f"Remote access tool found: {entry.name}",
                            detail=(
                                f"'{entry.name}' found in {app_dir}. "
                                "ScreenConnect/ConnectWise is used by the ClawHavoc "
                                "campaign for persistent remote access. "
                                "Verify this was intentionally installed."
                            ),
                            path=str(entry),
                        ))
                        break

        return ModuleResult(module_name=self.name, findings=findings)
