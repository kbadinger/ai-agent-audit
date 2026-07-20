"""Detect CVE-2026-28363: safeBins sandbox bypass (CVSS 9.9).

Checks for sandbox.safeBins configurations vulnerable to symlink escapes,
PATH manipulation, and binary name collision bypasses.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path

from ..agent_config import AgentConfigError, get_nested, load_agent_config
from ..config import ACTIVE_PROFILE, OPENCLAW_CONFIG, OPENCLAW_HOME
from ..models import Finding, ModuleResult, Severity
from .base import BaseSweep

logger = logging.getLogger(__name__)

# Binaries known to be exploitable for sandbox escape via CVE-2026-28363
_DANGEROUS_BINS = {
    "bash", "sh", "zsh", "dash", "ksh", "csh", "tcsh", "fish",
    "python", "python3", "perl", "ruby", "node", "php", "lua",
    "env",  # env can be used to bypass PATH restrictions
    "script",  # can spawn a shell
    "expect",  # can automate interactive programs
    "awk", "gawk", "mawk",  # can execute system commands
    "find",  # -exec flag
    "xargs",  # command chaining
    "nohup",  # can wrap arbitrary commands
    "strace", "ltrace",  # can attach to processes
}

# Patterns in safeBins entries that indicate bypass risk
_BYPASS_PATTERNS = [
    (r"\.\.", "Path traversal (..) in safeBins entry"),
    (r"[*?]", "Glob/wildcard in safeBins entry"),
    (r"^~", "Tilde expansion in safeBins entry"),
    (r"\$", "Variable expansion in safeBins entry"),
]


class SafeBinsBypassSweep(BaseSweep):
    name = "safebins_bypass"

    def run(self) -> ModuleResult:
        findings: list[Finding] = []

        if not OPENCLAW_CONFIG.exists():
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title=f"{ACTIVE_PROFILE.display_name} config not found",
                detail=f"{OPENCLAW_CONFIG} does not exist — cannot check safeBins.",
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        try:
            data = load_agent_config(OPENCLAW_CONFIG)
        except AgentConfigError as exc:
            findings.append(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title="Config unreadable",
                detail=f"Could not parse {OPENCLAW_CONFIG}: {exc}",
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        sandbox = get_nested(data, "agents.defaults.sandbox") or data.get("sandbox", {})
        if not isinstance(sandbox, dict):
            return ModuleResult(module_name=self.name, findings=findings)

        # Check if sandbox is even enabled
        mode = sandbox.get("mode")
        enabled = sandbox.get("enabled")
        if enabled is False or (
            isinstance(mode, str) and mode.lower() in {"off", "none", "disabled"}
        ):
            findings.append(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title="Sandbox disabled — safeBins irrelevant",
                detail="The agent sandbox is disabled. safeBins restrictions have no effect.",
                path=str(OPENCLAW_CONFIG),
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        safe_bins = sandbox.get("safeBins")
        if safe_bins is None:
            safe_bins = get_nested(data, "tools.exec.safeBins") or []
        if not isinstance(safe_bins, list):
            return ModuleResult(module_name=self.name, findings=findings)

        if not safe_bins:
            findings.append(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title="Empty safeBins list",
                detail=(
                    f"sandbox.safeBins is empty. Depending on {ACTIVE_PROFILE.display_name} version, "
                    "this may allow all binaries or none. Explicitly list allowed binaries."
                ),
                path=str(OPENCLAW_CONFIG),
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        for entry in safe_bins:
            if not isinstance(entry, str):
                continue
            basename = Path(entry).name.lower()

            # Check for dangerous binaries that can escape sandbox
            if basename in _DANGEROUS_BINS:
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title=f"Dangerous binary in safeBins: {basename}",
                    detail=(
                        f"'{entry}' in sandbox.safeBins allows sandbox escape via "
                        f"CVE-2026-28363. '{basename}' can execute arbitrary commands, "
                        f"bypassing sandbox restrictions entirely."
                    ),
                    path=str(OPENCLAW_CONFIG),
                ))

            # Check for bypass patterns
            for pattern, desc in _BYPASS_PATTERNS:
                if re.search(pattern, entry):
                    findings.append(Finding(
                        module=self.name,
                        severity=Severity.CRITICAL,
                        title=f"safeBins bypass pattern: {desc}",
                        detail=(
                            f"'{entry}' in sandbox.safeBins contains a pattern that "
                            f"can be exploited to bypass sandbox restrictions."
                        ),
                        path=str(OPENCLAW_CONFIG),
                    ))
                    break  # One finding per entry for patterns

            # Check for symlinks pointing outside expected paths
            resolved = Path(entry)
            if resolved.is_absolute() and resolved.is_symlink():
                target = resolved.resolve()
                try:
                    if not str(target).startswith(("/usr/", "/bin/", "/sbin/")):
                        findings.append(Finding(
                            module=self.name,
                            severity=Severity.WARNING,
                            title=f"safeBins symlink to unusual path: {entry}",
                            detail=(
                                f"'{entry}' is a symlink pointing to '{target}', "
                                f"which is outside standard system binary directories."
                            ),
                            path=str(OPENCLAW_CONFIG),
                        ))
                except OSError:
                    pass

        # Check for PATH manipulation vulnerability
        # If safeBins uses relative paths, PATH can be manipulated to redirect execution
        relative_bins = [b for b in safe_bins if isinstance(b, str) and not Path(b).is_absolute()]
        if relative_bins:
            findings.append(Finding(
                module=self.name,
                severity=Severity.CRITICAL,
                title="Relative paths in safeBins enable PATH manipulation",
                detail=(
                    f"safeBins contains relative paths: {relative_bins[:5]}. "
                    f"An attacker can manipulate PATH to redirect these to "
                    f"malicious binaries, bypassing sandbox (CVE-2026-28363)."
                ),
                path=str(OPENCLAW_CONFIG),
            ))

        return ModuleResult(module_name=self.name, findings=findings)
