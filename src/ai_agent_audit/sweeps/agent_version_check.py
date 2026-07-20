"""Agent version CVE check — flags installed agent versions with known CVEs.

Covers the OpenClaw "Claw Chain" cluster (Cyera, patched in 2026.4.22) and the
Hermes core CVEs that publish a clear date-scheme fix version. Component CVEs
that use a different version scheme (e.g. hermes-webui semver) are tracked via
the IOC/mappings intel rather than compared here, to avoid cross-scheme false
positives.
"""

from __future__ import annotations

import logging
import re
import subprocess

from ..advisory_catalog import load_catalog
from ..agent_config import AgentConfigError, load_agent_config
from ..config import ACTIVE_PROFILE, AGENT_CONFIG
from ..models import Finding, ModuleResult, Severity
from .base import BaseSweep

logger = logging.getLogger(__name__)

def _parse_version(version_str: str) -> tuple[int, ...] | None:
    """Parse 'v2026.4.22' / '2026.4.22' into a tuple of ints."""
    nums = re.findall(r"\d+", version_str)
    if not nums:
        return None
    return tuple(int(n) for n in nums)


def _parse_date_version(version_str: str) -> tuple[int, ...] | None:
    """Prefer a year-like release tag from composite version output."""
    match = re.search(r"(20\d{2}(?:\.\d+){2,3})", version_str)
    return _parse_version(match.group(1)) if match else None


def _parse_semver_version(version_str: str) -> tuple[int, ...] | None:
    """Extract a semantic version, including from composite release output."""
    match = re.search(r"(?<!\d)(\d+\.\d+\.\d+)(?![.\d])", version_str)
    if not match:
        return None
    parsed = _parse_version(match.group(1))
    return parsed if parsed and parsed[0] < 2000 else None


def _severity(value: str) -> Severity:
    normalized = str(value).lower()
    if normalized in {"critical", "high"}:
        return Severity.CRITICAL
    if normalized in {"warning", "medium", "moderate"}:
        return Severity.WARNING
    return Severity.INFO


class AgentVersionCheckSweep(BaseSweep):
    name = "agent_version_check"

    def run(self) -> ModuleResult:
        findings: list[Finding] = []
        slug = ACTIVE_PROFILE.slug
        display = ACTIVE_PROFILE.display_name
        advisories = load_catalog(slug)
        if not advisories:
            findings.append(Finding(
                module=self.name, severity=Severity.INFO,
                title=f"No version CVEs tracked for {display}",
                detail=f"No known version-gated CVEs are tracked for the {display} profile.",
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        version_str = self._detect_version()
        if version_str is None:
            findings.append(Finding(
                module=self.name, severity=Severity.INFO,
                title=f"{display} version could not be determined",
                detail=(
                    f"No 'version' key in {AGENT_CONFIG.name} and "
                    f"'{' '.join(ACTIVE_PROFILE.version_command) or '<none>'}' "
                    "was not runnable. Skipping version CVE check."
                ),
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        date_version = _parse_date_version(version_str)
        semver_version = _parse_semver_version(version_str)
        if date_version is None and semver_version is None:
            findings.append(Finding(
                module=self.name, severity=Severity.INFO,
                title=f"Unparseable {display} version",
                detail=f"Could not parse a version from: {version_str[:100]}",
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        path = str(AGENT_CONFIG) if AGENT_CONFIG.exists() else None
        comparable = 0
        for advisory in advisories:
            fixed = _parse_version(str(advisory.get("fixed") or ""))
            introduced = _parse_version(str(advisory.get("introduced") or ""))
            if not fixed:
                continue
            version = date_version if fixed[0] >= 2000 else semver_version
            if version is None:
                continue
            comparable += 1
            if (introduced is None or version >= introduced) and version < fixed:
                fixed_text = ".".join(str(v) for v in fixed)
                advisory_id = str(advisory["id"])
                findings.append(Finding(
                    module=self.name, severity=_severity(str(advisory.get("severity", "warning"))),
                    title=f"{advisory_id}: {advisory.get('title', 'Security advisory')}",
                    detail=(
                        f"{display} {version_str} is in the affected range for {advisory_id}. "
                        f"Upgrade to >= {fixed_text}."
                    ),
                    path=path,
                ))

        if not findings and comparable:
            findings.append(Finding(
                module=self.name, severity=Severity.INFO,
                title=f"{display} {version_str}: no known version CVEs",
                detail=f"{display} {version_str} is at or above all tracked fix versions.",
            ))
        elif not findings:
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title=f"{display} version {version_str} has no comparable advisories",
                detail="Tracked advisories use a different version scheme than this installation.",
            ))

        return ModuleResult(module_name=self.name, findings=findings)

    def _detect_version(self) -> str | None:
        """Resolve the installed version from config, then the version command."""
        if AGENT_CONFIG.exists():
            try:
                data = load_agent_config(AGENT_CONFIG)
                value = data.get("version")
                if isinstance(value, str) and value.strip():
                    return value.strip()
            except AgentConfigError:
                pass

        cmd = ACTIVE_PROFILE.version_command
        if cmd:
            try:
                result = subprocess.run(
                    list(cmd), capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip()
            except (FileNotFoundError, subprocess.SubprocessError, OSError):
                pass

        return None
