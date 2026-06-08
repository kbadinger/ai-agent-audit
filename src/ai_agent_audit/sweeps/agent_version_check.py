"""Agent version CVE check — flags installed agent versions with known CVEs.

Covers the OpenClaw "Claw Chain" cluster (Cyera, patched in 2026.4.22) and the
Hermes core CVEs that publish a clear date-scheme fix version. Component CVEs
that use a different version scheme (e.g. hermes-webui semver) are tracked via
the IOC/mappings intel rather than compared here, to avoid cross-scheme false
positives.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess

from ..config import ACTIVE_PROFILE, AGENT_CONFIG
from ..models import Finding, ModuleResult, Severity
from .base import BaseSweep

logger = logging.getLogger(__name__)

# Per-agent CVEs keyed by slug. `fixed` is the first non-vulnerable version
# (date scheme, e.g. (2026, 4, 22)). Installed version < fixed => vulnerable.
KNOWN_CVES: dict[str, list[dict]] = {
    "openclaw": [
        {"fixed": (2026, 4, 22), "cve": "CVE-2026-44112",
         "title": "Claw Chain: TOCTOU sandbox write-escape", "severity": Severity.CRITICAL},
        {"fixed": (2026, 4, 22), "cve": "CVE-2026-44113",
         "title": "Claw Chain: TOCTOU sandbox read-escape", "severity": Severity.WARNING},
        {"fixed": (2026, 4, 22), "cve": "CVE-2026-44115",
         "title": "Claw Chain: heredoc command-validation bypass", "severity": Severity.CRITICAL},
        {"fixed": (2026, 4, 22), "cve": "CVE-2026-44118",
         "title": "Claw Chain: loopback senderIsOwner trust bypass", "severity": Severity.WARNING},
    ],
    "hermes": [
        {"fixed": (2026, 4, 17), "cve": "CVE-2026-9368",
         "title": "Code execution in code_execution_tool.execute_code", "severity": Severity.CRITICAL},
        {"fixed": (2026, 4, 24), "cve": "CVE-2026-10548",
         "title": "Credential-pool sync improper authentication", "severity": Severity.CRITICAL},
    ],
}


def _parse_version(version_str: str) -> tuple[int, ...] | None:
    """Parse 'v2026.4.22' / '2026.4.22' into a tuple of ints."""
    nums = re.findall(r"\d+", version_str)
    if not nums:
        return None
    return tuple(int(n) for n in nums)


class AgentVersionCheckSweep(BaseSweep):
    name = "agent_version_check"

    def run(self) -> ModuleResult:
        findings: list[Finding] = []
        slug = ACTIVE_PROFILE.slug
        display = ACTIVE_PROFILE.display_name
        cves = KNOWN_CVES.get(slug, [])
        if not cves:
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

        version = _parse_version(version_str)
        if version is None:
            findings.append(Finding(
                module=self.name, severity=Severity.INFO,
                title=f"Unparseable {display} version",
                detail=f"Could not parse a version from: {version_str[:100]}",
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        # Only compare date-scheme installs (year-like major) against these
        # date-scheme CVEs. A semver install (major < 2000) is a different
        # component; comparing would be meaningless.
        if version[0] < 2000:
            findings.append(Finding(
                module=self.name, severity=Severity.INFO,
                title=f"{display} version {version_str} uses a non-date scheme",
                detail="Date-scheme CVE comparison skipped for this version string.",
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        path = str(AGENT_CONFIG) if AGENT_CONFIG.exists() else None
        for cve in cves:
            if version < cve["fixed"]:
                fixed = ".".join(str(v) for v in cve["fixed"])
                findings.append(Finding(
                    module=self.name, severity=cve["severity"],
                    title=f"{cve['cve']}: {cve['title']}",
                    detail=(
                        f"{display} {version_str} is vulnerable to {cve['cve']}. "
                        f"Upgrade to >= {fixed}."
                    ),
                    path=path,
                ))

        if not findings:
            findings.append(Finding(
                module=self.name, severity=Severity.INFO,
                title=f"{display} {version_str}: no known version CVEs",
                detail=f"{display} {version_str} is at or above all tracked fix versions.",
            ))

        return ModuleResult(module_name=self.name, findings=findings)

    def _detect_version(self) -> str | None:
        """Resolve the installed version from config, then the version command."""
        if AGENT_CONFIG.exists():
            try:
                data = json.loads(AGENT_CONFIG.read_text())
                value = data.get("version")
                if isinstance(value, str) and value.strip():
                    return value.strip()
            except (json.JSONDecodeError, OSError):
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
