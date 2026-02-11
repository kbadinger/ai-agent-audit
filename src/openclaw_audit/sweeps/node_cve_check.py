"""Node.js CVE version check sweep."""

from __future__ import annotations

import logging
import re
import subprocess

from ..models import Finding, ModuleResult, Severity
from .base import BaseSweep

logger = logging.getLogger(__name__)

# Known vulnerable Node.js versions: (max_vulnerable_version, cve, description, severity)
KNOWN_CVES: list[dict] = [
    {
        "max_version": (22, 12, 0),
        "cve": "CVE-2026-21636",
        "title": "Permission model bypass via Unix Domain Sockets",
        "severity": Severity.CRITICAL,
    },
]


def _parse_version(version_str: str) -> tuple[int, ...] | None:
    """Parse 'vX.Y.Z' into (X, Y, Z) tuple."""
    match = re.match(r"v?(\d+)\.(\d+)\.(\d+)", version_str.strip())
    if not match:
        return None
    return tuple(int(g) for g in match.groups())


class NodeCVECheckSweep(BaseSweep):
    name = "node_cve_check"

    def run(self) -> ModuleResult:
        findings: list[Finding] = []

        try:
            result = subprocess.run(
                ["node", "--version"],
                capture_output=True, text=True, timeout=10,
            )
        except FileNotFoundError:
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title="Node.js not installed",
                detail="node command not found. Skipping CVE check.",
            ))
            return ModuleResult(module_name=self.name, findings=findings)
        except subprocess.TimeoutExpired:
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title="Node version check timed out",
                detail="node --version timed out.",
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        if result.returncode != 0:
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title="Node version check failed",
                detail=f"node --version returned error: {result.stderr.strip()[:200]}",
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        version = _parse_version(result.stdout)
        if version is None:
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title="Unparseable Node.js version",
                detail=f"Could not parse version from: {result.stdout.strip()[:100]}",
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        version_str = result.stdout.strip()

        for cve in KNOWN_CVES:
            if version < cve["max_version"]:
                fixed = ".".join(str(v) for v in cve["max_version"])
                findings.append(Finding(
                    module=self.name,
                    severity=cve["severity"],
                    title=f"{cve['cve']}: {cve['title']}",
                    detail=(
                        f"Node.js {version_str} is vulnerable. "
                        f"Upgrade to >= {fixed}."
                    ),
                ))

        return ModuleResult(module_name=self.name, findings=findings)
