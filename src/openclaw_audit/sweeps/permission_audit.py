"""Full recursive permission audit of OPENCLAW_HOME."""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path

from ..config import (
    EXPECTED_PERMISSIONS,
    OPENCLAW_HOME,
    SENSITIVE_FILE_PATTERNS,
)
from ..models import Finding, ModuleResult, Severity
from .base import BaseSweep

logger = logging.getLogger(__name__)


class PermissionAuditSweep(BaseSweep):
    name = "permission_audit"

    def run(self) -> ModuleResult:
        findings: list[Finding] = []

        if not OPENCLAW_HOME.exists():
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title="OpenClaw home not found",
                detail=f"{OPENCLAW_HOME} does not exist.",
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        current_uid = os.getuid()

        # Collect sensitive file globs once
        sensitive_paths: set[str] = set()
        for pattern in SENSITIVE_FILE_PATTERNS:
            for match in OPENCLAW_HOME.glob(pattern):
                sensitive_paths.add(str(match))

        for dirpath, dirnames, filenames in os.walk(OPENCLAW_HOME):
            entries = [os.path.join(dirpath, d) for d in dirnames]
            entries += [os.path.join(dirpath, f) for f in filenames]
            entries.append(dirpath)

            for entry in entries:
                try:
                    st = os.lstat(entry)
                except OSError:
                    continue

                mode = st.st_mode
                is_sensitive = entry in sensitive_paths
                entry_path = Path(entry)
                is_expected = entry_path in EXPECTED_PERMISSIONS

                # --- CRITICAL checks: always scan everything ---

                # Check world-writable
                if mode & stat.S_IWOTH:
                    findings.append(Finding(
                        module=self.name,
                        severity=Severity.CRITICAL,
                        title="World-writable file",
                        detail=f"Mode {oct(stat.S_IMODE(mode))}; others can modify this file.",
                        path=entry,
                    ))

                # Check SUID/SGID
                if mode & (stat.S_ISUID | stat.S_ISGID):
                    findings.append(Finding(
                        module=self.name,
                        severity=Severity.CRITICAL,
                        title="SUID/SGID bit set",
                        detail=f"Mode {oct(stat.S_IMODE(mode))}; SUID/SGID bits are set.",
                        path=entry,
                    ))

                # --- WARNING checks: only on sensitive/expected paths ---
                # Normal extension/node_modules files being 644 is expected.

                if is_sensitive or is_expected:
                    # Check ownership
                    if st.st_uid != current_uid:
                        findings.append(Finding(
                            module=self.name,
                            severity=Severity.WARNING,
                            title="File not owned by current user",
                            detail=f"Owned by UID {st.st_uid}, expected {current_uid}.",
                            path=entry,
                        ))

                    # Check world-readable
                    if mode & stat.S_IROTH:
                        findings.append(Finding(
                            module=self.name,
                            severity=Severity.WARNING,
                            title="World-readable file",
                            detail=f"Mode {oct(stat.S_IMODE(mode))}; others can read this file.",
                            path=entry,
                        ))

                # Check against EXPECTED_PERMISSIONS for known dirs/files
                if is_expected:
                    expected = EXPECTED_PERMISSIONS[entry_path]
                    actual = stat.S_IMODE(mode)
                    if actual & ~expected:
                        findings.append(Finding(
                            module=self.name,
                            severity=Severity.WARNING,
                            title="Permissions exceed expected",
                            detail=(
                                f"Has {oct(actual)}, expected at most {oct(expected)}."
                            ),
                            path=entry,
                        ))

                # Check sensitive files against 0o600
                if is_sensitive and stat.S_ISREG(mode):
                    actual = stat.S_IMODE(mode)
                    if actual & ~0o600:
                        findings.append(Finding(
                            module=self.name,
                            severity=Severity.WARNING,
                            title="Sensitive file too permissive",
                            detail=(
                                f"Has {oct(actual)}, expected at most 0o600."
                            ),
                            path=entry,
                        ))

        return ModuleResult(module_name=self.name, findings=findings)
