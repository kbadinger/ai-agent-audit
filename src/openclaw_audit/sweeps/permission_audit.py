"""Full recursive permission audit of OPENCLAW_HOME."""

from __future__ import annotations

import logging
import os
import stat
import time
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

        # Aggregate counters for sensitive file issues (avoid 1 finding per file)
        sensitive_world_readable: list[str] = []
        sensitive_too_permissive: list[str] = []
        orphaned_tmp_files: list[str] = []
        one_hour_ago = time.time() - 3600

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

                # --- WARNING checks: only on expected permission paths ---
                if is_expected:
                    if st.st_uid != current_uid:
                        findings.append(Finding(
                            module=self.name,
                            severity=Severity.WARNING,
                            title="File not owned by current user",
                            detail=f"Owned by UID {st.st_uid}, expected {current_uid}.",
                            path=entry,
                        ))

                    expected = EXPECTED_PERMISSIONS[entry_path]
                    actual = stat.S_IMODE(mode)
                    if actual & ~expected:
                        findings.append(Finding(
                            module=self.name,
                            severity=Severity.WARNING,
                            title="Permissions exceed expected",
                            detail=f"Has {oct(actual)}, expected at most {oct(expected)}.",
                            path=entry,
                        ))

                # --- Orphaned .tmp file check ---
                if (
                    stat.S_ISREG(mode)
                    and entry.endswith(".tmp")
                    and st.st_mtime < one_hour_ago
                ):
                    orphaned_tmp_files.append(entry)

                # --- Sensitive file checks: aggregate into summaries ---
                if is_sensitive and stat.S_ISREG(mode):
                    if mode & stat.S_IROTH:
                        sensitive_world_readable.append(entry)
                    actual = stat.S_IMODE(mode)
                    if actual & ~0o600:
                        sensitive_too_permissive.append(entry)

        # Emit aggregated findings for sensitive files
        if sensitive_too_permissive:
            samples = sensitive_too_permissive[:5]
            sample_text = "\n".join(f"  - {p}" for p in samples)
            extra = f"\n  ... and {len(sensitive_too_permissive) - 5} more" if len(sensitive_too_permissive) > 5 else ""
            findings.append(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title=f"{len(sensitive_too_permissive)} sensitive files too permissive",
                detail=f"Expected mode 0o600 or stricter:\n{sample_text}{extra}",
            ))

        if orphaned_tmp_files:
            samples = orphaned_tmp_files[:5]
            sample_text = "\n".join(f"  - {p}" for p in samples)
            extra = f"\n  ... and {len(orphaned_tmp_files) - 5} more" if len(orphaned_tmp_files) > 5 else ""
            findings.append(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title=f"{len(orphaned_tmp_files)} orphaned .tmp files found",
                detail=f"Temp files older than 1 hour may contain sensitive data:\n{sample_text}{extra}",
            ))

        if sensitive_world_readable:
            samples = sensitive_world_readable[:5]
            sample_text = "\n".join(f"  - {p}" for p in samples)
            extra = f"\n  ... and {len(sensitive_world_readable) - 5} more" if len(sensitive_world_readable) > 5 else ""
            findings.append(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title=f"{len(sensitive_world_readable)} sensitive files world-readable",
                detail=f"Others can read these files:\n{sample_text}{extra}",
            ))

        return ModuleResult(module_name=self.name, findings=findings)
