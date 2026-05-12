"""Audit exec-approvals.json for overly permissive execution policies."""

from __future__ import annotations

import json
import logging
import os
import stat

from ..config import OPENCLAW_EXEC_APPROVALS
from ..models import Finding, ModuleResult, Severity
from .base import BaseSweep

logger = logging.getLogger(__name__)


class ExecApprovalsAuditSweep(BaseSweep):
    name = "exec_approvals_audit"

    def run(self) -> ModuleResult:
        findings: list[Finding] = []

        if not OPENCLAW_EXEC_APPROVALS.exists():
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title="Exec approvals file not found",
                detail=f"{OPENCLAW_EXEC_APPROVALS} does not exist.",
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        # Check file permissions
        try:
            file_stat = os.stat(OPENCLAW_EXEC_APPROVALS)
            mode = stat.S_IMODE(file_stat.st_mode)
            if mode & 0o177:  # anything beyond owner rw (0o600)
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.WARNING,
                    title="Exec approvals file permissions too loose",
                    detail=f"File has mode {oct(mode)}, expected 0o600 or stricter.",
                    path=str(OPENCLAW_EXEC_APPROVALS),
                ))
        except OSError:
            pass

        # Parse JSON content
        try:
            data = json.loads(OPENCLAW_EXEC_APPROVALS.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            findings.append(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title="Cannot parse exec approvals file",
                detail=str(exc),
                path=str(OPENCLAW_EXEC_APPROVALS),
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        # data can be a list or dict of entries
        entries = data if isinstance(data, list) else data.values() if isinstance(data, dict) else []

        for entry in entries:
            if not isinstance(entry, dict):
                continue

            entry_id = entry.get("command", entry.get("name", entry.get("id", "unknown")))

            # Check for security: allow on non-owner
            if entry.get("security") == "allow":
                scope = entry.get("scope", "")
                if scope != "owner":
                    findings.append(Finding(
                        module=self.name,
                        severity=Severity.CRITICAL,
                        title=f"Unrestricted exec approval: {entry_id}",
                        detail=(
                            f"Entry has security='allow' for scope='{scope}'. "
                            "Any process can execute commands without approval."
                        ),
                        path=str(OPENCLAW_EXEC_APPROVALS),
                    ))

            # Check for ask: never
            if entry.get("ask") == "never":
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title=f"Approval bypass: {entry_id}",
                    detail="Entry has ask='never', bypassing all execution approval prompts.",
                    path=str(OPENCLAW_EXEC_APPROVALS),
                ))

        return ModuleResult(module_name=self.name, findings=findings)
