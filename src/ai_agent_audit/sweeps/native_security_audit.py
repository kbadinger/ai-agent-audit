"""Adapter for the audited agent's native structured security audit."""

from __future__ import annotations

import json
import subprocess
from typing import Any, Iterable

from ..config import ACTIVE_PROFILE
from ..models import Finding, ModuleResult, ModuleStatus, Severity
from .base import BaseSweep


def _records(payload: Any) -> Iterable[dict[str, Any]]:
    """Yield finding-like records from common native audit response shapes."""
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                yield item
        return
    if not isinstance(payload, dict):
        return
    for key in ("findings", "issues", "results", "vulnerabilities", "checks"):
        value = payload.get(key)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    yield item
            return


def _severity(value: Any) -> Severity:
    normalized = str(value or "info").lower()
    if normalized in {"critical", "high", "fatal", "error"}:
        return Severity.CRITICAL
    if normalized in {"medium", "moderate", "warning", "warn"}:
        return Severity.WARNING
    return Severity.INFO


class NativeSecurityAuditSweep(BaseSweep):
    """Run OpenClaw/Hermes' own audit and normalize its findings."""

    name = "native_security_audit"

    def run(self) -> ModuleResult:
        command = ACTIVE_PROFILE.native_audit_command
        if not command:
            return ModuleResult(
                module_name=self.name,
                status=ModuleStatus.SKIPPED,
                message=f"{ACTIVE_PROFILE.display_name} does not define a native audit command",
            )

        try:
            completed = subprocess.run(
                list(command),
                capture_output=True,
                text=True,
                timeout=60,
            )
        except FileNotFoundError:
            return ModuleResult(
                module_name=self.name,
                status=ModuleStatus.SKIPPED,
                message=f"Native audit executable not installed: {command[0]}",
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            return ModuleResult(
                module_name=self.name,
                status=ModuleStatus.ERROR,
                message=f"Native audit failed: {exc}",
            )

        output = completed.stdout.strip()
        if not output:
            detail = completed.stderr.strip() or f"exit code {completed.returncode}"
            return ModuleResult(
                module_name=self.name,
                status=ModuleStatus.ERROR,
                message=f"Native audit returned no JSON: {detail[:300]}",
            )
        try:
            payload = json.loads(output)
        except json.JSONDecodeError as exc:
            return ModuleResult(
                module_name=self.name,
                status=ModuleStatus.ERROR,
                message=f"Native audit returned invalid JSON: {exc}",
            )

        native_records = list(_records(payload))
        if completed.returncode != 0 and not native_records:
            detail = completed.stderr.strip() or f"exit code {completed.returncode}"
            return ModuleResult(
                module_name=self.name,
                status=ModuleStatus.ERROR,
                message=f"Native audit failed: {detail[:300]}",
            )

        findings: list[Finding] = []
        for record in native_records:
            state = str(record.get("status") or record.get("result") or "").lower()
            if record.get("passed") is True or state in {"pass", "passed", "ok", "success"}:
                continue
            check_id = record.get("checkId") or record.get("id") or record.get("rule")
            title = record.get("title") or record.get("name") or check_id or "Native audit finding"
            detail = (
                record.get("detail")
                or record.get("description")
                or record.get("message")
                or title
            )
            remediation = record.get("remediation") or record.get("recommendation") or record.get("fix")
            findings.append(Finding(
                module=self.name,
                severity=_severity(record.get("severity") or record.get("level")),
                title=f"{check_id}: {title}" if check_id and check_id not in str(title) else str(title),
                detail=str(detail),
                path=str(record.get("path")) if record.get("path") else None,
                remediation=str(remediation) if remediation else None,
                confidence=1.0,
            ))

        return ModuleResult(module_name=self.name, findings=findings)
