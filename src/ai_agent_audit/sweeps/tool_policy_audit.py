"""Audit tool execution policies in the active agent's config."""

from __future__ import annotations

import json
import logging

from ..config import ACTIVE_PROFILE, OPENCLAW_CONFIG
from ..models import Finding, ModuleResult, Severity
from .base import BaseSweep

logger = logging.getLogger(__name__)


class ToolPolicyAuditSweep(BaseSweep):
    name = "tool_policy_audit"

    def run(self) -> ModuleResult:
        findings: list[Finding] = []

        if not OPENCLAW_CONFIG.exists():
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title=f"{ACTIVE_PROFILE.display_name} config not found",
                detail=f"{OPENCLAW_CONFIG} does not exist.",
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        try:
            data = json.loads(OPENCLAW_CONFIG.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            findings.append(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title=f"Cannot parse {ACTIVE_PROFILE.display_name} config",
                detail=str(exc),
                path=str(OPENCLAW_CONFIG),
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        tools = data.get("tools", {})
        if not isinstance(tools, dict):
            return ModuleResult(module_name=self.name, findings=findings)

        # Check elevated tool config
        elevated = tools.get("elevated", {})
        if isinstance(elevated, dict):
            # allowFrom contains wildcard
            allow_from = elevated.get("allowFrom", [])
            if isinstance(allow_from, list) and "*" in allow_from:
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title="Elevated tools allow all callers",
                    detail="tools.elevated.allowFrom contains '*', any caller can use elevated tools.",
                    path=str(OPENCLAW_CONFIG),
                ))
            elif isinstance(allow_from, str) and allow_from == "*":
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title="Elevated tools allow all callers",
                    detail="tools.elevated.allowFrom is '*', any caller can use elevated tools.",
                    path=str(OPENCLAW_CONFIG),
                ))

            # requireApproval is false
            if elevated.get("requireApproval") is False:
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title="Elevated tools do not require approval",
                    detail="tools.elevated.requireApproval is false. Dangerous commands execute without confirmation.",
                    path=str(OPENCLAW_CONFIG),
                ))

            # Elevated mode with no restrictions at all
            has_allow_from = bool(allow_from)
            has_approval = elevated.get("requireApproval", True) is not False
            has_deny = bool(tools.get("deny"))
            if not has_allow_from and not has_approval and not has_deny:
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title="Elevated mode with no restrictions",
                    detail="Elevated tools have no allowFrom, no requireApproval, and no deny list.",
                    path=str(OPENCLAW_CONFIG),
                ))

        # Check deny list
        deny = tools.get("deny")
        if deny is None or (isinstance(deny, list) and len(deny) == 0):
            findings.append(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title="No tool deny list configured",
                detail="tools.deny is empty or missing. No tools are explicitly blocked.",
                path=str(OPENCLAW_CONFIG),
            ))

        return ModuleResult(module_name=self.name, findings=findings)
