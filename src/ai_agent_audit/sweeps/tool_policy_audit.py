"""Audit tool execution policies in the active agent's config."""

from __future__ import annotations

import logging

from ..agent_config import AgentConfigError, load_agent_config
from ..config import ACTIVE_PROFILE, OPENCLAW_CONFIG
from ..models import Finding, ModuleResult, Severity
from .base import BaseSweep

logger = logging.getLogger(__name__)


def _contains_wildcard(value: object) -> bool:
    if value == "*":
        return True
    if isinstance(value, list):
        return any(_contains_wildcard(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_wildcard(item) for item in value.values())
    return False


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
            data = load_agent_config(OPENCLAW_CONFIG)
        except AgentConfigError as exc:
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
            if _contains_wildcard(allow_from):
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title="Elevated tools allow all callers",
                    detail="tools.elevated.allowFrom contains '*', any caller can use elevated tools.",
                    path=str(OPENCLAW_CONFIG),
                ))

            # Current OpenClaw scopes elevated access with provider-specific
            # allowFrom maps; requireApproval was a legacy cloned-schema key.
            has_allow_from = bool(allow_from)
            has_deny = bool(tools.get("deny"))
            if elevated.get("enabled") is True and not has_allow_from and not has_deny:
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title="Elevated mode with no restrictions",
                    detail="Elevated tools are enabled with no allowFrom map or deny list.",
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
