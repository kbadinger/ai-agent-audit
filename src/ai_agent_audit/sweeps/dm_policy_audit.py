"""Audit DM (direct message) policy settings in the active agent's config."""

from __future__ import annotations

import json
import logging

from ..config import ACTIVE_PROFILE, OPENCLAW_CONFIG
from ..models import Finding, ModuleResult, Severity
from .base import BaseSweep

logger = logging.getLogger(__name__)


class DMPolicyAuditSweep(BaseSweep):
    name = "dm_policy_audit"

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

        # Check top-level dmPolicy
        dm_policy = data.get("dmPolicy")
        if dm_policy == "open":
            findings.append(Finding(
                module=self.name,
                severity=Severity.CRITICAL,
                title="Global DM policy is open",
                detail="Anyone can send direct messages to the agent without approval.",
                path=str(OPENCLAW_CONFIG),
            ))

        # Check channels config
        channels = data.get("channels", {})
        if isinstance(channels, dict):
            for channel_name, channel_cfg in channels.items():
                if not isinstance(channel_cfg, dict):
                    continue
                self._check_channel(channel_name, channel_cfg, findings)

        return ModuleResult(module_name=self.name, findings=findings)

    def _check_channel(self, name: str, cfg: dict, findings: list[Finding]) -> None:
        """Check a single channel configuration."""
        # dmPolicy = open
        if cfg.get("dmPolicy") == "open":
            findings.append(Finding(
                module=self.name,
                severity=Severity.CRITICAL,
                title=f"Channel '{name}' has open DM policy",
                detail="Channel allows direct messages from anyone without approval.",
                path=str(OPENCLAW_CONFIG),
            ))

        # allowFrom containing wildcard or empty
        allow_from = cfg.get("allowFrom", None)
        if isinstance(allow_from, list):
            if "*" in allow_from:
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.WARNING,
                    title=f"Channel '{name}' allows all senders",
                    detail="allowFrom contains wildcard '*', accepting messages from anyone.",
                    path=str(OPENCLAW_CONFIG),
                ))
            elif len(allow_from) == 0:
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.WARNING,
                    title=f"Channel '{name}' has empty allowFrom",
                    detail="allowFrom is an empty list, which may default to allow-all.",
                    path=str(OPENCLAW_CONFIG),
                ))

        # Enabled channel with no access restrictions
        enabled = cfg.get("enabled", True)
        if enabled and allow_from is None and cfg.get("dmPolicy") is None:
            findings.append(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title=f"Channel '{name}' has no access restrictions",
                detail="Channel is enabled but has no allowFrom or dmPolicy configured.",
                path=str(OPENCLAW_CONFIG),
            ))
