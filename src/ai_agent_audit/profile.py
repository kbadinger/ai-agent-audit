"""Environment profiler — detects what's installed to skip irrelevant checks."""

from __future__ import annotations

import json
import logging
import platform
import shutil
from pathlib import Path

from .agent_config import AgentConfigError, load_agent_config, mcp_config_present
from .config import (
    ACTIVE_PROFILE,
    AUDIT_BASELINES,
    OPENCLAW_CONFIG,
    OPENCLAW_MCP_CONFIG,
    OPENCLAW_SKILLS,
)

logger = logging.getLogger(__name__)

PROFILE_FILE = AUDIT_BASELINES / "environment.json"


class EnvironmentProfiler:
    """Detects what's present in this environment so sweeps can skip irrelevant checks."""

    def __init__(self):
        self._profile: dict = {}
        self.refresh()

    def refresh(self) -> None:
        """Re-scan the environment and update the profile."""
        self._profile = {
            "agent": ACTIVE_PROFILE.slug,
            "os": platform.system(),
            "has_docker": shutil.which("docker") is not None,
            "has_mcp_config": self._check_mcp_config(),
            "has_skills": OPENCLAW_SKILLS.exists(),
            "skill_count": self._count_skills(),
            "has_config": OPENCLAW_CONFIG.exists(),
            "has_gateway": self._check_gateway_config(),
        }
        self._save()

    def _count_skills(self) -> int:
        try:
            if not OPENCLAW_SKILLS.exists():
                return 0
            return sum(1 for d in OPENCLAW_SKILLS.iterdir() if d.is_dir())
        except OSError:
            return 0

    def _check_gateway_config(self) -> bool:
        """Check if gateway is configured in openclaw.json."""
        try:
            if not OPENCLAW_CONFIG.exists():
                return False
            config = load_agent_config(OPENCLAW_CONFIG)
            return "gateway" in config
        except AgentConfigError:
            return False

    def _check_mcp_config(self) -> bool:
        """Check current embedded and legacy MCP configuration layouts."""
        try:
            if not OPENCLAW_MCP_CONFIG.exists():
                return False
            return mcp_config_present(load_agent_config(OPENCLAW_MCP_CONFIG))
        except AgentConfigError:
            return False

    def _save(self) -> None:
        try:
            PROFILE_FILE.parent.mkdir(parents=True, exist_ok=True)
            PROFILE_FILE.write_text(json.dumps(self._profile, indent=2))
        except OSError as exc:
            logger.warning("Failed to save environment profile: %s", exc)

    def is_relevant(self, check_name: str) -> bool:
        """Return whether a check is relevant to this environment.

        Checks not in the relevance map are always relevant (conservative).
        """
        agent = self._profile.get("agent")
        openclaw_only = {
            "agent_comm_audit",
            "dm_policy_audit",
            "exec_approvals_audit",
            "node_cve_check",
            "reverse_proxy_audit",
            "safebins_bypass",
            "tool_policy_audit",
            "websocket_security",
        }
        if check_name in openclaw_only and agent != "openclaw":
            return False
        if check_name == "hermes_hardening" and agent != "hermes":
            return False

        relevance = {
            "docker_security": self._profile.get("has_docker", False),
            "mcp_security": self._profile.get("has_mcp_config", False),
            "mcp_rugpull": self._profile.get("has_mcp_config", False),
            "skill_scanner": self._profile.get("has_skills", False),
            "websocket_security": self._profile.get("has_gateway", False),
            "reverse_proxy_audit": self._profile.get("has_gateway", False),
            "vscode_trojan_check": self._profile.get("os") in ("Darwin", "Linux"),
            "persistence_detection": self._profile.get("os") in ("Darwin", "Linux"),
        }
        return relevance.get(check_name, True)

    @property
    def profile(self) -> dict:
        return dict(self._profile)
