"""MCP tool definition mutation detection (rug-pull attacks).

On first run, hashes all MCP tool descriptions from mcp.json.
On subsequent runs, detects description changes that may indicate
a compromised or malicious MCP server swapping tool behavior post-approval.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

from ..agent_config import AgentConfigError, extract_mcp_servers, load_agent_config
from ..config import AUDIT_BASELINES, OPENCLAW_MCP_CONFIG
from ..models import Finding, ModuleResult, Severity
from .base import BaseSweep

logger = logging.getLogger(__name__)

_BASELINE_FILE = AUDIT_BASELINES / "mcp-tool-hashes.json"


def _hash_tool(server_name: str, tool_name: str, description: str) -> str:
    """Create a stable hash of a tool's identity + description."""
    key = f"{server_name}:{tool_name}:{description}"
    return hashlib.sha256(key.encode()).hexdigest()[:32]


class MCPRugPullSweep(BaseSweep):
    name = "mcp_rugpull"

    def run(self) -> ModuleResult:
        findings: list[Finding] = []

        if not OPENCLAW_MCP_CONFIG.exists():
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title="MCP config not found",
                detail=f"{OPENCLAW_MCP_CONFIG} does not exist.",
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        try:
            data = load_agent_config(OPENCLAW_MCP_CONFIG)
        except AgentConfigError as exc:
            findings.append(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title="MCP config unreadable",
                detail=f"Could not parse {OPENCLAW_MCP_CONFIG}: {exc}",
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        # Build current tool hash map
        current_hashes: dict[str, dict] = {}
        servers = extract_mcp_servers(data)
        for server_name, server_cfg in servers.items():
            if not isinstance(server_cfg, dict):
                continue
            tools = server_cfg.get("tools", [])
            if not isinstance(tools, list):
                continue
            for tool in tools:
                if not isinstance(tool, dict):
                    continue
                tool_name = tool.get("name", "")
                description = tool.get("description", "")
                tool_key = f"{server_name}:{tool_name}"
                current_hashes[tool_key] = {
                    "hash": _hash_tool(server_name, tool_name, description),
                    "server": server_name,
                    "tool": tool_name,
                    "description_preview": description[:200],
                }

        # Load baseline
        baseline: dict[str, dict] = {}
        if _BASELINE_FILE.exists():
            try:
                baseline = json.loads(_BASELINE_FILE.read_text())
            except (json.JSONDecodeError, OSError):
                baseline = {}

        if not baseline:
            # First run — establish baseline
            self._save_baseline(current_hashes)
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title="MCP tool baseline established",
                detail=f"Hashed {len(current_hashes)} tool descriptions for future comparison.",
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        # Compare against baseline
        for tool_key, current in current_hashes.items():
            if tool_key not in baseline:
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.WARNING,
                    title=f"New MCP tool detected: {current['tool']}",
                    detail=(
                        f"Server '{current['server']}' registered new tool "
                        f"'{current['tool']}' since last scan. "
                        f"Description: {current['description_preview']}"
                    ),
                    path=str(OPENCLAW_MCP_CONFIG),
                ))
            elif current["hash"] != baseline[tool_key].get("hash"):
                old_preview = baseline[tool_key].get("description_preview", "?")
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title=f"MCP tool description changed: {current['tool']}",
                    detail=(
                        f"POTENTIAL RUG-PULL: Server '{current['server']}', "
                        f"tool '{current['tool']}' description was modified since "
                        f"last scan. This may indicate a compromised MCP server.\n"
                        f"Previous: {old_preview}\n"
                        f"Current: {current['description_preview']}"
                    ),
                    path=str(OPENCLAW_MCP_CONFIG),
                ))

        # Check for removed tools
        for tool_key, old in baseline.items():
            if tool_key not in current_hashes:
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.WARNING,
                    title=f"MCP tool removed: {old.get('tool', '?')}",
                    detail=(
                        f"Server '{old.get('server', '?')}' no longer exposes "
                        f"tool '{old.get('tool', '?')}'. Tool may have been "
                        f"replaced or the server was reconfigured."
                    ),
                    path=str(OPENCLAW_MCP_CONFIG),
                ))

        # Update baseline
        self._save_baseline(current_hashes)

        return ModuleResult(module_name=self.name, findings=findings)

    @staticmethod
    def _save_baseline(hashes: dict[str, dict]) -> None:
        _BASELINE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _BASELINE_FILE.write_text(json.dumps(hashes, indent=2) + "\n")
