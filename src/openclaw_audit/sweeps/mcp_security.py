"""MCP server configuration security sweep."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from ..config import INJECTION_PATTERNS, OPENCLAW_MCP_CONFIG
from ..models import Finding, ModuleResult, Severity
from .base import BaseSweep

logger = logging.getLogger(__name__)


class MCPSecuritySweep(BaseSweep):
    name = "mcp_security"

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
            data = json.loads(OPENCLAW_MCP_CONFIG.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            findings.append(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title="MCP config unreadable",
                detail=f"Could not parse {OPENCLAW_MCP_CONFIG}: {exc}",
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        # Check enableAllProjectMcpServers
        if data.get("enableAllProjectMcpServers") is True:
            findings.append(Finding(
                module=self.name,
                severity=Severity.CRITICAL,
                title="All project MCP servers enabled",
                detail=(
                    "enableAllProjectMcpServers=true allows any project to "
                    "register MCP servers automatically. Disable this setting."
                ),
                path=str(OPENCLAW_MCP_CONFIG),
            ))

        # Check each configured server
        servers = data.get("mcpServers", {})
        for server_name, server_cfg in servers.items():
            # Check tool descriptions for injection patterns
            tools = server_cfg.get("tools", [])
            for tool in tools:
                desc = tool.get("description", "")
                for inj in INJECTION_PATTERNS:
                    if re.search(inj["pattern"], desc):
                        findings.append(Finding(
                            module=self.name,
                            severity=Severity.CRITICAL,
                            title=f"Injection pattern in MCP tool: {inj['name']}",
                            detail=(
                                f"Server '{server_name}', tool '{tool.get('name', '?')}' "
                                f"description matches injection pattern: {desc[:200]}"
                            ),
                            path=str(OPENCLAW_MCP_CONFIG),
                        ))

            # Check version pinning
            version = server_cfg.get("version", "")
            image = server_cfg.get("image", "")
            pkg = server_cfg.get("package", "")
            source = image or pkg or ""
            if source and (version in ("latest", "") or ":latest" in source):
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.WARNING,
                    title=f"MCP server '{server_name}' not version-pinned",
                    detail=(
                        "Server uses 'latest' or no version pin. "
                        "A compromised update could replace this server (rug-pull risk)."
                    ),
                    path=str(OPENCLAW_MCP_CONFIG),
                ))

            # Check unrestricted network access
            network = server_cfg.get("network", {})
            if network.get("unrestricted") is True:
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.WARNING,
                    title=f"MCP server '{server_name}' has unrestricted network",
                    detail="Server has unrestricted network access. Restrict to required hosts.",
                    path=str(OPENCLAW_MCP_CONFIG),
                ))

        return ModuleResult(module_name=self.name, findings=findings)
