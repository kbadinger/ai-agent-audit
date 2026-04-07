"""MCP server configuration security sweep."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from ..config import INJECTION_PATTERNS, OPENCLAW_MCP_CONFIG
from ..ioc import C2_IPS, MALICIOUS_DOMAINS, ABUSED_SERVICES, record_ioc_match
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

            # Check tool descriptions against IOC database
            for tool in tools:
                desc = tool.get("description", "")
                tool_name = tool.get("name", "?")

                # Check for C2 IPs in description
                for ip in C2_IPS:
                    if ip in desc:
                        record_ioc_match(ip)
                        findings.append(Finding(
                            module=self.name,
                            severity=Severity.CRITICAL,
                            title=f"C2 IP in MCP tool description: {tool_name}",
                            detail=(
                                f"Server '{server_name}', tool '{tool_name}' "
                                f"description contains known C2 IP {ip}."
                            ),
                            path=str(OPENCLAW_MCP_CONFIG),
                        ))

                # Check for malicious/abused domains
                for domain in MALICIOUS_DOMAINS | ABUSED_SERVICES:
                    if domain in desc:
                        record_ioc_match(domain)
                        findings.append(Finding(
                            module=self.name,
                            severity=Severity.CRITICAL,
                            title=f"Malicious domain in MCP tool description: {tool_name}",
                            detail=(
                                f"Server '{server_name}', tool '{tool_name}' "
                                f"description references known malicious/abused "
                                f"domain: {domain}."
                            ),
                            path=str(OPENCLAW_MCP_CONFIG),
                        ))

            # Check server command/args for IOC domains
            cmd_args = " ".join(
                [server_cfg.get("command", "")]
                + (server_cfg.get("args", []) if isinstance(server_cfg.get("args"), list) else [])
            )
            for domain in MALICIOUS_DOMAINS | ABUSED_SERVICES:
                if domain in cmd_args:
                    record_ioc_match(domain)
                    findings.append(Finding(
                        module=self.name,
                        severity=Severity.CRITICAL,
                        title=f"MCP server '{server_name}' connects to malicious domain",
                        detail=(
                            f"Server command/args reference known malicious/abused "
                            f"domain: {domain}."
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
