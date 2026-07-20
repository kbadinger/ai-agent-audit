from unittest.mock import patch

from ai_agent_audit.sweeps.dm_policy_audit import DMPolicyAuditSweep
from ai_agent_audit.sweeps.mcp_security import MCPSecuritySweep
from ai_agent_audit.sweeps.safebins_bypass import SafeBinsBypassSweep
from ai_agent_audit.sweeps.tool_policy_audit import ToolPolicyAuditSweep


def _titles(result):
    return {finding.title for finding in result.findings}


def test_nested_channel_account_dm_policy(tmp_path):
    config = tmp_path / "openclaw.json"
    config.write_text("""
    {channels: {discord: {accounts: {primary: {dmPolicy: 'open'}}}}}
    """)
    with patch("ai_agent_audit.sweeps.dm_policy_audit.OPENCLAW_CONFIG", config):
        result = DMPolicyAuditSweep().run()
    assert "Channel 'discord/primary' has open DM policy" in _titles(result)


def test_provider_scoped_elevated_wildcard(tmp_path):
    config = tmp_path / "openclaw.json"
    config.write_text("""
    {tools: {elevated: {enabled: true, allowFrom: {discord: ['*']}}, deny: ['shell']}}
    """)
    with patch("ai_agent_audit.sweeps.tool_policy_audit.OPENCLAW_CONFIG", config):
        result = ToolPolicyAuditSweep().run()
    assert "Elevated tools allow all callers" in _titles(result)


def test_embedded_mcp_servers_are_audited(tmp_path):
    config = tmp_path / "openclaw.json"
    config.write_text("""
    {mcp: {servers: {remote: {package: 'example-mcp', tools: []}}}}
    """)
    with patch("ai_agent_audit.sweeps.mcp_security.OPENCLAW_MCP_CONFIG", config):
        result = MCPSecuritySweep().run()
    assert "MCP server 'remote' not version-pinned" in _titles(result)


def test_current_sandbox_mode_and_exec_safebins(tmp_path):
    config = tmp_path / "openclaw.json"
    config.write_text("""
    {agents: {defaults: {sandbox: {mode: 'all'}}}, tools: {exec: {safeBins: ['bash']}}}
    """)
    with patch("ai_agent_audit.sweeps.safebins_bypass.OPENCLAW_CONFIG", config):
        result = SafeBinsBypassSweep().run()
    assert "Dangerous binary in safeBins: bash" in _titles(result)
