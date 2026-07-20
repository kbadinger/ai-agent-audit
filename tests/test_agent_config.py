from types import SimpleNamespace

from ai_agent_audit.agent_config import (
    auth_enabled,
    dm_policy_open,
    extract_mcp_servers,
    load_agent_config,
    redaction_enabled,
    sandbox_enabled,
)


def _profile(slug="openclaw"):
    return SimpleNamespace(slug=slug)


def test_openclaw_json5_and_current_schema(tmp_path):
    path = tmp_path / "openclaw.json"
    path.write_text("""
    {
      // OpenClaw accepts comments and trailing commas.
      gateway: {auth: {mode: 'token'},},
      agents: {defaults: {sandbox: {mode: 'all'},},},
      logging: {redactSensitive: true},
      mcp: {servers: {trusted: {command: 'server'}}},
      channels: {discord: {dmPolicy: 'restricted'}},
    }
    """)

    data = load_agent_config(path)
    assert auth_enabled(data, _profile()) is True
    assert sandbox_enabled(data, _profile()) is True
    assert redaction_enabled(data, _profile()) is True
    assert dm_policy_open(data) is False
    assert set(extract_mcp_servers(data)) == {"trusted"}


def test_hermes_yaml(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("""
    approvals:
      mode: ask
    security:
      allow_private_urls: false
    mcp:
      servers:
        local:
          command: server
    """)

    data = load_agent_config(path)
    assert data["approvals"]["mode"] == "ask"
    assert set(extract_mcp_servers(data)) == {"local"}


def test_openclaw_explicitly_unsafe_current_values(tmp_path):
    path = tmp_path / "openclaw.json"
    path.write_text("{gateway:{auth:{mode:'none'}},agents:{defaults:{sandbox:{mode:'off'}}}}")
    data = load_agent_config(path)
    assert auth_enabled(data, _profile()) is False
    assert sandbox_enabled(data, _profile()) is False


def test_unknown_schema_values_are_not_treated_as_secure(tmp_path):
    path = tmp_path / "openclaw.json"
    path.write_text("{gateway:{auth:{mode:'mystery'}},agents:{defaults:{sandbox:{mode:'mystery'}}}}")
    data = load_agent_config(path)
    assert auth_enabled(data, _profile()) is None
    assert sandbox_enabled(data, _profile()) is None
