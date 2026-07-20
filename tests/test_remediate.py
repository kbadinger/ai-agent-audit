from types import SimpleNamespace
from unittest.mock import patch

from ai_agent_audit.remediate import RemediationEngine


def test_dry_run_never_rewrites_json5_config(tmp_path):
    config = tmp_path / "openclaw.json"
    original = "{gateway:{auth:{mode:'none'},},}"
    config.write_text(original)
    profile = SimpleNamespace(
        display_name="OpenClaw",
        native_fix_command=("openclaw", "security", "audit", "--fix", "--json"),
    )
    engine = RemediationEngine(dry_run=True)
    with patch("ai_agent_audit.remediate.OPENCLAW_CONFIG", config), \
            patch("ai_agent_audit.remediate.ACTIVE_PROFILE", profile), \
            patch("ai_agent_audit.remediate.subprocess.run") as run:
        engine._fix_config()

    assert config.read_text() == original
    run.assert_not_called()
    assert "schema-aware native fixer" in engine.actions[0]["detail"]


def test_agent_without_native_fixer_leaves_yaml_unchanged(tmp_path):
    config = tmp_path / "config.yaml"
    original = "approvals:\n  mode: off\n"
    config.write_text(original)
    profile = SimpleNamespace(display_name="Hermes", native_fix_command=())
    engine = RemediationEngine()
    with patch("ai_agent_audit.remediate.OPENCLAW_CONFIG", config), \
            patch("ai_agent_audit.remediate.ACTIVE_PROFILE", profile):
        engine._fix_config()
    assert config.read_text() == original
    assert engine.actions[0]["applied"] is False
