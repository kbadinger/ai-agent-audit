from types import SimpleNamespace
from unittest.mock import patch

from ai_agent_audit.profile import EnvironmentProfiler


def test_hermes_skips_openclaw_schema_sweeps(tmp_path):
    missing = tmp_path / "missing"
    with patch("ai_agent_audit.profile.ACTIVE_PROFILE", SimpleNamespace(slug="hermes")), \
            patch("ai_agent_audit.profile.PROFILE_FILE", tmp_path / "profile.json"), \
            patch("ai_agent_audit.profile.OPENCLAW_CONFIG", missing / "config.yaml"), \
            patch("ai_agent_audit.profile.OPENCLAW_MCP_CONFIG", missing / "config.yaml"), \
            patch("ai_agent_audit.profile.OPENCLAW_SKILLS", missing / "skills"):
        profiler = EnvironmentProfiler()

    assert profiler.is_relevant("hermes_hardening") is True
    assert profiler.is_relevant("websocket_security") is False
    assert profiler.is_relevant("tool_policy_audit") is False
    assert profiler.is_relevant("native_security_audit") is True
