"""Tests for the AgentProfile abstraction and profile resolution."""

import importlib
import os
import sys
from pathlib import Path

import pytest


def _reload_config_with_env(monkeypatch, env: dict) -> tuple:
    """Reload ai_agent_audit.agents + config with new env vars set.

    Returns (active_profile, config_module) for assertions.
    """
    for k, v in env.items():
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, v)

    # Drop cached modules so module-level constants re-evaluate
    for mod in ("ai_agent_audit.config", "ai_agent_audit.agents"):
        sys.modules.pop(mod, None)

    agents = importlib.import_module("ai_agent_audit.agents")
    config = importlib.import_module("ai_agent_audit.config")
    return config.ACTIVE_PROFILE, config


def test_profile_registry_has_openclaw_and_hermes():
    from ai_agent_audit.agents import all_profiles, SUPPORTED_PROFILES

    profiles = all_profiles()
    assert set(profiles.keys()) == {"openclaw", "hermes"}
    assert profiles["openclaw"].display_name == "OpenClaw"
    assert profiles["hermes"].display_name == "Hermes"
    assert SUPPORTED_PROFILES == ("openclaw", "hermes")


def test_explicit_openclaw_via_env(monkeypatch):
    profile, _ = _reload_config_with_env(monkeypatch, {
        "AI_AGENT_AUDIT_PROFILE": "openclaw",
        "OPENCLAW_HOME": None,
        "HERMES_HOME": None,
    })
    assert profile.slug == "openclaw"
    assert profile.config_filename == "openclaw.json"
    assert profile.home == Path.home() / ".openclaw"


def test_explicit_hermes_via_env(monkeypatch):
    profile, config = _reload_config_with_env(monkeypatch, {
        "AI_AGENT_AUDIT_PROFILE": "hermes",
        "OPENCLAW_HOME": None,
        "HERMES_HOME": None,
    })
    assert profile.slug == "hermes"
    assert profile.config_filename == "hermes.json"
    assert profile.home == Path.home() / ".hermes"

    # Legacy aliases must route to the active profile, not the literal openclaw home
    assert config.OPENCLAW_HOME == profile.home
    assert config.OPENCLAW_CONFIG == profile.home / "hermes.json"
    assert config.AUDIT_DIR == profile.home / ".audit"


def test_home_dir_override_via_env(monkeypatch, tmp_path):
    custom = tmp_path / "fake-hermes"
    profile, _ = _reload_config_with_env(monkeypatch, {
        "AI_AGENT_AUDIT_PROFILE": "hermes",
        "HERMES_HOME": str(custom),
        "OPENCLAW_HOME": None,
    })
    assert profile.home == custom
    assert profile.config_path == custom / "hermes.json"


def test_auto_resolution_prefers_existing_install(monkeypatch, tmp_path):
    """auto should pick OpenClaw if its home exists, even with Hermes home set."""
    openclaw_home = tmp_path / "openclaw"
    openclaw_home.mkdir()
    hermes_home = tmp_path / "hermes"
    hermes_home.mkdir()

    profile, _ = _reload_config_with_env(monkeypatch, {
        "AI_AGENT_AUDIT_PROFILE": "auto",
        "OPENCLAW_HOME": str(openclaw_home),
        "HERMES_HOME": str(hermes_home),
    })
    # Per resolution order, OpenClaw wins when both exist
    assert profile.slug == "openclaw"


def test_auto_resolution_picks_hermes_when_only_hermes_exists(monkeypatch, tmp_path):
    hermes_home = tmp_path / "hermes"
    hermes_home.mkdir()
    nonexistent_openclaw = tmp_path / "openclaw-not-here"

    profile, _ = _reload_config_with_env(monkeypatch, {
        "AI_AGENT_AUDIT_PROFILE": "auto",
        "OPENCLAW_HOME": str(nonexistent_openclaw),
        "HERMES_HOME": str(hermes_home),
    })
    assert profile.slug == "hermes"


def test_unknown_profile_raises(monkeypatch):
    monkeypatch.setenv("AI_AGENT_AUDIT_PROFILE", "claude-code")
    sys.modules.pop("ai_agent_audit.agents", None)
    sys.modules.pop("ai_agent_audit.config", None)
    agents = importlib.import_module("ai_agent_audit.agents")
    with pytest.raises(ValueError, match="Unknown agent profile"):
        agents.get_active_profile()


def test_suspicious_systemd_pattern_uses_profile_keywords(monkeypatch):
    _, config = _reload_config_with_env(monkeypatch, {
        "AI_AGENT_AUDIT_PROFILE": "hermes",
        "HERMES_HOME": None,
    })
    systemd = next(
        p for p in config.SUSPICIOUS_PROCESS_PATTERNS
        if p["name"] == "Systemd service"
    )
    # Pattern must mention hermes keywords, not openclaw, when Hermes is active
    assert "hermes" in systemd["pattern"]
    assert "openclaw" not in systemd["pattern"]


def test_exfil_compression_uses_profile_home_dotdir(monkeypatch):
    _, config = _reload_config_with_env(monkeypatch, {
        "AI_AGENT_AUDIT_PROFILE": "hermes",
        "HERMES_HOME": None,
    })
    compress = next(
        p for p in config.EXFIL_PATTERNS
        if p["name"] == "Compression before exfil"
    )
    assert ".hermes" in compress["pattern"]
    assert ".openclaw" not in compress["pattern"]


def test_mdns_detail_uses_display_name(monkeypatch):
    _, config = _reload_config_with_env(monkeypatch, {
        "AI_AGENT_AUDIT_PROFILE": "hermes",
        "HERMES_HOME": None,
    })
    mdns = next(
        r for r in config.INSECURE_CONFIG_RULES
        if r["key"] == "network.mdns.broadcast"
    )
    assert "Hermes" in mdns["detail"]
