"""Tests for config_watcher detection rules."""

import json
import tempfile
from pathlib import Path

from ai_agent_audit.models import Finding, Severity
from ai_agent_audit.monitors.config_watcher import ConfigWatcher


def _run_config_check(config_data: dict) -> list[Finding]:
    """Write config to temp file, run a single check, return findings."""
    findings: list[Finding] = []

    tmp_dir = Path(tempfile.mkdtemp())
    config_path = tmp_dir / "openclaw.json"
    config_path.write_text(json.dumps(config_data))

    watcher = ConfigWatcher(on_finding=findings.append, config_path=config_path)
    watcher._check_config()
    return findings


def test_secure_config_no_findings():
    config = {
        "gateway": {
            "bind": "127.0.0.1",
            "auth": {"enabled": True, "allowOpenDM": False, "deviceAuth": True},
        },
        "sandbox": {"enabled": True},
        "logging": {"redactSecrets": True},
        "network": {"mdns": {"broadcast": False}},
    }
    findings = _run_config_check(config)
    assert len(findings) == 0


def test_gateway_non_loopback():
    config = {"gateway": {"bind": "0.0.0.0"}}
    findings = _run_config_check(config)
    titles = [f.title for f in findings]
    assert "Gateway bound to non-loopback address" in titles
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical) >= 1


def test_auth_disabled():
    config = {"gateway": {"auth": {"enabled": False}}}
    findings = _run_config_check(config)
    titles = [f.title for f in findings]
    assert "Authentication disabled" in titles


def test_open_dm_policy():
    config = {"gateway": {"auth": {"allowOpenDM": True}}}
    findings = _run_config_check(config)
    titles = [f.title for f in findings]
    assert "Open DM policy enabled" in titles


def test_sandbox_disabled():
    config = {"sandbox": {"enabled": False}}
    findings = _run_config_check(config)
    titles = [f.title for f in findings]
    assert "Sandbox disabled" in titles
    # Sandbox is WARNING, not CRITICAL
    sandbox_finding = [f for f in findings if f.title == "Sandbox disabled"][0]
    assert sandbox_finding.severity == Severity.WARNING


def test_device_auth_disabled():
    config = {"gateway": {"auth": {"deviceAuth": False}}}
    findings = _run_config_check(config)
    titles = [f.title for f in findings]
    assert "Device authentication disabled" in titles


def test_log_redaction_disabled():
    config = {"logging": {"redactSecrets": False}}
    findings = _run_config_check(config)
    titles = [f.title for f in findings]
    assert "Log secret redaction disabled" in titles


def test_mdns_broadcast():
    config = {"network": {"mdns": {"broadcast": True}}}
    findings = _run_config_check(config)
    titles = [f.title for f in findings]
    assert "Full mDNS broadcast enabled" in titles


def test_hardcoded_api_key():
    config = {"apiKey": "sk-ant-abcdefghijklmnopqrstuvwxyz123456"}
    findings = _run_config_check(config)
    secrets = [f for f in findings if "Hardcoded secret" in f.title]
    assert len(secrets) >= 1


def test_missing_config_no_crash():
    """Non-existent config should not crash."""
    findings: list[Finding] = []
    watcher = ConfigWatcher(
        on_finding=findings.append,
        config_path=Path("/nonexistent/openclaw.json"),
    )
    watcher._check_config()
    assert len(findings) == 0


def test_multiple_issues():
    """Config with multiple issues should produce multiple findings."""
    config = {
        "gateway": {
            "bind": "0.0.0.0",
            "auth": {"enabled": False, "allowOpenDM": True},
        },
        "sandbox": {"enabled": False},
    }
    findings = _run_config_check(config)
    assert len(findings) >= 4  # non-loopback, auth disabled, open DM, sandbox off
