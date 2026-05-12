"""Tests for CVE-2026-28363 safeBins bypass detection sweep."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from ai_agent_audit.sweeps.safebins_bypass import SafeBinsBypassSweep


def _run_with_config(config_data):
    """Helper: write config, run sweep, return findings."""
    tmp = tempfile.mkdtemp()
    config_path = Path(tmp) / "openclaw.json"
    config_path.write_text(json.dumps(config_data))

    sweep = SafeBinsBypassSweep()
    with patch("ai_agent_audit.sweeps.safebins_bypass.OPENCLAW_CONFIG", config_path):
        result = sweep.run()
    return result.findings


class TestSafeBinsBypass:
    def test_no_config_file(self):
        sweep = SafeBinsBypassSweep()
        with patch("ai_agent_audit.sweeps.safebins_bypass.OPENCLAW_CONFIG",
                    Path("/nonexistent/openclaw.json")):
            result = sweep.run()
        assert len(result.findings) == 1
        assert "not found" in result.findings[0].title.lower() or "not found" in result.findings[0].detail.lower()

    def test_sandbox_disabled(self):
        findings = _run_with_config({"sandbox": {"enabled": False}})
        assert any("disabled" in f.title.lower() for f in findings)

    def test_empty_safebins(self):
        findings = _run_with_config({"sandbox": {"enabled": True, "safeBins": []}})
        assert any("empty" in f.title.lower() for f in findings)

    def test_dangerous_binary_bash(self):
        findings = _run_with_config({
            "sandbox": {"enabled": True, "safeBins": ["/bin/bash"]}
        })
        critical = [f for f in findings if f.severity.name == "CRITICAL"]
        assert len(critical) >= 1
        assert any("bash" in f.title.lower() for f in critical)

    def test_dangerous_binary_python(self):
        findings = _run_with_config({
            "sandbox": {"enabled": True, "safeBins": ["/usr/bin/python3"]}
        })
        critical = [f for f in findings if f.severity.name == "CRITICAL"]
        assert any("python3" in f.title.lower() for f in critical)

    def test_safe_binary_ls(self):
        findings = _run_with_config({
            "sandbox": {"enabled": True, "safeBins": ["/bin/ls"]}
        })
        critical = [f for f in findings if f.severity.name == "CRITICAL"]
        assert len(critical) == 0

    def test_path_traversal_pattern(self):
        findings = _run_with_config({
            "sandbox": {"enabled": True, "safeBins": ["/usr/../bin/cat"]}
        })
        critical = [f for f in findings if f.severity.name == "CRITICAL"]
        assert any("traversal" in f.title.lower() or "bypass" in f.title.lower() for f in critical)

    def test_glob_pattern(self):
        findings = _run_with_config({
            "sandbox": {"enabled": True, "safeBins": ["/usr/bin/*"]}
        })
        critical = [f for f in findings if f.severity.name == "CRITICAL"]
        assert len(critical) >= 1

    def test_relative_path(self):
        findings = _run_with_config({
            "sandbox": {"enabled": True, "safeBins": ["cat", "ls"]}
        })
        critical = [f for f in findings if f.severity.name == "CRITICAL"]
        assert any("relative" in f.title.lower() for f in critical)

    def test_variable_expansion(self):
        findings = _run_with_config({
            "sandbox": {"enabled": True, "safeBins": ["$HOME/bin/tool"]}
        })
        critical = [f for f in findings if f.severity.name == "CRITICAL"]
        assert any("bypass" in f.title.lower() for f in critical)

    def test_multiple_dangerous_bins(self):
        findings = _run_with_config({
            "sandbox": {"enabled": True, "safeBins": ["/bin/bash", "/usr/bin/env", "/bin/sh"]}
        })
        critical = [f for f in findings if f.severity.name == "CRITICAL"]
        assert len(critical) >= 3  # one per dangerous binary
