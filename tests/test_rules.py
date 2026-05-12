"""Tests for YAML custom rule engine."""

import tempfile
from pathlib import Path
from unittest.mock import patch

from ai_agent_audit.rules import _parse_yaml, load_rules, CustomRulesSweep


class TestParseYaml:
    def test_simple_key_value(self):
        result = _parse_yaml("name: test rule\npattern: foo.*bar")
        assert result["name"] == "test rule"
        assert result["pattern"] == "foo.*bar"

    def test_quoted_values(self):
        result = _parse_yaml('name: "quoted value"')
        assert result["name"] == "quoted value"

    def test_boolean_values(self):
        result = _parse_yaml("enabled: true\ndisabled: false")
        assert result["enabled"] is True
        assert result["disabled"] is False

    def test_comments_ignored(self):
        result = _parse_yaml("# comment\nname: test\n# another comment")
        assert result == {"name": "test"}

    def test_empty_lines_ignored(self):
        result = _parse_yaml("\n\nname: test\n\n")
        assert result == {"name": "test"}

    def test_list_values(self):
        result = _parse_yaml("paths:\n- /path/one\n- /path/two")
        assert result["paths"] == ["/path/one", "/path/two"]


class TestCustomRulesSweep:
    def test_no_rules_dir(self):
        sweep = CustomRulesSweep()
        with patch("ai_agent_audit.rules.RULES_DIR", Path("/nonexistent")):
            result = sweep.run()
        assert len(result.findings) == 0

    def test_file_content_rule_matches(self):
        tmp = Path(tempfile.mkdtemp())
        rules_dir = tmp / "rules"
        rules_dir.mkdir()

        # Write a rule
        (rules_dir / "test.yaml").write_text(
            "name: Detect secret\n"
            "target: file_content\n"
            "pattern: sk-ant-[a-zA-Z0-9]+\n"
            "severity: critical\n"
            "mitre_attack: T1552.001\n"
            "owasp_asi: ASI03\n"
            "remediation: Remove the secret\n"
        )

        # Write a target file
        target_dir = tmp / "home"
        target_dir.mkdir()
        (target_dir / "config.txt").write_text("api_key = sk-ant-abc123def456")

        sweep = CustomRulesSweep()
        with patch("ai_agent_audit.rules.RULES_DIR", rules_dir), \
             patch("ai_agent_audit.rules.OPENCLAW_HOME", target_dir):
            result = sweep.run()

        assert len(result.findings) >= 1
        f = result.findings[0]
        assert f.title == "Detect secret"
        assert f.mitre_attack == "T1552.001"
        assert f.owasp_asi == "ASI03"

    def test_file_content_rule_no_match(self):
        tmp = Path(tempfile.mkdtemp())
        rules_dir = tmp / "rules"
        rules_dir.mkdir()

        (rules_dir / "test.yaml").write_text(
            "name: Detect malware\n"
            "target: file_content\n"
            "pattern: MALWARE_SIGNATURE_XYZ\n"
            "severity: critical\n"
        )

        target_dir = tmp / "home"
        target_dir.mkdir()
        (target_dir / "clean.txt").write_text("This file is clean.")

        sweep = CustomRulesSweep()
        with patch("ai_agent_audit.rules.RULES_DIR", rules_dir), \
             patch("ai_agent_audit.rules.OPENCLAW_HOME", target_dir):
            result = sweep.run()

        # Should have no findings (rule didn't match)
        assert len(result.findings) == 0

    def test_config_value_rule(self):
        tmp = Path(tempfile.mkdtemp())
        rules_dir = tmp / "rules"
        rules_dir.mkdir()

        (rules_dir / "config.yaml").write_text(
            "name: Insecure bind\n"
            "target: config_value\n"
            "config_key: gateway.bind\n"
            "pattern: 0\\.0\\.0\\.0\n"
            "severity: critical\n"
        )

        config_path = tmp / "openclaw.json"
        config_path.write_text('{"gateway": {"bind": "0.0.0.0"}}')

        sweep = CustomRulesSweep()
        with patch("ai_agent_audit.rules.RULES_DIR", rules_dir), \
             patch("ai_agent_audit.rules.OPENCLAW_CONFIG", config_path):
            result = sweep.run()

        assert len(result.findings) >= 1
        assert result.findings[0].title == "Insecure bind"

    def test_invalid_regex_reported(self):
        tmp = Path(tempfile.mkdtemp())
        rules_dir = tmp / "rules"
        rules_dir.mkdir()

        (rules_dir / "bad.yaml").write_text(
            "name: Bad regex\n"
            "target: file_content\n"
            "pattern: [invalid\n"
            "severity: warning\n"
        )

        sweep = CustomRulesSweep()
        with patch("ai_agent_audit.rules.RULES_DIR", rules_dir), \
             patch("ai_agent_audit.rules.OPENCLAW_HOME", tmp):
            result = sweep.run()

        assert any("Invalid regex" in f.title for f in result.findings)

    def test_missing_name_skipped(self):
        tmp = Path(tempfile.mkdtemp())
        rules_dir = tmp / "rules"
        rules_dir.mkdir()

        (rules_dir / "noname.yaml").write_text(
            "pattern: something\nseverity: warning\n"
        )

        rules = []
        with patch("ai_agent_audit.rules.RULES_DIR", rules_dir):
            rules = load_rules()

        assert len(rules) == 0
