"""Tests for SARIF v2.1.0 output formatter."""

import json

from openclaw_audit.sarif import findings_to_sarif, sarif_to_json


def _make_finding(**overrides):
    base = {
        "id": 1,
        "dedup_hash": "abc123def456",
        "module": "test_module",
        "severity": 2,
        "title": "Test finding",
        "detail": "This is a test finding detail.",
        "path": "/home/user/.openclaw/openclaw.json",
        "confidence": 0.85,
        "first_seen": 1700000000.0,
        "last_seen": 1700000100.0,
        "times_seen": 3,
        "mitre_attack": "T1190",
        "owasp_asi": "ASI03",
        "remediation": "Fix the thing.",
        "triage_status": None,
    }
    base.update(overrides)
    return base


class TestSARIFFormatter:
    def test_sarif_schema_version(self):
        sarif = findings_to_sarif([])
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert "sarif-schema-2.1.0" in sarif["$schema"]

    def test_sarif_empty_findings(self):
        sarif = findings_to_sarif([])
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []

    def test_sarif_tool_metadata(self):
        sarif = findings_to_sarif([], tool_version="1.2.3")
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "openclaw-audit"
        assert driver["version"] == "1.2.3"

    def test_sarif_finding_mapping(self):
        f = _make_finding()
        sarif = findings_to_sarif([f])
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        result = results[0]
        assert result["ruleId"] == "abc123def456"
        assert result["level"] == "error"  # CRITICAL -> error
        assert result["message"]["text"] == "This is a test finding detail."

    def test_sarif_severity_mapping(self):
        for sev, expected_level in [(0, "note"), (1, "warning"), (2, "error")]:
            f = _make_finding(severity=sev, dedup_hash=f"hash{sev}")
            sarif = findings_to_sarif([f])
            result = sarif["runs"][0]["results"][0]
            assert result["level"] == expected_level, f"severity {sev} should map to {expected_level}"

    def test_sarif_location_from_path(self):
        f = _make_finding(path="/test/path.json")
        sarif = findings_to_sarif([f])
        result = sarif["runs"][0]["results"][0]
        loc = result["locations"][0]["physicalLocation"]["artifactLocation"]
        assert loc["uri"] == "/test/path.json"

    def test_sarif_no_location_when_no_path(self):
        f = _make_finding(path=None)
        sarif = findings_to_sarif([f])
        result = sarif["runs"][0]["results"][0]
        assert "locations" not in result

    def test_sarif_mitre_owasp_tags(self):
        f = _make_finding(mitre_attack="T1190", owasp_asi="ASI03")
        sarif = findings_to_sarif([f])
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "mitre:T1190" in rule["properties"]["tags"]
        assert "owasp:ASI03" in rule["properties"]["tags"]

    def test_sarif_rule_dedup(self):
        """Two findings with same dedup_hash should create only one rule."""
        f1 = _make_finding(detail="first")
        f2 = _make_finding(detail="second")
        sarif = findings_to_sarif([f1, f2])
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        results = sarif["runs"][0]["results"]
        assert len(rules) == 1
        assert len(results) == 2

    def test_sarif_remediation_as_help(self):
        f = _make_finding(remediation="Fix it now.")
        sarif = findings_to_sarif([f])
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["help"]["text"] == "Fix it now."

    def test_sarif_triage_status_in_properties(self):
        f = _make_finding(triage_status="confirmed")
        sarif = findings_to_sarif([f])
        result = sarif["runs"][0]["results"][0]
        assert result["properties"]["triageStatus"] == "confirmed"

    def test_sarif_to_json_roundtrip(self):
        f = _make_finding()
        sarif = findings_to_sarif([f])
        text = sarif_to_json(sarif)
        parsed = json.loads(text)
        assert parsed["version"] == "2.1.0"
