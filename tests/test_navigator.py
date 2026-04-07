"""Tests for MITRE ATT&CK Navigator layer export."""

import json

from openclaw_audit.navigator import findings_to_navigator, navigator_to_json


def _make_finding(**overrides):
    base = {
        "id": 1,
        "dedup_hash": "abc123",
        "module": "test",
        "severity": 2,
        "title": "Test finding",
        "detail": "Detail",
        "path": "/test",
        "confidence": 0.9,
        "mitre_attack": "T1190",
        "owasp_asi": "ASI03",
    }
    base.update(overrides)
    return base


class TestNavigatorExport:
    def test_layer_structure(self):
        layer = findings_to_navigator([])
        assert layer["name"] == "openclaw-audit"
        assert layer["domain"] == "enterprise-attack"
        assert "techniques" in layer
        assert "gradient" in layer
        assert "legendItems" in layer

    def test_empty_findings(self):
        layer = findings_to_navigator([])
        assert layer["techniques"] == []

    def test_technique_mapping(self):
        f = _make_finding(mitre_attack="T1190", severity=2)
        layer = findings_to_navigator([f])
        assert len(layer["techniques"]) == 1
        tech = layer["techniques"][0]
        assert tech["techniqueID"] == "T1190"
        assert tech["score"] == 100  # CRITICAL
        assert tech["color"] == "#ff6666"

    def test_severity_colors(self):
        findings = [
            _make_finding(mitre_attack="T1190", severity=2, dedup_hash="a"),
            _make_finding(mitre_attack="T1110", severity=1, dedup_hash="b"),
            _make_finding(mitre_attack="T1018", severity=0, dedup_hash="c"),
        ]
        layer = findings_to_navigator(findings)
        by_id = {t["techniqueID"]: t for t in layer["techniques"]}
        assert by_id["T1190"]["color"] == "#ff6666"  # Red
        assert by_id["T1110"]["color"] == "#ffcc00"  # Yellow
        assert by_id["T1018"]["color"] == "#99ccff"  # Blue

    def test_no_mitre_attack_skipped(self):
        f = _make_finding(mitre_attack=None)
        layer = findings_to_navigator([f])
        assert layer["techniques"] == []

    def test_subtechnique(self):
        f = _make_finding(mitre_attack="T1059.004")
        layer = findings_to_navigator([f])
        tech = layer["techniques"][0]
        assert tech["techniqueID"] == "T1059.004"
        assert tech["showSubtechniques"] is True

    def test_highest_severity_wins(self):
        findings = [
            _make_finding(mitre_attack="T1190", severity=0, dedup_hash="a"),
            _make_finding(mitre_attack="T1190", severity=2, dedup_hash="b"),
        ]
        layer = findings_to_navigator(findings)
        assert len(layer["techniques"]) == 1
        assert layer["techniques"][0]["score"] == 100

    def test_json_roundtrip(self):
        layer = findings_to_navigator([_make_finding()])
        text = navigator_to_json(layer)
        parsed = json.loads(text)
        assert parsed["name"] == "openclaw-audit"

    def test_custom_layer_name(self):
        layer = findings_to_navigator([], layer_name="my-scan", description="My scan results")
        assert layer["name"] == "my-scan"
        assert layer["description"] == "My scan results"
