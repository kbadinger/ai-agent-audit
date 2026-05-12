"""Tests for STIX 2.1 export."""

import json

from ai_agent_audit.stix import findings_to_stix, ioc_to_stix, stix_to_json


def _make_finding(**overrides):
    base = {
        "id": 1,
        "dedup_hash": "abc123",
        "module": "test",
        "severity": 2,
        "title": "Test finding",
        "detail": "Detail text",
        "path": "/test/file.json",
        "confidence": 0.85,
        "mitre_attack": "T1190",
        "owasp_asi": "ASI03",
    }
    base.update(overrides)
    return base


class TestFindingsToSTIX:
    def test_bundle_structure(self):
        bundle = findings_to_stix([])
        assert bundle["type"] == "bundle"
        assert "id" in bundle
        assert "objects" in bundle
        # Should have identity object even with no findings
        assert len(bundle["objects"]) == 1
        assert bundle["objects"][0]["type"] == "identity"

    def test_finding_as_indicator(self):
        f = _make_finding()
        bundle = findings_to_stix([f])
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert len(indicators) == 1
        ind = indicators[0]
        assert ind["spec_version"] == "2.1"
        assert ind["name"] == "Test finding"
        assert ind["confidence"] == 85

    def test_mitre_external_reference(self):
        f = _make_finding(mitre_attack="T1190")
        bundle = findings_to_stix([f])
        ind = [o for o in bundle["objects"] if o["type"] == "indicator"][0]
        refs = ind.get("external_references", [])
        mitre_refs = [r for r in refs if r["source_name"] == "mitre-attack"]
        assert len(mitre_refs) == 1
        assert mitre_refs[0]["external_id"] == "T1190"

    def test_owasp_external_reference(self):
        f = _make_finding(owasp_asi="ASI03")
        bundle = findings_to_stix([f])
        ind = [o for o in bundle["objects"] if o["type"] == "indicator"][0]
        refs = ind.get("external_references", [])
        owasp_refs = [r for r in refs if r["source_name"] == "owasp-agentic-top-10"]
        assert len(owasp_refs) == 1

    def test_severity_labels(self):
        f = _make_finding(severity=2)
        bundle = findings_to_stix([f])
        ind = [o for o in bundle["objects"] if o["type"] == "indicator"][0]
        assert "critical" in ind["labels"]

    def test_json_roundtrip(self):
        bundle = findings_to_stix([_make_finding()])
        text = stix_to_json(bundle)
        parsed = json.loads(text)
        assert parsed["type"] == "bundle"


class TestIOCToSTIX:
    def test_ioc_bundle_has_indicators(self):
        bundle = ioc_to_stix()
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert len(indicators) > 0  # Should have C2 IPs + domains + hashes

    def test_ioc_has_c2_ips(self):
        bundle = ioc_to_stix()
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        c2_indicators = [i for i in indicators if "C2 IP" in i["name"]]
        assert len(c2_indicators) >= 5  # We have 5 C2 IPs

    def test_ioc_has_domains(self):
        bundle = ioc_to_stix()
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        domain_indicators = [i for i in indicators if "domain" in i["name"].lower()]
        assert len(domain_indicators) >= 9  # We have 9 malicious domains

    def test_ioc_has_threat_actors(self):
        bundle = ioc_to_stix()
        actors = [o for o in bundle["objects"] if o["type"] == "threat-actor"]
        assert len(actors) >= 8  # We have 8+ malicious publishers

    def test_ioc_stix_patterns(self):
        bundle = ioc_to_stix()
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        ip_ind = [i for i in indicators if "ipv4-addr" in i.get("pattern", "")]
        assert len(ip_ind) >= 1
