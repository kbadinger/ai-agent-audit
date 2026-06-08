"""Tests for the abuse.ch ThreatFox IOC feed parser and updater integration."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from ai_agent_audit.ioc_updater import (
    IOCUpdater,
    parse_threatfox,
    _looks_like_threatfox,
)


_SAMPLE = {
    "1001": [{
        "ioc_value": "203.0.113.5:443",
        "ioc_type": "ip:port",
        "threat_type": "botnet_cc",
        "malware": "win.remcos",
        "malware_printable": "Remcos",
        "confidence_level": 100,
    }],
    "1002": [{
        "ioc_value": "evil-c2.example.com",
        "ioc_type": "domain",
        "threat_type": "botnet_cc",
        "malware_printable": "Cobalt Strike",
        "confidence_level": 90,
    }],
    "1003": [{
        "ioc_value": "https://drop.example.net/payload.bin",
        "ioc_type": "url",
        "threat_type": "payload_delivery",
        "malware_printable": "AMOS",
        "confidence_level": 80,
    }],
    "1004": [{
        "ioc_value": "a" * 64,
        "ioc_type": "sha256_hash",
        "malware_printable": "AMOS Stealer",
        "confidence_level": 95,
    }],
    "1005": [{
        "ioc_value": "low-confidence.example.org",
        "ioc_type": "domain",
        "confidence_level": 10,  # below default threshold, dropped
    }],
}


class TestThreatFoxParser:
    def test_looks_like_threatfox_true(self):
        assert _looks_like_threatfox(_SAMPLE) is True

    def test_looks_like_threatfox_false_for_native_schema(self):
        assert _looks_like_threatfox({"c2_ips": [], "malicious_domains": []}) is False

    def test_looks_like_threatfox_false_for_nondict(self):
        assert _looks_like_threatfox([1, 2, 3]) is False

    def test_ip_port_maps_to_c2_ip_without_port(self):
        out = parse_threatfox(_SAMPLE)
        assert "203.0.113.5" in out["c2_ips"]

    def test_domain_maps_to_malicious_domains(self):
        out = parse_threatfox(_SAMPLE)
        assert "evil-c2.example.com" in out["malicious_domains"]

    def test_url_maps_to_host(self):
        out = parse_threatfox(_SAMPLE)
        assert "drop.example.net" in out["malicious_domains"]

    def test_hash_maps_to_file_hashes_with_label(self):
        out = parse_threatfox(_SAMPLE)
        assert out["file_hashes"]["a" * 64] == "AMOS Stealer"

    def test_low_confidence_dropped(self):
        out = parse_threatfox(_SAMPLE)
        assert "low-confidence.example.org" not in out["malicious_domains"]

    def test_confidence_threshold_override(self):
        out = parse_threatfox(_SAMPLE, min_confidence=0)
        assert "low-confidence.example.org" in out["malicious_domains"]


class TestUpdaterIntegration:
    def test_update_from_file_detects_threatfox_schema(self):
        tmp = tempfile.mkdtemp()
        feed = Path(tmp) / "feed.json"
        feed.write_text(json.dumps(_SAMPLE))
        custom = Path(tmp) / "ioc-custom.json"

        updater = IOCUpdater()
        with patch("ai_agent_audit.ioc_updater.CUSTOM_IOC_PATH", custom):
            stats = updater.update_from_file(feed)

        assert "error" not in stats
        assert stats["c2_ips_added"] == 1
        assert stats["malicious_domains_added"] == 2  # domain + url host
        assert stats["file_hashes_added"] == 1
        saved = json.loads(custom.read_text())
        assert "203.0.113.5" in saved["c2_ips"]

    def test_update_from_file_native_schema_still_works(self):
        tmp = tempfile.mkdtemp()
        feed = Path(tmp) / "native.json"
        feed.write_text(json.dumps({"c2_ips": ["198.51.100.7"], "malicious_domains": ["bad.test"]}))
        custom = Path(tmp) / "ioc-custom.json"

        updater = IOCUpdater()
        with patch("ai_agent_audit.ioc_updater.CUSTOM_IOC_PATH", custom):
            stats = updater.update_from_file(feed)

        assert stats["c2_ips_added"] == 1
        assert stats["malicious_domains_added"] == 1

    def test_update_from_threatfox_uses_feed(self):
        tmp = tempfile.mkdtemp()
        custom = Path(tmp) / "ioc-custom.json"
        updater = IOCUpdater()
        with patch.object(updater, "_fetch_url", return_value=_SAMPLE), \
                patch("ai_agent_audit.ioc_updater.CUSTOM_IOC_PATH", custom):
            stats = updater.update_from_threatfox()
        assert "error" not in stats
        assert stats["c2_ips_added"] == 1
