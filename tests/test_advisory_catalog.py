import json
from unittest.mock import patch

from ai_agent_audit.advisory_catalog import AdvisoryCatalogUpdater, _version_text, load_catalog


def test_version_text_handles_date_and_semver_ranges():
    assert _version_text(">= 2026.5.20, < 2026.6.9") == "2026.5.20"
    assert _version_text(">= 0.18.2") == "0.18.2"


def test_updater_normalizes_ghsa_and_caches(tmp_path):
    cache = tmp_path / "advisories.json"
    payload = [{
        "ghsa_id": "GHSA-test-1234-5678",
        "cve_id": None,
        "summary": "Approval bypass",
        "severity": "high",
        "html_url": "https://example.invalid/advisory",
        "vulnerabilities": [{
            "vulnerable_version_range": ">= 2026.5.20, < 2026.6.9",
            "patched_versions": ">= 2026.6.9",
        }],
    }]
    updater = AdvisoryCatalogUpdater()
    with patch("ai_agent_audit.advisory_catalog.CATALOG_CACHE", cache), \
            patch.object(updater, "_fetch", return_value=payload):
        stats = updater.update("openclaw")
    assert stats["advisories_loaded"] == 1
    record = json.loads(cache.read_text())["advisories"]["openclaw"][0]
    assert record["id"] == "GHSA-test-1234-5678"
    assert record["introduced"] == "2026.5.20"
    assert record["fixed"] == "2026.6.9"


def test_bundled_catalog_contains_current_ghsa(tmp_path):
    with patch("ai_agent_audit.advisory_catalog.CATALOG_CACHE", tmp_path / "missing.json"):
        ids = {entry["id"] for entry in load_catalog("openclaw")}
    assert "GHSA-3fp5-v549-9v66" in ids
