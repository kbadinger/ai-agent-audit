"""Tests that fed IOCs reach live detection, and the daemon auto-refresh gate."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from ai_agent_audit import ioc
from ai_agent_audit.engine import AuditEngine


@pytest.fixture
def restore_ioc_sets():
    """Snapshot and restore the in-memory IOC collections around a test."""
    snap = (
        set(ioc.C2_IPS), set(ioc.MALICIOUS_DOMAINS), set(ioc.EXFIL_DOMAINS),
        dict(ioc.MALICIOUS_HASHES), dict(ioc.MALICIOUS_PUBLISHERS),
    )
    yield
    ioc.C2_IPS.clear(); ioc.C2_IPS.update(snap[0])
    ioc.MALICIOUS_DOMAINS.clear(); ioc.MALICIOUS_DOMAINS.update(snap[1])
    ioc.EXFIL_DOMAINS.clear(); ioc.EXFIL_DOMAINS.update(snap[2])
    ioc.MALICIOUS_HASHES.clear(); ioc.MALICIOUS_HASHES.update(snap[3])
    ioc.MALICIOUS_PUBLISHERS.clear(); ioc.MALICIOUS_PUBLISHERS.update(snap[4])


class TestLoadCustomIOCs:
    def test_feed_iocs_reach_in_memory_sets(self, restore_ioc_sets):
        tmp = Path(tempfile.mkdtemp()) / "ioc-custom.json"
        tmp.write_text(json.dumps({
            "c2_ips": ["111.111.111.111"],
            "malicious_domains": ["feed-bad.example"],
            "file_hashes": {"deadbeefdeadbeef": "FeedMalware"},
            "malicious_publishers": {"evilpub": "known-bad"},
        }))

        loaded = ioc.load_custom_iocs(path=tmp)

        assert loaded == 5
        assert "111.111.111.111" in ioc.C2_IPS
        assert "feed-bad.example" in ioc.MALICIOUS_DOMAINS
        assert "feed-bad.example" in ioc.EXFIL_DOMAINS  # snapshot union kept in sync
        assert ioc.MALICIOUS_HASHES["deadbeefdeadbeef"] == "FeedMalware"
        assert "evilpub" in ioc.MALICIOUS_PUBLISHERS

    def test_consumers_see_the_same_objects(self, restore_ioc_sets):
        """Detection modules import the IOC objects directly; in-place updates must show."""
        from ai_agent_audit.sweeps import mcp_security
        from ai_agent_audit.sweeps import network_forensics
        assert mcp_security.C2_IPS is ioc.C2_IPS
        assert network_forensics.EXFIL_DOMAINS is ioc.EXFIL_DOMAINS

        tmp = Path(tempfile.mkdtemp()) / "ioc-custom.json"
        tmp.write_text(json.dumps({"c2_ips": ["222.222.222.222"]}))
        ioc.load_custom_iocs(path=tmp)
        assert "222.222.222.222" in mcp_security.C2_IPS

    def test_missing_file_returns_zero(self):
        assert ioc.load_custom_iocs(path=Path("/nonexistent/ioc-custom.json")) == 0


class TestAutoRefreshGate:
    def _stub_updater(self):
        mock = MagicMock(return_value={"c2_ips_added": 3})
        return mock

    def test_refresh_runs_then_is_gated(self):
        baselines = Path(tempfile.mkdtemp())
        update = self._stub_updater()
        with patch("ai_agent_audit.engine.AUDIT_BASELINES", baselines), \
                patch("ai_agent_audit.engine.IOC_AUTO_REFRESH", True), \
                patch("ai_agent_audit.engine.IOC_REFRESH_INTERVAL_SECONDS", 3600), \
                patch("ai_agent_audit.engine.load_custom_iocs", return_value=3), \
                patch("ai_agent_audit.ioc_updater.IOCUpdater.update_from_threatfox", update):
            AuditEngine._maybe_refresh_iocs(None)
            assert update.call_count == 1
            assert (baselines / "ioc-refresh.json").exists()
            # Second call within the interval must not fetch again
            AuditEngine._maybe_refresh_iocs(None)
            assert update.call_count == 1

    def test_disabled_does_not_refresh(self):
        baselines = Path(tempfile.mkdtemp())
        update = self._stub_updater()
        with patch("ai_agent_audit.engine.AUDIT_BASELINES", baselines), \
                patch("ai_agent_audit.engine.IOC_AUTO_REFRESH", False), \
                patch("ai_agent_audit.ioc_updater.IOCUpdater.update_from_threatfox", update):
            AuditEngine._maybe_refresh_iocs(None)
            assert update.call_count == 0

    def test_network_error_does_not_raise_or_stamp(self):
        baselines = Path(tempfile.mkdtemp())
        update = MagicMock(return_value={"error": "network down"})
        with patch("ai_agent_audit.engine.AUDIT_BASELINES", baselines), \
                patch("ai_agent_audit.engine.IOC_AUTO_REFRESH", True), \
                patch("ai_agent_audit.engine.IOC_REFRESH_INTERVAL_SECONDS", 3600), \
                patch("ai_agent_audit.ioc_updater.IOCUpdater.update_from_threatfox", update):
            AuditEngine._maybe_refresh_iocs(None)  # must not raise
            # Stamp not written on failure -> retries next cycle
            assert not (baselines / "ioc-refresh.json").exists()
