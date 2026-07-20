"""Tests for the agent version CVE check (Claw Chain + Hermes core CVEs)."""

import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ai_agent_audit.sweeps.agent_version_check import (
    AgentVersionCheckSweep,
    _parse_version,
)


def _profile(slug, display):
    return SimpleNamespace(slug=slug, display_name=display, version_command=())


def _run(profile, version=None, config_extra=None):
    """Write a config (optionally with a version), patch globals, run the sweep."""
    tmp = tempfile.mkdtemp()
    config_path = Path(tmp) / f"{profile.slug}.json"
    data = dict(config_extra or {})
    if version is not None:
        data["version"] = version
    config_path.write_text(json.dumps(data))

    sweep = AgentVersionCheckSweep()
    with patch("ai_agent_audit.sweeps.agent_version_check.ACTIVE_PROFILE", profile), \
            patch("ai_agent_audit.sweeps.agent_version_check.AGENT_CONFIG", config_path):
        return sweep.run().findings


def _titles(findings):
    return [f.title for f in findings]


class TestParseVersion:
    def test_date_scheme(self):
        assert _parse_version("2026.4.22") == (2026, 4, 22)

    def test_v_prefix(self):
        assert _parse_version("v0.9.0") == (0, 9, 0)

    def test_unparseable(self):
        assert _parse_version("not-a-version") is None


class TestOpenClawClawChain:
    def test_vulnerable_version_flags_all_four(self):
        findings = _run(_profile("openclaw", "OpenClaw"), version="2026.4.10")
        cves = [f for f in findings if f.title.startswith("CVE-")]
        ids = " ".join(_titles(cves))
        assert "CVE-2026-44112" in ids
        assert "CVE-2026-44113" in ids
        assert "CVE-2026-44115" in ids
        assert "CVE-2026-44118" in ids
        assert len(cves) == 4

    def test_patched_version_is_clean(self):
        findings = _run(_profile("openclaw", "OpenClaw"), version="2026.4.22")
        assert not [f for f in findings if f.title.startswith("CVE-")]
        assert any(f.title.startswith("GHSA-") for f in findings)

    def test_severity_split(self):
        findings = _run(_profile("openclaw", "OpenClaw"), version="2026.4.0")
        by_id = {f.title.split(":")[0]: f for f in findings if f.title.startswith("CVE-")}
        assert by_id["CVE-2026-44112"].severity.name == "CRITICAL"
        assert by_id["CVE-2026-44118"].severity.name == "WARNING"


class TestHermesCVEs:
    def test_old_hermes_flags_both(self):
        findings = _run(_profile("hermes", "Hermes"), version="2026.4.16")
        ids = " ".join(t for t in _titles(findings) if t.startswith("CVE-"))
        assert "CVE-2026-9368" in ids
        assert "CVE-2026-10548" in ids

    def test_boundary_only_credential_cve(self):
        # 2026.4.20 is past the 9368 fix (2026.4.17) but before 10548 fix (2026.4.24)
        findings = _run(_profile("hermes", "Hermes"), version="2026.4.20")
        ids = " ".join(t for t in _titles(findings) if t.startswith("CVE-"))
        assert "CVE-2026-9368" not in ids
        assert "CVE-2026-10548" in ids

    def test_composite_semver_and_date_release_uses_date(self):
        findings = _run(_profile("hermes", "Hermes"), version="0.18.2 (2026.7.7.2)")
        assert not [f for f in findings if f.title.startswith("CVE-")]
        assert any("no known version CVEs" in f.title for f in findings)


class TestEdgeCases:
    def test_no_version_detected(self):
        findings = _run(_profile("openclaw", "OpenClaw"), version=None)
        assert any("could not be determined" in f.title for f in findings)

    def test_non_date_scheme_skipped(self):
        findings = _run(_profile("hermes", "Hermes"), version="0.9.0")
        assert any("no comparable advisories" in f.title for f in findings)
        assert not [f for f in findings if f.title.startswith("CVE-")]

    def test_unknown_profile_has_no_cves(self):
        findings = _run(_profile("claude-code", "Claude Code"), version="1.0.0")
        assert any("No version CVEs tracked" in f.title for f in findings)
