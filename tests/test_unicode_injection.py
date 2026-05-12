"""Tests for hidden Unicode/zero-width character injection sweep."""

import tempfile
from pathlib import Path
from unittest.mock import patch

from ai_agent_audit.sweeps.unicode_injection import UnicodeInjectionSweep


def _run_with_file(filename, content):
    """Write a file to a temp dir simulating OPENCLAW_HOME and run the sweep."""
    tmp = Path(tempfile.mkdtemp())
    file_path = tmp / filename
    file_path.write_text(content)

    sweep = UnicodeInjectionSweep()
    with patch("ai_agent_audit.sweeps.unicode_injection.OPENCLAW_HOME", tmp), \
         patch("ai_agent_audit.sweeps.unicode_injection.OPENCLAW_WORKSPACE", tmp / "workspace"), \
         patch("ai_agent_audit.sweeps.unicode_injection.OPENCLAW_SKILLS", tmp / "skills"), \
         patch("ai_agent_audit.sweeps.unicode_injection.OPENCLAW_MCP_CONFIG", tmp / "mcp.json"):
        result = sweep.run()
    return result.findings


class TestUnicodeInjection:
    def test_clean_file_no_findings(self):
        findings = _run_with_file("CLAUDE.md", "This is a clean file with no hidden chars.\n")
        critical = [f for f in findings if f.severity.name == "CRITICAL"]
        assert len(critical) == 0

    def test_zero_width_space_detected(self):
        # Embed zero-width space
        content = "Normal text\u200bwith hidden zero-width space"
        findings = _run_with_file("CLAUDE.md", content)
        critical = [f for f in findings if f.severity.name == "CRITICAL"]
        assert len(critical) >= 1
        assert any("Zero-Width Space" in f.title for f in critical)

    def test_zero_width_joiner_detected(self):
        content = "text\u200dwith ZWJ"
        findings = _run_with_file("CLAUDE.md", content)
        critical = [f for f in findings if f.severity.name == "CRITICAL"]
        assert any("Zero-Width Joiner" in f.title for f in critical)

    def test_bom_detected(self):
        content = "\ufeffHidden BOM at start"
        findings = _run_with_file("AGENTS.md", content)
        critical = [f for f in findings if f.severity.name == "CRITICAL"]
        assert any("No-Break Space" in f.title or "BOM" in f.title for f in critical)

    def test_bidi_override_detected(self):
        content = "Text with \u202e reverse override"
        findings = _run_with_file("CLAUDE.md", content)
        critical = [f for f in findings if f.severity.name == "CRITICAL"]
        assert any("Bidi override" in f.title or "Right-To-Left Override" in f.title for f in critical)

    def test_rtl_mark_detected(self):
        content = "Text with \u200f RTL mark"
        findings = _run_with_file("CLAUDE.md", content)
        critical = [f for f in findings if f.severity.name == "CRITICAL"]
        assert any("Right-To-Left Mark" in f.title for f in critical)

    def test_homoglyph_cyrillic_a(self):
        # Cyrillic 'a' mixed with Latin
        content = "This text has a Cyrillic \u0430 in it"
        findings = _run_with_file("CLAUDE.md", content)
        warnings = [f for f in findings if f.severity.name == "WARNING"]
        assert any("Homoglyph" in f.title for f in warnings)

    def test_multiple_invisible_chars(self):
        content = "text\u200b\u200c\u200dthree hidden chars"
        findings = _run_with_file("CLAUDE.md", content)
        critical = [f for f in findings if f.severity.name == "CRITICAL"]
        assert len(critical) >= 3  # One per char type

    def test_soft_hyphen_detected(self):
        content = "exec\u00adute hidden command"
        findings = _run_with_file("CLAUDE.md", content)
        critical = [f for f in findings if f.severity.name == "CRITICAL"]
        assert any("Soft Hyphen" in f.title for f in critical)

    def test_openclaw_json_scanned(self):
        content = '{"gateway": {"bind": "0.0.0.0\u200b"}}'
        findings = _run_with_file("openclaw.json", content)
        critical = [f for f in findings if f.severity.name == "CRITICAL"]
        assert len(critical) >= 1
