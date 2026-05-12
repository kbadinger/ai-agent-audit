"""Tests for Sprint 7b: Finding enrichment mappings and IOC aging integration."""

from ai_agent_audit.mappings import enrich
from ai_agent_audit.models import Finding, Severity
from ai_agent_audit import ioc


# --- enrich() tests ---


def test_enrich_c2_ip_finding():
    f = Finding(module="network_monitor", severity=Severity.CRITICAL,
                title="Known C2 IP: 91.92.242.30", detail="test")
    enrich(f)
    assert f.confidence == 0.95
    assert f.mitre_attack == "T1071.001"
    assert f.owasp_asi == "ASI10"
    assert f.remediation is not None
    assert "Block" in f.remediation


def test_enrich_prompt_injection():
    f = Finding(module="session_analyzer", severity=Severity.CRITICAL,
                title="Prompt injection: Ignore instructions", detail="test")
    enrich(f)
    assert f.confidence == 0.80
    assert f.mitre_attack == "T1059"
    assert f.owasp_asi == "ASI01"


def test_enrich_malicious_skill():
    f = Finding(module="skill_scanner", severity=Severity.CRITICAL,
                title="Malicious skill name pattern: clawhub", detail="test")
    enrich(f)
    assert f.confidence == 0.85
    assert f.mitre_attack == "T1195.002"
    assert f.owasp_asi == "ASI04"


def test_enrich_websocket_insecure():
    f = Finding(module="websocket_security", severity=Severity.CRITICAL,
                title="Insecure auth allows WebSocket full compromise", detail="test")
    enrich(f)
    assert f.confidence == 0.95
    assert f.mitre_attack == "T1190"


def test_enrich_unknown_finding_keeps_defaults():
    f = Finding(module="unknown_module", severity=Severity.INFO,
                title="Something new", detail="test")
    enrich(f)
    assert f.confidence == 0.5  # unchanged default
    assert f.mitre_attack is None
    assert f.owasp_asi is None
    assert f.remediation is None


def test_enrich_correlation_active_breach():
    f = Finding(module="correlation", severity=Severity.CRITICAL,
                title="Active breach detected", detail="test")
    enrich(f)
    assert f.confidence == 0.95
    assert f.mitre_attack == "T1071.001"
    assert f.owasp_asi == "ASI10"


def test_enrich_config_gateway_bound():
    f = Finding(module="config_watcher", severity=Severity.CRITICAL,
                title="Gateway bound to non-loopback address", detail="test")
    enrich(f)
    assert f.confidence == 0.95
    assert f.mitre_attack == "T1190"


def test_enrich_memory_poisoning():
    f = Finding(module="memory_poisoning_monitor", severity=Severity.CRITICAL,
                title="Injection pattern in SOUL.md: Fake system prompt", detail="test")
    enrich(f)
    assert f.confidence == 0.85
    assert f.mitre_attack == "T1565.001"
    assert f.owasp_asi == "ASI06"


def test_enrich_cve_check():
    f = Finding(module="node_cve_check", severity=Severity.CRITICAL,
                title="CVE-2026-21636: Node.js permission bypass", detail="test")
    enrich(f)
    assert f.confidence == 0.95
    assert f.mitre_attack == "T1203"
    assert f.owasp_asi == "ASI05"


def test_enrich_stale_credential():
    f = Finding(module="credential_rotation", severity=Severity.CRITICAL,
                title="Stale credential: /path/to/key (200 days old)", detail="test")
    enrich(f)
    assert f.confidence == 0.75
    assert f.owasp_asi == "ASI03"


def test_enrich_docker_socket():
    f = Finding(module="docker_security", severity=Severity.CRITICAL,
                title="Docker socket mounted in 'openclaw-1'", detail="test")
    enrich(f)
    assert f.confidence == 0.90
    assert f.mitre_attack == "T1611"


# --- IOC aging tests ---


def test_ioc_record_and_confidence():
    # Fresh IOC — no match history
    assert ioc.ioc_confidence("1.2.3.4") == 1.0

    # Record a match
    ioc.record_ioc_match("1.2.3.4")
    assert ioc.ioc_confidence("1.2.3.4") == 1.0  # just matched, still fresh


def test_ioc_stale_confidence():
    import time
    # Simulate old match by directly setting the dict
    ioc._ioc_matches["old.example.com"] = time.time() - (91 * 86400)
    assert ioc.ioc_confidence("old.example.com") == 0.3


def test_ioc_very_stale_confidence():
    import time
    ioc._ioc_matches["ancient.example.com"] = time.time() - (181 * 86400)
    assert ioc.ioc_confidence("ancient.example.com") == 0.1


# --- Prefix matching edge cases ---


def test_enrich_partial_title_match():
    """Channel findings in dm_policy_audit use prefix 'Channel' for various titles."""
    f = Finding(module="dm_policy_audit", severity=Severity.CRITICAL,
                title="Channel 'general' has open DM policy", detail="test")
    enrich(f)
    assert f.owasp_asi == "ASI09"


def test_enrich_container_finding():
    """Docker container findings vary by container name."""
    f = Finding(module="docker_security", severity=Severity.CRITICAL,
                title="Container 'myapp' runs as root", detail="test")
    enrich(f)
    assert f.confidence == 0.75
    assert f.mitre_attack == "T1610"
