"""Tests for Sprint 7: Self-Learning Cycle (models, db triage, learner, alerting)."""

import tempfile
from pathlib import Path

from ai_agent_audit.db import FindingsDB
from ai_agent_audit.learner import PrecisionTracker
from ai_agent_audit.models import Finding, Severity


def _make_db() -> FindingsDB:
    tmp = Path(tempfile.mkdtemp()) / "test.db"
    return FindingsDB(db_path=tmp)


# --- Finding model tests ---


def test_finding_default_confidence():
    f = Finding(module="test", severity=Severity.CRITICAL, title="T", detail="D")
    assert f.confidence == 0.5


def test_finding_custom_confidence():
    f = Finding(module="test", severity=Severity.CRITICAL, title="T", detail="D", confidence=0.9)
    assert f.confidence == 0.9


def test_finding_triage_defaults_none():
    f = Finding(module="test", severity=Severity.CRITICAL, title="T", detail="D")
    assert f.triage_status is None
    assert f.mitre_attack is None
    assert f.owasp_asi is None
    assert f.remediation is None


def test_finding_framework_fields():
    f = Finding(
        module="test", severity=Severity.CRITICAL, title="T", detail="D",
        mitre_attack="T1059.004", owasp_asi="ASI05", remediation="Disable shell access",
    )
    assert f.mitre_attack == "T1059.004"
    assert f.owasp_asi == "ASI05"
    assert f.remediation == "Disable shell access"


# --- DB schema migration tests ---


def test_db_stores_confidence():
    db = _make_db()
    f = Finding(module="test", severity=Severity.CRITICAL, title="T", detail="D", confidence=0.87)
    db.insert(f)

    active = db.get_active_findings()
    assert len(active) == 1
    assert abs(active[0]["confidence"] - 0.87) < 0.001
    db.close()


def test_db_stores_mitre_and_owasp():
    db = _make_db()
    f = Finding(
        module="test", severity=Severity.WARNING, title="T", detail="D",
        mitre_attack="T1059", owasp_asi="ASI05",
    )
    db.insert(f)

    active = db.get_active_findings()
    assert active[0]["mitre_attack"] == "T1059"
    assert active[0]["owasp_asi"] == "ASI05"
    db.close()


def test_db_updates_confidence_on_dedup():
    db = _make_db()
    f1 = Finding(module="test", severity=Severity.INFO, title="Dup", detail="v1", confidence=0.5)
    f2 = Finding(module="test", severity=Severity.INFO, title="Dup", detail="v2", confidence=0.8)

    db.insert(f1)
    db.insert(f2)

    active = db.get_active_findings()
    assert len(active) == 1
    assert abs(active[0]["confidence"] - 0.8) < 0.001
    db.close()


# --- Triage tests ---


def test_triage_confirm():
    db = _make_db()
    f = Finding(module="test", severity=Severity.CRITICAL, title="T", detail="D")
    db.insert(f)

    findings = db.get_triageable()
    fid = findings[0]["id"]

    assert db.triage(fid, "confirmed")

    triaged = db.get_triageable()
    assert triaged[0]["triage_status"] == "confirmed"
    db.close()


def test_triage_false_positive():
    db = _make_db()
    f = Finding(module="test", severity=Severity.WARNING, title="FP", detail="D")
    db.insert(f)

    findings = db.get_triageable()
    fid = findings[0]["id"]

    assert db.triage(fid, "false_positive")

    triaged = db.get_triageable()
    assert triaged[0]["triage_status"] == "false_positive"
    db.close()


def test_triage_invalid_status_raises():
    db = _make_db()
    f = Finding(module="test", severity=Severity.INFO, title="T", detail="D")
    db.insert(f)

    findings = db.get_triageable()
    fid = findings[0]["id"]

    try:
        db.triage(fid, "invalid")
        assert False, "Should have raised ValueError"
    except ValueError:
        pass
    db.close()


def test_triage_nonexistent_returns_false():
    db = _make_db()
    assert not db.triage(99999, "confirmed")
    db.close()


# --- Precision stats tests ---


def test_precision_stats_empty():
    db = _make_db()
    stats = db.get_precision_stats()
    assert stats == {}
    db.close()


def test_precision_stats_with_triage_data():
    db = _make_db()

    # Insert 3 findings with same rule, triage them differently
    for i in range(3):
        f = Finding(module="scanner", severity=Severity.WARNING, title="Suspicious file", detail=f"d{i}", path=f"/p{i}")
        db.insert(f)

    findings = db.get_triageable()
    # Confirm 2, mark 1 as FP
    db.triage(findings[0]["id"], "confirmed")
    db.triage(findings[1]["id"], "confirmed")
    db.triage(findings[2]["id"], "false_positive")

    stats = db.get_precision_stats()
    key = "scanner:Suspicious file"
    assert key in stats
    assert stats[key]["confirmed"] == 2
    assert stats[key]["false_positive"] == 1
    db.close()


# --- PrecisionTracker calibration tests ---


def test_calibrate_no_data_returns_original():
    tracker = PrecisionTracker()
    f = Finding(module="test", severity=Severity.CRITICAL, title="Unknown rule", detail="D", confidence=0.7)
    assert tracker.calibrate(f) == 0.7


def test_calibrate_high_precision_boosts():
    db = _make_db()

    # Create findings and triage all as confirmed
    for i in range(5):
        f = Finding(module="scanner", severity=Severity.WARNING, title="Real threat", detail=f"d{i}", path=f"/p{i}")
        db.insert(f)
    findings = db.get_triageable()
    for f in findings:
        db.triage(f["id"], "confirmed")

    tracker = PrecisionTracker(db=db)
    tracker.refresh()

    test_finding = Finding(module="scanner", severity=Severity.WARNING, title="Real threat", detail="new", confidence=0.8)
    calibrated = tracker.calibrate(test_finding)

    # Precision = 1.0, multiplier = 0.2 + 0.8*1.0 = 1.0, so confidence stays at 0.8
    assert abs(calibrated - 0.8) < 0.01
    db.close()


def test_calibrate_low_precision_suppresses():
    db = _make_db()

    # Create findings and triage all as false positives
    for i in range(5):
        f = Finding(module="scanner", severity=Severity.WARNING, title="Noisy rule", detail=f"d{i}", path=f"/p{i}")
        db.insert(f)
    findings = db.get_triageable()
    for f in findings:
        db.triage(f["id"], "false_positive")

    tracker = PrecisionTracker(db=db)
    tracker.refresh()

    test_finding = Finding(module="scanner", severity=Severity.WARNING, title="Noisy rule", detail="new", confidence=0.8)
    calibrated = tracker.calibrate(test_finding)

    # Precision = 0.0, multiplier = 0.2 + 0.8*0.0 = 0.2, confidence = 0.8*0.2 = 0.16
    assert abs(calibrated - 0.16) < 0.01
    db.close()


def test_calibrate_below_min_samples_unchanged():
    db = _make_db()

    # Only 2 triages (below MIN_SAMPLES=3)
    for i in range(2):
        f = Finding(module="scanner", severity=Severity.WARNING, title="FewData", detail=f"d{i}", path=f"/p{i}")
        db.insert(f)
    findings = db.get_triageable()
    for f in findings:
        db.triage(f["id"], "false_positive")

    tracker = PrecisionTracker(db=db)
    tracker.refresh()

    test_finding = Finding(module="scanner", severity=Severity.WARNING, title="FewData", detail="new", confidence=0.7)
    # Not enough data — should return original
    assert tracker.calibrate(test_finding) == 0.7
    db.close()


def test_calibrate_mixed_precision():
    db = _make_db()

    # 3 confirmed, 1 FP = 75% precision
    for i in range(4):
        f = Finding(module="scanner", severity=Severity.WARNING, title="Mixed", detail=f"d{i}", path=f"/p{i}")
        db.insert(f)
    findings = db.get_triageable()
    for f in findings[:3]:
        db.triage(f["id"], "confirmed")
    db.triage(findings[3]["id"], "false_positive")

    tracker = PrecisionTracker(db=db)
    tracker.refresh()

    test_finding = Finding(module="scanner", severity=Severity.WARNING, title="Mixed", detail="new", confidence=0.8)
    calibrated = tracker.calibrate(test_finding)

    # Precision = 0.75, multiplier = 0.2 + 0.8*0.75 = 0.8, confidence = 0.8*0.8 = 0.64
    assert abs(calibrated - 0.64) < 0.01
    db.close()
