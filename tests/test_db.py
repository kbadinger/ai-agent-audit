"""Tests for the FindingsDB module."""

import tempfile
import time
from pathlib import Path

from openclaw_audit.db import FindingsDB
from openclaw_audit.models import Finding, Severity


def _make_db() -> FindingsDB:
    """Create a temporary in-memory-like DB for testing."""
    tmp = Path(tempfile.mkdtemp()) / "test.db"
    return FindingsDB(db_path=tmp)


def test_insert_and_retrieve():
    db = _make_db()
    f = Finding(module="test", severity=Severity.CRITICAL, title="Bad thing", detail="details")
    db.insert(f)

    active = db.get_active_findings()
    assert len(active) == 1
    assert active[0]["title"] == "Bad thing"
    assert active[0]["severity"] == int(Severity.CRITICAL)
    assert active[0]["times_seen"] == 1
    db.close()


def test_deduplication():
    db = _make_db()
    f1 = Finding(module="test", severity=Severity.WARNING, title="Dup", detail="v1")
    f2 = Finding(module="test", severity=Severity.WARNING, title="Dup", detail="v2")

    db.insert(f1)
    db.insert(f2)

    active = db.get_active_findings()
    assert len(active) == 1
    assert active[0]["times_seen"] == 2
    assert active[0]["detail"] == "v2"  # updated to latest detail
    db.close()


def test_different_findings_not_deduped():
    db = _make_db()
    f1 = Finding(module="test", severity=Severity.INFO, title="A", detail="d1")
    f2 = Finding(module="test", severity=Severity.INFO, title="B", detail="d2")

    db.insert(f1)
    db.insert(f2)

    active = db.get_active_findings()
    assert len(active) == 2
    db.close()


def test_resolve_stale():
    db = _make_db()
    f1 = Finding(module="mod", severity=Severity.INFO, title="Keep", detail="d")
    f2 = Finding(module="mod", severity=Severity.INFO, title="Remove", detail="d")

    db.insert(f1)
    db.insert(f2)

    # Only f1's hash is current
    db.resolve_stale("mod", {f1.dedup_hash})

    active = db.get_active_findings()
    assert len(active) == 1
    assert active[0]["title"] == "Keep"
    db.close()


def test_get_findings_since():
    db = _make_db()
    old = Finding(module="test", severity=Severity.INFO, title="Old", detail="d", timestamp=1000.0)
    new = Finding(module="test", severity=Severity.INFO, title="New", detail="d", timestamp=time.time())

    db.insert(old)
    db.insert(new)

    recent = db.get_findings_since(time.time() - 60)
    assert len(recent) == 1
    assert recent[0]["title"] == "New"
    db.close()


def test_trend_data():
    db = _make_db()
    now = time.time()
    for i in range(3):
        db.insert(Finding(
            module="test",
            severity=Severity.CRITICAL,
            title=f"Issue {i}",
            detail="d",
            timestamp=now - i * 100,
        ))

    trend = db.get_trend_data(days=1)
    assert len(trend) >= 1
    # All should be same day (within seconds of each other)
    total = sum(t["count"] for t in trend)
    assert total == 3
    db.close()


def test_insert_many():
    db = _make_db()
    findings = [
        Finding(module="test", severity=Severity.INFO, title=f"F{i}", detail="d")
        for i in range(5)
    ]
    db.insert_many(findings)

    active = db.get_active_findings()
    assert len(active) == 5
    db.close()
