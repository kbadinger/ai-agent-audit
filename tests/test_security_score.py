"""Tests for security_score grading and scoring logic."""

from openclaw_audit.sweeps.security_score import _grade, _get_nested


def test_grade_a():
    assert _grade(135) == "A"
    assert _grade(120) == "A"


def test_grade_b():
    assert _grade(119) == "B"
    assert _grade(100) == "B"


def test_grade_c():
    assert _grade(99) == "C"
    assert _grade(80) == "C"


def test_grade_d():
    assert _grade(79) == "D"
    assert _grade(60) == "D"


def test_grade_f():
    assert _grade(59) == "F"
    assert _grade(0) == "F"


def test_get_nested_simple():
    data = {"a": {"b": {"c": 42}}}
    assert _get_nested(data, "a.b.c") == 42


def test_get_nested_missing():
    data = {"a": {"b": 1}}
    assert _get_nested(data, "a.b.c") is None
    assert _get_nested(data, "x.y") is None


def test_get_nested_top_level():
    data = {"key": "value"}
    assert _get_nested(data, "key") == "value"


def test_get_nested_non_dict():
    data = {"a": "string"}
    assert _get_nested(data, "a.b") is None


def test_sweep_runs_without_openclaw():
    """SecurityScoreSweep should run without crashing even if ~/.openclaw doesn't exist."""
    from openclaw_audit.sweeps.security_score import SecurityScoreSweep
    sweep = SecurityScoreSweep()
    result = sweep.run()
    assert result.module_name == "security_score"
    assert len(result.findings) == 1  # always produces a score finding

    # Score should be in the title
    finding = result.findings[0]
    assert "Security Score:" in finding.title
    assert "Grade:" in finding.title
    assert "/135" in finding.title


def test_sweep_score_range():
    """Score should be between 0 and 135."""
    from openclaw_audit.sweeps.security_score import SecurityScoreSweep
    sweep = SecurityScoreSweep()
    result = sweep.run()
    finding = result.findings[0]

    # Parse score from title "Security Score: X/135 (Grade: Y)"
    import re
    m = re.search(r"(\d+)/135", finding.title)
    assert m is not None
    score = int(m.group(1))
    assert 0 <= score <= 135


def test_sweep_detail_has_all_checks():
    """Detail should list all 17 checks."""
    from openclaw_audit.sweeps.security_score import SecurityScoreSweep
    sweep = SecurityScoreSweep()
    result = sweep.run()
    detail = result.findings[0].detail

    # Should contain PASS or FAIL for each check
    pass_count = detail.count("[PASS]")
    fail_count = detail.count("[FAIL]")
    assert pass_count + fail_count == 17
