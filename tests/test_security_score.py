"""Tests for security_score grading and scoring logic."""

from ai_agent_audit.sweeps.security_score import _grade, _get_nested


def test_grade_a():
    assert _grade(140) == "A"
    assert _grade(125) == "A"


def test_grade_b():
    assert _grade(124) == "B"
    assert _grade(105) == "B"


def test_grade_c():
    assert _grade(104) == "C"
    assert _grade(85) == "C"


def test_grade_d():
    assert _grade(84) == "D"
    assert _grade(65) == "D"


def test_grade_f():
    assert _grade(64) == "F"
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
    from ai_agent_audit.sweeps.security_score import SecurityScoreSweep
    sweep = SecurityScoreSweep()
    result = sweep.run()
    assert result.module_name == "security_score"
    assert len(result.findings) == 1  # always produces a score finding

    # Score should be in the title
    finding = result.findings[0]
    assert "Security Score:" in finding.title
    assert "Grade:" in finding.title
    assert "/140" in finding.title


def test_sweep_score_range():
    """Score should be between 0 and 135."""
    from ai_agent_audit.sweeps.security_score import SecurityScoreSweep
    sweep = SecurityScoreSweep()
    result = sweep.run()
    finding = result.findings[0]

    # Parse score from title "Security Score: X/140 (Grade: Y)"
    import re
    m = re.search(r"(\d+)/140", finding.title)
    assert m is not None
    score = int(m.group(1))
    assert 0 <= score <= 140


def test_sweep_detail_has_all_checks():
    """Detail should list all 17 checks."""
    from ai_agent_audit.sweeps.security_score import SecurityScoreSweep
    sweep = SecurityScoreSweep()
    result = sweep.run()
    detail = result.findings[0].detail

    # Should contain PASS or FAIL for each check
    pass_count = detail.count("[PASS]")
    fail_count = detail.count("[FAIL]")
    assert pass_count + fail_count == 18
