from types import SimpleNamespace
from unittest.mock import MagicMock

from ai_agent_audit.db import FindingsDB
from ai_agent_audit.engine import AuditEngine
from ai_agent_audit.models import Finding, ModuleResult, ModuleStatus, Severity
from ai_agent_audit.sweeps.base import BaseSweep


class _SequenceSweep(BaseSweep):
    name = "integration"

    def __init__(self, results):
        self.results = list(results)

    def run(self):
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def _engine(tmp_path, alerts):
    engine = AuditEngine(
        db=FindingsDB(tmp_path / "findings.db"),
        on_finding_callback=alerts.append,
    )
    engine.profiler = SimpleNamespace(refresh=lambda: None, is_relevant=lambda _: True)
    engine._maybe_refresh_iocs = MagicMock()
    engine._maybe_refresh_advisories = MagicMock()
    return engine


def test_full_sweep_stores_alerts_and_resolves_stale(tmp_path):
    alerts = []
    finding = Finding(
        module="integration",
        severity=Severity.CRITICAL,
        title="Detected",
        detail="evidence",
        confidence=1.0,
    )
    sweep = _SequenceSweep([
        ModuleResult(module_name="integration", findings=[finding]),
        ModuleResult(module_name="integration", findings=[]),
    ])
    engine = _engine(tmp_path, alerts)
    engine.register_sweep(sweep)

    first = engine.run_all_sweeps()
    assert first[0].status == ModuleStatus.OK
    assert len(engine.db.get_active_findings()) == 1
    assert [item.title for item in alerts] == ["Detected"]

    engine.run_all_sweeps()
    assert engine.db.get_active_findings() == []
    engine.db.close()


def test_degraded_scan_does_not_resolve_existing_findings(tmp_path):
    alerts = []
    finding = Finding("integration", Severity.WARNING, "Detected", "evidence")
    sweep = _SequenceSweep([
        ModuleResult(module_name="integration", findings=[finding]),
        ModuleResult(
            module_name="integration",
            status=ModuleStatus.DEGRADED,
            message="permission denied",
        ),
    ])
    engine = _engine(tmp_path, alerts)
    engine.register_sweep(sweep)
    engine.run_all_sweeps()
    engine.run_all_sweeps()
    assert len(engine.db.get_active_findings()) == 1
    engine.db.close()


def test_sweep_exception_is_returned_as_error(tmp_path):
    engine = _engine(tmp_path, [])
    engine.register_sweep(_SequenceSweep([PermissionError("denied")]))
    result = engine.run_all_sweeps()[0]
    assert result.status == ModuleStatus.ERROR
    assert "PermissionError" in result.message
    engine.db.close()
