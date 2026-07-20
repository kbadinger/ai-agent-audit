import json
from types import SimpleNamespace
from unittest.mock import patch

from ai_agent_audit.models import ModuleStatus, Severity
from ai_agent_audit.sweeps.native_security_audit import NativeSecurityAuditSweep


def test_native_audit_normalizes_only_failed_checks():
    profile = SimpleNamespace(
        display_name="OpenClaw",
        native_audit_command=("openclaw", "security", "audit", "--json"),
    )
    payload = {
        "checks": [
            {"checkId": "gateway.auth", "status": "fail", "severity": "high", "title": "Auth disabled", "message": "unsafe"},
            {"checkId": "permissions", "status": "pass", "severity": "info", "title": "Permissions"},
        ]
    }
    completed = SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")
    with patch("ai_agent_audit.sweeps.native_security_audit.ACTIVE_PROFILE", profile), \
            patch("ai_agent_audit.sweeps.native_security_audit.subprocess.run", return_value=completed):
        result = NativeSecurityAuditSweep().run()

    assert result.status == ModuleStatus.OK
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.CRITICAL
    assert result.findings[0].title.startswith("gateway.auth")


def test_missing_native_executable_is_skipped():
    profile = SimpleNamespace(display_name="Hermes", native_audit_command=("hermes", "audit", "--json"))
    with patch("ai_agent_audit.sweeps.native_security_audit.ACTIVE_PROFILE", profile), \
            patch("ai_agent_audit.sweeps.native_security_audit.subprocess.run", side_effect=FileNotFoundError):
        result = NativeSecurityAuditSweep().run()
    assert result.status == ModuleStatus.SKIPPED
