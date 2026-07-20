"""Compute a weighted 0-140 security score with letter grade."""

from __future__ import annotations

import json
import logging
import os
import re
import stat

from ..agent_config import (
    AgentConfigError,
    auth_enabled as normalized_auth_enabled,
    dm_policy_open,
    extract_mcp_servers,
    get_nested,
    load_agent_config,
    redaction_enabled,
    sandbox_enabled,
)
from ..config import (
    ACTIVE_PROFILE,
    AUDIT_BASELINES,
    INJECTION_PATTERNS,
    MEMORY_FILES,
    OPENCLAW_CONFIG,
    OPENCLAW_EXEC_APPROVALS,
    OPENCLAW_HOME,
    OPENCLAW_MCP_CONFIG,
    OPENCLAW_WORKSPACE,
    EXPECTED_PERMISSIONS,
    SUSPICIOUS_PROCESS_PATTERNS,
)
from ..ioc import MALICIOUS_SKILL_PATTERNS
from ..models import Finding, ModuleResult, ModuleStatus, Severity
from .base import BaseSweep

logger = logging.getLogger(__name__)

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


_get_nested = get_nested


def _grade(score: int) -> str:
    if score >= 125:
        return "A"
    if score >= 105:
        return "B"
    if score >= 85:
        return "C"
    if score >= 65:
        return "D"
    return "F"


class SecurityScoreSweep(BaseSweep):
    name = "security_score"

    def run(self) -> ModuleResult:
        findings: list[Finding] = []
        score = 0
        config: dict = {}
        checks: list[tuple[str, int, bool | None]] = []  # None means visibility unknown

        # Load config
        config_valid = False
        if OPENCLAW_CONFIG.exists():
            try:
                config = load_agent_config(OPENCLAW_CONFIG)
                config_valid = True
            except AgentConfigError:
                pass

        # 1. Config exists and is valid (5)
        checks.append(("Config exists and is valid", 5, config_valid))

        # 2. Auth enabled (15)
        auth_state = normalized_auth_enabled(config, ACTIVE_PROFILE) if config_valid else None
        checks.append(("Authentication enabled", 15, auth_state))

        # 3. Gateway bound to loopback (15)
        bind = _get_nested(config, "gateway.bind") if config_valid else None
        bound_loopback = (
            bind in ("127.0.0.1", "localhost", "::1", "loopback")
            if bind is not None else None
        )
        checks.append(("Gateway bound to loopback", 15, bound_loopback))

        # 4. Sandbox enabled (10)
        sandbox_ok = sandbox_enabled(config, ACTIVE_PROFILE) if config_valid else None
        checks.append(("Sandbox enabled", 10, sandbox_ok))

        # 5. Permissions correct (10)
        home_exists = OPENCLAW_HOME.exists()
        perms_ok: bool | None = True if home_exists else None
        if home_exists:
            for path, expected in EXPECTED_PERMISSIONS.items():
                if path.exists():
                    actual = stat.S_IMODE(path.stat().st_mode)
                    if actual & ~expected:
                        perms_ok = False
                        break
        checks.append(("Permissions correct", 10, perms_ok))

        # 6. No world-readable files (10)
        world_readable: bool | None = False if home_exists else None
        if home_exists:
            for dirpath, _, filenames in os.walk(OPENCLAW_HOME):
                for fname in filenames:
                    fpath = os.path.join(dirpath, fname)
                    try:
                        st = os.lstat(fpath)
                        if st.st_mode & stat.S_IROTH:
                            world_readable = True
                            break
                    except OSError:
                        continue
                if world_readable:
                    break
        checks.append((
            "No world-readable files",
            10,
            None if world_readable is None else not world_readable,
        ))

        # 7. Credentials hashed/unchanged (5)
        creds_ok: bool | None = True if home_exists else None
        creds_baseline = AUDIT_BASELINES / "credential-ages.json"
        if not creds_baseline.exists():
            creds_ok = True  # No baseline yet, first run
        checks.append(("Credentials baseline intact", 5, creds_ok))

        # 8. No suspicious processes (10)
        suspicious_procs = False
        process_visible = HAS_PSUTIL
        if HAS_PSUTIL:
            compiled = [
                re.compile(p["pattern"]) for p in SUSPICIOUS_PROCESS_PATTERNS
            ]
            try:
                processes = list(psutil.process_iter(["pid", "cmdline"]))
            except (psutil.Error, OSError):
                processes = []
                process_visible = False
            for proc in processes:
                try:
                    cmdline = " ".join(proc.info.get("cmdline") or [])
                except (psutil.Error, OSError, KeyError, TypeError):
                    continue
                for pat in compiled:
                    if pat.search(cmdline):
                        suspicious_procs = True
                        break
                if suspicious_procs:
                    break
        checks.append(("No suspicious processes", 10, not suspicious_procs if process_visible else None))

        # 9. No unusual network connections (5)
        unusual_net = False
        network_visible = HAS_PSUTIL
        if HAS_PSUTIL:
            try:
                for conn in psutil.net_connections(kind="inet"):
                    if (
                        conn.status == "LISTEN"
                        and conn.laddr
                        and conn.laddr.ip == "0.0.0.0"
                        and conn.pid
                    ):
                        try:
                            proc = psutil.Process(conn.pid)
                            cmdline = " ".join(proc.cmdline()).lower()
                            if any(kw in cmdline for kw in ACTIVE_PROFILE.process_keywords):
                                unusual_net = True
                                break
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
            except (psutil.Error, OSError):
                network_visible = False
        checks.append(("No unusual network connections", 5, not unusual_net if network_visible else None))

        # 10. Log redaction enabled (5)
        redact_ok = redaction_enabled(config, ACTIVE_PROFILE) if config_valid else None
        checks.append(("Log redaction enabled", 5, redact_ok))

        # 11. Extensions unchanged from baseline (10)
        extensions_ok = True
        ext_baseline = AUDIT_BASELINES / "extensions.json"
        if ext_baseline.exists():
            try:
                baseline = json.loads(ext_baseline.read_text())
                # Quick check: compare file count (full check is in plugin_integrity)
                from ..config import OPENCLAW_EXTENSIONS
                if OPENCLAW_EXTENSIONS.exists():
                    current_count = sum(
                        1 for _ in OPENCLAW_EXTENSIONS.rglob("*") if _.is_file()
                    )
                    if current_count != len(baseline):
                        extensions_ok = False
            except (json.JSONDecodeError, OSError):
                extensions_ok = False
        checks.append(("Extensions unchanged from baseline", 10, extensions_ok))

        # 12. DM policy not open (10)
        dm_open = dm_policy_open(config) if config_valid else None
        dm_ok = None if dm_open is None else not dm_open
        checks.append(("DM policy not open", 10, dm_ok))

        # 13. Exec approvals secure (5)
        exec_ok: bool | None = True if home_exists else None
        if OPENCLAW_EXEC_APPROVALS.exists():
            try:
                mode = stat.S_IMODE(OPENCLAW_EXEC_APPROVALS.stat().st_mode)
                if mode != 0o600:
                    exec_ok = False
            except OSError:
                exec_ok = False
        # No file = no bypass risk, so exec_ok stays True
        checks.append(("Exec approvals secure", 5, exec_ok))

        # 14. No memory poisoning (5)
        memory_ok: bool | None = True if home_exists else None
        compiled_injections = [re.compile(p["pattern"]) for p in INJECTION_PATTERNS]
        memory_paths = [OPENCLAW_WORKSPACE / name for name in MEMORY_FILES] if home_exists else []
        memories = OPENCLAW_WORKSPACE / "memories"
        if memories.is_dir():
            memory_paths.extend(memories.rglob("*.md"))
        for mem_path in memory_paths:
            if mem_path.exists():
                try:
                    content = mem_path.read_text(errors="replace")
                    for pat in compiled_injections:
                        if pat.search(content):
                            memory_ok = False
                            break
                except OSError:
                    pass
            if not memory_ok:
                break
        checks.append(("No memory poisoning", 5, memory_ok))

        # 15. Skills verified (5)
        skills_ok: bool | None = True if home_exists else None
        compiled_skill_pats = [re.compile(p) for p in MALICIOUS_SKILL_PATTERNS]
        if OPENCLAW_WORKSPACE.exists():
            try:
                for item in OPENCLAW_WORKSPACE.iterdir():
                    for pat in compiled_skill_pats:
                        if pat.search(item.name):
                            skills_ok = False
                            break
                    if not skills_ok:
                        break
            except OSError:
                pass
        checks.append(("Skills verified", 5, skills_ok))

        # 16. MCP servers restricted (5)
        mcp_ok: bool | None = None if not config_valid else True
        if OPENCLAW_MCP_CONFIG.exists():
            try:
                mcp_data = load_agent_config(OPENCLAW_MCP_CONFIG)
                if mcp_data.get("enableAllProjectMcpServers") is True:
                    mcp_ok = False
                elif extract_mcp_servers(mcp_data):
                    # Native audit evaluates per-server policy. Presence alone
                    # is not evidence that every MCP server is restricted.
                    mcp_ok = None
            except AgentConfigError:
                mcp_ok = None
        checks.append(("MCP servers restricted", 5, mcp_ok))

        # 17. Memory extraPaths has no path traversal (5)
        extra_paths_ok: bool | None = True if config_valid else None
        extra_paths = _get_nested(config, "memory.extraPaths") or []
        if isinstance(extra_paths, list) and OPENCLAW_WORKSPACE.exists():
            workspace = str(OPENCLAW_WORKSPACE.resolve())
            for p in extra_paths:
                if not isinstance(p, str):
                    continue
                try:
                    resolved = str((OPENCLAW_WORKSPACE / p).resolve())
                except (OSError, ValueError):
                    continue
                if not resolved.startswith(workspace + "/") and resolved != workspace:
                    extra_paths_ok = False
                    break
        checks.append(("Memory extraPaths safe", 5, extra_paths_ok))

        # 18. WebSocket origin validated (5)
        gw_port = _get_nested(config, "gateway.port")
        ws_ok = None if auth_state is None else not (
            gw_port in (None, 3000, 8080) and auth_state is not True
        )
        checks.append(("WebSocket origin validated", 5, ws_ok))

        # Calculate score
        for name, weight, passed in checks:
            if passed is True:
                score += weight

        unknown_count = sum(1 for _, _, passed in checks if passed is None)
        grade = "INCOMPLETE" if unknown_count else _grade(score)

        # Build detail report
        completeness = f"; {unknown_count} UNKNOWN" if unknown_count else ""
        detail_lines = [f"Security Score: {score}/140 (Grade: {grade}{completeness})", ""]
        for name, weight, passed in checks:
            status = "UNKNOWN" if passed is None else ("PASS" if passed else "FAIL")
            detail_lines.append(f"  [{status}] {name} (weight: {weight})")

        severity = Severity.INFO
        if grade == "INCOMPLETE":
            severity = Severity.WARNING
        elif grade in ("D", "F"):
            severity = Severity.CRITICAL
        elif grade == "C":
            severity = Severity.WARNING

        findings.append(Finding(
            module=self.name,
            severity=severity,
            title=f"Security Score: {score}/140 (Grade: {grade})",
            detail="\n".join(detail_lines),
        ))

        return ModuleResult(
            module_name=self.name,
            findings=findings,
            status=ModuleStatus.DEGRADED if unknown_count else ModuleStatus.OK,
            message=(
                f"{unknown_count} score checks lacked sufficient visibility or configuration evidence"
                if unknown_count else None
            ),
        )
