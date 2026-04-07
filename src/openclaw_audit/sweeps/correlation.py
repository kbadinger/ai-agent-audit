"""Finding correlation engine: detects multi-indicator attack chains."""

from __future__ import annotations

import logging
import time
from collections import defaultdict

from ..db import FindingsDB
from ..models import Finding, ModuleResult, Severity
from .base import BaseSweep

logger = logging.getLogger(__name__)

# Time windows in seconds
_1_HOUR = 3600
_30_MIN = 1800
_15_MIN = 900
_24_HOURS = 86400


class CorrelationSweep(BaseSweep):
    name = "correlation"

    def __init__(self, db: FindingsDB | None = None):
        self._db = db

    def run(self) -> ModuleResult:
        findings: list[Finding] = []
        db = self._db or FindingsDB()
        owns_db = self._db is None
        try:
            self._correlate(db, findings)
        except Exception:
            logger.exception("Correlation sweep failed")
        finally:
            if owns_db:
                db.close()
        return ModuleResult(module_name=self.name, findings=findings)

    def _correlate(self, db: FindingsDB, findings: list[Finding]) -> None:
        now = time.time()
        # Grab the last 24 hours of findings for analysis
        recent = db.get_findings_since(now - _24_HOURS)

        # Filter out findings produced by correlation itself to avoid loops
        recent = [f for f in recent if f["module"] != "correlation"]

        if not recent:
            return

        # Index findings by module for pattern matching
        by_module: defaultdict[str, list[dict]] = defaultdict(list)
        for f in recent:
            by_module[f["module"]].append(f)

        self._check_active_breach(recent, by_module, findings, now)
        self._check_privilege_escalation(by_module, findings, now)
        self._check_supply_chain(by_module, findings, now)
        self._check_data_exfiltration(by_module, findings, now)
        self._check_coordinated_attack(recent, findings, now)
        self._check_escalating_threat(db, findings, now)
        self._check_cascading_failure(recent, by_module, findings, now)
        self._check_resource_exhaustion_chain(by_module, findings, now)

    # --- Pattern: Active Breach ---
    def _check_active_breach(
        self,
        recent: list[dict],
        by_module: defaultdict[str, list[dict]],
        findings: list[Finding],
        now: float,
    ) -> None:
        auth_failures = [
            f for f in by_module.get("log_forensics", [])
            if "auth" in f["title"].lower() and f["last_seen"] >= now - _1_HOUR
        ]
        suspicious_procs = [
            f for f in by_module.get("process_monitor", [])
            if f["last_seen"] >= now - _1_HOUR
        ]
        c2_connections = [
            f for f in (
                by_module.get("network_forensics", [])
                + by_module.get("network_monitor", [])
            )
            if any(kw in f["title"].lower() for kw in ("c2", "c&c", "command and control", "reverse", "suspicious"))
            and f["last_seen"] >= now - _1_HOUR
        ]

        if auth_failures and suspicious_procs and c2_connections:
            detail_parts = (
                [f"Auth failures: {_summarize(auth_failures)}"]
                + [f"Suspicious processes: {_summarize(suspicious_procs)}"]
                + [f"C2 connections: {_summarize(c2_connections)}"]
            )
            findings.append(Finding(
                module="correlation",
                severity=Severity.CRITICAL,
                title="Active breach detected",
                detail="Multiple indicators of an active breach within 1 hour.\n"
                       + "\n".join(detail_parts),
            ))

    # --- Pattern: Privilege Escalation ---
    def _check_privilege_escalation(
        self,
        by_module: defaultdict[str, list[dict]],
        findings: list[Finding],
        now: float,
    ) -> None:
        perm_changes = [
            f for f in (
                by_module.get("permission_audit", [])
                + by_module.get("permission_monitor", [])
            )
            if f["last_seen"] >= now - _1_HOUR
        ]
        cred_changes = [
            f for f in by_module.get("credential_guard", [])
            if f["last_seen"] >= now - _1_HOUR
        ]

        if perm_changes and cred_changes:
            findings.append(Finding(
                module="correlation",
                severity=Severity.CRITICAL,
                title="Privilege escalation pattern",
                detail="Permission loosening + credential changes within 1 hour.\n"
                       f"Permission changes: {_summarize(perm_changes)}\n"
                       f"Credential changes: {_summarize(cred_changes)}",
            ))

    # --- Pattern: Supply Chain Compromise ---
    def _check_supply_chain(
        self,
        by_module: defaultdict[str, list[dict]],
        findings: list[Finding],
        now: float,
    ) -> None:
        plugin_findings = [
            f for f in by_module.get("plugin_integrity", [])
            if f["last_seen"] >= now - _24_HOURS
            and f["severity"] >= int(Severity.WARNING)
        ]
        skill_findings = [
            f for f in by_module.get("skill_scanner", [])
            if f["last_seen"] >= now - _24_HOURS
            and f["severity"] >= int(Severity.WARNING)
        ]

        if plugin_findings and skill_findings:
            findings.append(Finding(
                module="correlation",
                severity=Severity.CRITICAL,
                title="Supply chain compromise pattern",
                detail="Extension changes + suspicious skills within 24 hours.\n"
                       f"Extension findings: {_summarize(plugin_findings)}\n"
                       f"Skill findings: {_summarize(skill_findings)}",
            ))

    # --- Pattern: Data Exfiltration ---
    def _check_data_exfiltration(
        self,
        by_module: defaultdict[str, list[dict]],
        findings: list[Finding],
        now: float,
    ) -> None:
        exfil_patterns = [
            f for f in by_module.get("session_analyzer", [])
            if any(kw in f["title"].lower() for kw in ("exfil", "data", "transfer", "upload"))
            and f["last_seen"] >= now - _30_MIN
        ]
        unusual_net = [
            f for f in by_module.get("network_monitor", [])
            if f["last_seen"] >= now - _30_MIN
        ]

        if exfil_patterns and unusual_net:
            findings.append(Finding(
                module="correlation",
                severity=Severity.CRITICAL,
                title="Data exfiltration in progress",
                detail="Exfiltration pattern + unusual network activity within 30 minutes.\n"
                       f"Exfiltration indicators: {_summarize(exfil_patterns)}\n"
                       f"Network anomalies: {_summarize(unusual_net)}",
            ))

    # --- Pattern: Coordinated Attack ---
    def _check_coordinated_attack(
        self,
        recent: list[dict],
        findings: list[Finding],
        now: float,
    ) -> None:
        # 3+ CRITICAL findings from different modules within 15 minutes
        criticals = [
            f for f in recent
            if f["severity"] == int(Severity.CRITICAL)
            and f["last_seen"] >= now - _15_MIN
        ]
        modules_hit = {f["module"] for f in criticals}
        if len(modules_hit) >= 3:
            findings.append(Finding(
                module="correlation",
                severity=Severity.CRITICAL,
                title="Coordinated attack detected",
                detail=f"CRITICAL findings from {len(modules_hit)} modules in 15 minutes: "
                       f"{', '.join(sorted(modules_hit))}.\n"
                       f"Total critical findings: {len(criticals)}.",
            ))

    # --- Pattern: Escalating Threat ---
    def _check_escalating_threat(
        self,
        db: FindingsDB,
        findings: list[Finding],
        now: float,
    ) -> None:
        last_hour = [
            f for f in db.get_findings_since(now - _1_HOUR)
            if f["module"] != "correlation"
        ]
        prev_hour = [
            f for f in db.get_findings_since(now - 2 * _1_HOUR)
            if f["module"] != "correlation"
            and f["last_seen"] < now - _1_HOUR
        ]

        count_last = len(last_hour)
        count_prev = len(prev_hour)

        if count_prev > 0 and count_last > count_prev * 1.5:
            findings.append(Finding(
                module="correlation",
                severity=Severity.WARNING,
                title="Escalating threat level",
                detail=f"Finding count increasing: {count_last} in last hour vs "
                       f"{count_prev} in previous hour (>{50}% increase).",
            ))


    # --- Pattern: Cascading Failure (ASI08) ---
    def _check_cascading_failure(
        self,
        recent: list[dict],
        by_module: defaultdict[str, list[dict]],
        findings: list[Finding],
        now: float,
    ) -> None:
        """Detect cascading failure patterns across agents and modules."""
        # Check for multiple agent failures within 30 minutes
        agent_findings = [
            f for f in by_module.get("agent_comm_audit", [])
            if f["last_seen"] >= now - _30_MIN
        ]
        crash_findings = [
            f for f in by_module.get("log_forensics", [])
            if "crash" in f["title"].lower() and f["last_seen"] >= now - _30_MIN
        ]
        baseline_anomalies = [
            f for f in by_module.get("behavioral_baseline", [])
            if f["severity"] >= int(Severity.WARNING) and f["last_seen"] >= now - _30_MIN
        ]

        # Cascade indicator: errors propagating across multiple systems
        failing_modules = set()
        for f in recent:
            if (f["severity"] >= int(Severity.WARNING)
                    and f["last_seen"] >= now - _30_MIN):
                failing_modules.add(f["module"])

        if len(failing_modules) >= 4 and (crash_findings or baseline_anomalies):
            findings.append(Finding(
                module="correlation",
                severity=Severity.CRITICAL,
                title="Cascading failure detected",
                detail=(
                    f"Warnings/errors across {len(failing_modules)} modules in 30 minutes "
                    f"with {'crash' if crash_findings else 'behavioral anomaly'} indicators. "
                    f"Affected modules: {', '.join(sorted(failing_modules))}. "
                    f"May indicate a cascading failure or system-wide compromise."
                ),
            ))

        # Agent cascade: agent comm issues + other failures
        if agent_findings and len(failing_modules) >= 3:
            findings.append(Finding(
                module="correlation",
                severity=Severity.WARNING,
                title="Agent cascade risk: inter-agent issues with system failures",
                detail=(
                    f"Agent communication issues ({len(agent_findings)} findings) "
                    f"alongside failures in {len(failing_modules)} modules. "
                    f"Errors may be propagating between agents."
                ),
            ))

    # --- Pattern: Resource Exhaustion Chain (ASI08) ---
    def _check_resource_exhaustion_chain(
        self,
        by_module: defaultdict[str, list[dict]],
        findings: list[Finding],
        now: float,
    ) -> None:
        """Detect resource exhaustion leading to cascading issues."""
        process_spikes = [
            f for f in by_module.get("behavioral_baseline", [])
            if "process" in f["title"].lower() and f["last_seen"] >= now - _1_HOUR
        ]
        connection_spikes = [
            f for f in by_module.get("behavioral_baseline", [])
            if "connection" in f["title"].lower() and f["last_seen"] >= now - _1_HOUR
        ]
        crash_findings = [
            f for f in by_module.get("log_forensics", [])
            if "crash" in f["title"].lower() and f["last_seen"] >= now - _1_HOUR
        ]

        if (process_spikes or connection_spikes) and crash_findings:
            findings.append(Finding(
                module="correlation",
                severity=Severity.WARNING,
                title="Resource exhaustion chain detected",
                detail=(
                    f"Resource spikes (processes: {len(process_spikes)}, "
                    f"connections: {len(connection_spikes)}) followed by "
                    f"crashes ({len(crash_findings)}). May indicate DoS or "
                    f"runaway agent consuming resources."
                ),
            ))


def _summarize(findings: list[dict], max_items: int = 3) -> str:
    """Summarize a list of finding dicts into a short string."""
    titles = [f["title"] for f in findings[:max_items]]
    summary = "; ".join(titles)
    if len(findings) > max_items:
        summary += f" (+{len(findings) - max_items} more)"
    return summary
