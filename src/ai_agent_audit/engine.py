"""Orchestrator: loads monitors and sweeps, runs on schedule."""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Optional

from .config import (
    DEFAULT_SWEEP_INTERVAL_SECONDS,
    IOC_AUTO_REFRESH,
    IOC_REFRESH_INTERVAL_SECONDS,
    AUDIT_BASELINES,
)
from .db import FindingsDB
from .ioc import load_ioc_matches, load_custom_iocs, save_ioc_matches
from .learner import PrecisionTracker
from .mappings import enrich
from .models import Finding, ModuleResult
from .monitors.base import BaseMonitor
from .profile import EnvironmentProfiler
from .sweeps.base import BaseSweep

logger = logging.getLogger(__name__)


class AuditEngine:
    """Central orchestrator for monitors and sweeps."""

    # Minimum confidence to alert on a finding (below this, still stored but not alerted)
    ALERT_CONFIDENCE_THRESHOLD = 0.2

    def __init__(
        self,
        db: Optional[FindingsDB] = None,
        sweep_interval: int = DEFAULT_SWEEP_INTERVAL_SECONDS,
        on_finding_callback: Optional[object] = None,
    ):
        self.db = db or FindingsDB()
        self.sweep_interval = sweep_interval
        self._on_finding_extra = on_finding_callback
        self._monitors: list[BaseMonitor] = []
        self._sweeps: list[BaseSweep] = []
        self._monitor_threads: list[threading.Thread] = []
        self._sweep_timer: Optional[threading.Event] = None
        self._running = False
        self.tracker = PrecisionTracker(db=self.db)
        self.profiler = EnvironmentProfiler()
        load_ioc_matches()
        # Pull any previously-fetched feed IOCs into the live detection sets.
        load_custom_iocs()

    def register_monitor(self, monitor: BaseMonitor) -> None:
        self._monitors.append(monitor)

    def register_sweep(self, sweep: BaseSweep) -> None:
        self._sweeps.append(sweep)

    def _on_finding(self, finding: Finding) -> None:
        """Callback for monitors to report findings. Enriches and calibrates first."""
        enrich(finding)
        finding.confidence = self.tracker.calibrate(finding)
        self.db.insert(finding)
        if callable(self._on_finding_extra) and finding.confidence >= self.ALERT_CONFIDENCE_THRESHOLD:
            try:
                self._on_finding_extra(finding)
            except Exception:
                logger.warning("Finding callback failed", exc_info=True)

    def _maybe_refresh_iocs(self) -> None:
        """Refresh the ThreatFox feed if enabled and the interval has elapsed.

        Fail-safe: network/parse errors are logged and never break a sweep cycle.
        The stamp is only advanced on success, so a transient outage retries next
        cycle.
        """
        if not IOC_AUTO_REFRESH:
            return
        stamp = AUDIT_BASELINES / "ioc-refresh.json"
        now = time.time()
        last = 0.0
        try:
            if stamp.exists():
                last = float(json.loads(stamp.read_text()).get("last", 0.0))
        except (json.JSONDecodeError, OSError, ValueError, TypeError):
            last = 0.0
        if now - last < IOC_REFRESH_INTERVAL_SECONDS:
            return
        try:
            from .ioc_updater import IOCUpdater
            stats = IOCUpdater().update_from_threatfox()
            if "error" in stats:
                logger.warning("IOC feed refresh failed: %s", stats["error"])
                return
            loaded = load_custom_iocs()
            logger.info("IOC feed refreshed: %s (%d indicators live in detection)", stats, loaded)
            stamp.parent.mkdir(parents=True, exist_ok=True)
            stamp.write_text(json.dumps({"last": now}))
        except Exception:
            logger.warning("IOC auto-refresh error", exc_info=True)

    def run_all_sweeps(self) -> list[ModuleResult]:
        """Run all registered sweeps and store results."""
        self._maybe_refresh_iocs()
        results = []
        for sweep in self._sweeps:
            if not self.profiler.is_relevant(sweep.name):
                logger.debug("Skipping irrelevant sweep: %s", sweep.name)
                continue
            try:
                result = sweep.execute()
                for finding in result.findings:
                    enrich(finding)
                    finding.confidence = self.tracker.calibrate(finding)
                self.db.insert_many(result.findings)
                results.append(result)
            except Exception:
                logger.exception("Sweep %s failed", sweep.name)
        # Refresh learning systems after each sweep cycle
        self.tracker.refresh()
        save_ioc_matches()
        return results

    def start(self) -> None:
        """Start all monitors and the sweep scheduler."""
        self._running = True
        self._sweep_timer = threading.Event()

        # Start monitors
        for monitor in self._monitors:
            t = threading.Thread(
                target=self._run_monitor, args=(monitor,), daemon=True
            )
            t.start()
            self._monitor_threads.append(t)

        # Start sweep scheduler
        sweep_thread = threading.Thread(target=self._sweep_loop, daemon=True)
        sweep_thread.start()
        self._monitor_threads.append(sweep_thread)

        logger.info(
            "Engine started: %d monitors, %d sweeps (interval=%ds)",
            len(self._monitors),
            len(self._sweeps),
            self.sweep_interval,
        )

    def stop(self) -> None:
        """Stop all monitors and the sweep scheduler."""
        self._running = False
        if self._sweep_timer:
            self._sweep_timer.set()
        for monitor in self._monitors:
            try:
                monitor.stop()
            except Exception:
                logger.exception("Error stopping monitor %s", monitor.name)
        for t in self._monitor_threads:
            t.join(timeout=5)
        self.db.close()
        logger.info("Engine stopped.")

    def _run_monitor(self, monitor: BaseMonitor) -> None:
        try:
            monitor.start()
        except Exception:
            logger.exception("Monitor %s crashed", monitor.name)

    def _sweep_loop(self) -> None:
        """Run sweeps on interval."""
        # Run initial sweep
        self.run_all_sweeps()
        while self._running:
            if self._sweep_timer and self._sweep_timer.wait(self.sweep_interval):
                break  # Timer was set (stop signal)
            if self._running:
                self.run_all_sweeps()


def build_default_engine(db: Optional[FindingsDB] = None) -> AuditEngine:
    """Create an engine with all default monitors and sweeps registered."""
    from .monitors.config_watcher import ConfigWatcher
    from .monitors.credential_guard import CredentialGuard
    from .monitors.memory_poisoning_monitor import MemoryPoisoningMonitor
    from .monitors.network_monitor import NetworkMonitor
    from .monitors.permission_monitor import PermissionMonitor
    from .monitors.process_monitor import ProcessMonitor
    from .monitors.session_analyzer import SessionAnalyzer
    from .sweeps.dm_policy_audit import DMPolicyAuditSweep
    from .sweeps.docker_security import DockerSecuritySweep
    from .sweeps.exec_approvals_audit import ExecApprovalsAuditSweep
    from .sweeps.log_forensics import LogForensicsSweep
    from .sweeps.mcp_security import MCPSecuritySweep
    from .sweeps.network_forensics import NetworkForensicsSweep
    from .sweeps.node_cve_check import NodeCVECheckSweep
    from .sweeps.permission_audit import PermissionAuditSweep
    from .sweeps.persistence_detection import PersistenceDetectionSweep
    from .sweeps.plugin_integrity import PluginIntegritySweep
    from .sweeps.reverse_proxy_audit import ReverseProxyAuditSweep
    from .sweeps.security_score import SecurityScoreSweep
    from .sweeps.skill_scanner import SkillScannerSweep
    from .sweeps.tool_policy_audit import ToolPolicyAuditSweep
    from .sweeps.vscode_trojan_check import VSCodeTrojanCheckSweep
    from .sweeps.websocket_security import WebSocketSecuritySweep
    from .sweeps.behavioral_baseline import BehavioralBaselineSweep
    from .sweeps.credential_rotation import CredentialRotationSweep
    from .sweeps.correlation import CorrelationSweep
    from .sweeps.agent_comm_audit import AgentCommAuditSweep
    from .sweeps.safebins_bypass import SafeBinsBypassSweep
    from .sweeps.mcp_rugpull import MCPRugPullSweep
    from .sweeps.unicode_injection import UnicodeInjectionSweep
    from .sweeps.worm_propagation import WormPropagationSweep
    from .sweeps.agent_version_check import AgentVersionCheckSweep
    from .sweeps.hermes_hardening import HermesHardeningSweep
    from .rules import CustomRulesSweep
    from .alerting import Alerter

    alerter = Alerter()
    engine = AuditEngine(db=db, on_finding_callback=alerter.alert)

    # Register monitors
    for cls in [ConfigWatcher, PermissionMonitor, CredentialGuard,
                ProcessMonitor, NetworkMonitor, SessionAnalyzer,
                MemoryPoisoningMonitor]:
        engine.register_monitor(cls(on_finding=engine._on_finding))

    # Register sweeps
    for cls in [PermissionAuditSweep, PluginIntegritySweep, LogForensicsSweep,
                NetworkForensicsSweep, SecurityScoreSweep,
                SkillScannerSweep, WebSocketSecuritySweep,
                ExecApprovalsAuditSweep, PersistenceDetectionSweep,
                DMPolicyAuditSweep, ToolPolicyAuditSweep,
                MCPSecuritySweep, DockerSecuritySweep,
                ReverseProxyAuditSweep, NodeCVECheckSweep,
                VSCodeTrojanCheckSweep, BehavioralBaselineSweep,
                CredentialRotationSweep, AgentCommAuditSweep,
                SafeBinsBypassSweep, MCPRugPullSweep,
                UnicodeInjectionSweep, WormPropagationSweep,
                AgentVersionCheckSweep, HermesHardeningSweep,
                CustomRulesSweep]:
        engine.register_sweep(cls())

    # CorrelationSweep needs access to the DB for querying recent findings
    engine.register_sweep(CorrelationSweep(db=engine.db))

    return engine
