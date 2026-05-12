"""Monitor agent processes for suspicious activity (OpenClaw / Hermes / ...)."""

from __future__ import annotations

import logging
import re
import threading

import psutil

from ..config import ACTIVE_PROFILE, MONITOR_POLL_INTERVAL_SECONDS, SUSPICIOUS_PROCESS_PATTERNS
from ..models import Finding, Severity
from .base import BaseMonitor

logger = logging.getLogger(__name__)

_MAX_TREE_DEPTH = 5
_MAX_CHILDREN = 20
_PROCESS_KEYWORDS = tuple(kw.lower() for kw in ACTIVE_PROFILE.process_keywords)


def _get_agent_pids() -> list[int]:
    """Find PIDs of processes matching the active agent's process keywords."""
    pids: list[int] = []
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            name = (proc.info["name"] or "").lower()
            cmdline = " ".join(proc.info["cmdline"] or []).lower()
            if any(kw in name or kw in cmdline for kw in _PROCESS_KEYWORDS):
                pids.append(proc.info["pid"])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return pids


def _tree_depth(proc: psutil.Process, seen: set[int] | None = None) -> int:
    """Return the depth of a process tree (1 = leaf)."""
    if seen is None:
        seen = set()
    if proc.pid in seen:
        return 0
    seen.add(proc.pid)
    try:
        children = proc.children()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return 1
    if not children:
        return 1
    return 1 + max(_tree_depth(c, seen) for c in children)


class ProcessMonitor(BaseMonitor):
    """Tracks the active agent's process trees and flags suspicious children."""

    name = "process_monitor"

    def __init__(self, on_finding):
        super().__init__(on_finding)
        self._poll_thread: threading.Thread | None = None

    def start(self) -> None:
        self._running.set()
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._poll_thread.start()

    def stop(self) -> None:
        self._running.clear()
        if self._poll_thread:
            self._poll_thread.join(timeout=5)
            self._poll_thread = None

    def _poll_loop(self) -> None:
        # Check once immediately, then poll
        self._check()
        while self._running.is_set():
            self._running.wait(timeout=MONITOR_POLL_INTERVAL_SECONDS)
            if not self._running.is_set():
                break
            self._check()

    def _check(self) -> None:
        pids = _get_agent_pids()
        if not pids:
            return

        for pid in pids:
            try:
                parent = psutil.Process(pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            self._check_tree(parent)

    def _check_tree(self, proc: psutil.Process) -> None:
        # Check tree depth
        depth = _tree_depth(proc)
        if depth > _MAX_TREE_DEPTH:
            self.report_finding(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title="Deep process tree",
                detail=f"PID {proc.pid} has a process tree {depth} levels deep (limit {_MAX_TREE_DEPTH}).",
            ))

        try:
            children = proc.children(recursive=True)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return

        # Check excessive children
        if len(children) > _MAX_CHILDREN:
            self.report_finding(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title="Excessive child processes",
                detail=f"PID {proc.pid} has {len(children)} children (limit {_MAX_CHILDREN}).",
            ))

        for child in children:
            try:
                child_name = (child.name() or "").lower()
                child_cmdline = " ".join(child.cmdline())
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            # Flag non-node children
            if child_name and child_name != "node" and not child_name.startswith("node"):
                self.report_finding(Finding(
                    module=self.name,
                    severity=Severity.INFO,
                    title=f"Non-node child process: {child_name}",
                    detail=f"PID {child.pid} ({child_name}) is a child of {ACTIVE_PROFILE.display_name} PID {proc.pid}.",
                ))

            # Check against suspicious patterns
            for rule in SUSPICIOUS_PROCESS_PATTERNS:
                if re.search(rule["pattern"], child_cmdline):
                    self.report_finding(Finding(
                        module=self.name,
                        severity=Severity.CRITICAL,
                        title=f"Suspicious process: {rule['name']}",
                        detail=f"PID {child.pid} cmdline matches '{rule['name']}' pattern.",
                    ))
