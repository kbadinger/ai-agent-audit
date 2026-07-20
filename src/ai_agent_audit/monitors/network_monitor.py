"""Monitor network connections made by the active agent's processes."""

from __future__ import annotations

import ipaddress
import logging
import threading

import psutil

from ..config import ACTIVE_PROFILE, MONITOR_POLL_INTERVAL_SECONDS
from ..ioc import C2_IPS, C2_PORTS, record_ioc_match
from ..models import Finding, Severity
from .base import BaseMonitor

logger = logging.getLogger(__name__)

_STANDARD_PORTS = {80, 443, 8080}
_MAX_CONNECTIONS = 50
_PROCESS_KEYWORDS = tuple(kw.lower() for kw in ACTIVE_PROFILE.process_keywords)


def _get_agent_pids() -> list[int]:
    """Find PIDs of processes matching the active agent's process keywords."""
    pids: list[int] = []
    try:
        processes = list(psutil.process_iter(["pid", "name", "cmdline"]))
    except (psutil.Error, OSError) as exc:
        logger.warning("Process visibility unavailable: %s", exc)
        return pids
    for proc in processes:
        try:
            name = (proc.info["name"] or "").lower()
            cmdline = " ".join(proc.info["cmdline"] or []).lower()
            if any(kw in name or kw in cmdline for kw in _PROCESS_KEYWORDS):
                pids.append(proc.info["pid"])
        except (psutil.Error, OSError, KeyError, TypeError):
            continue
    return pids


def _is_private_non_localhost(addr: str) -> bool:
    """Return True if addr is a private LAN address but not loopback."""
    try:
        ip = ipaddress.ip_address(addr)
        return ip.is_private and not ip.is_loopback
    except ValueError:
        return False


class NetworkMonitor(BaseMonitor):
    """Flags suspicious network activity from the active agent's processes."""

    name = "network_monitor"

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

        pid_set = set(pids)
        connections: list[psutil._common.sconn] = []

        try:
            all_conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            logger.debug("Cannot access network connections (may need root)")
            return

        for conn in all_conns:
            if conn.pid in pid_set:
                connections.append(conn)

        # Excessive connections
        if len(connections) > _MAX_CONNECTIONS:
            self.report_finding(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title="Excessive network connections",
                detail=f"{ACTIVE_PROFILE.display_name} processes have {len(connections)} connections (limit {_MAX_CONNECTIONS}).",
            ))

        for conn in connections:
            laddr = conn.laddr
            raddr = conn.raddr

            # Listening on 0.0.0.0
            if conn.status == "LISTEN" and laddr and laddr.ip in ("0.0.0.0", "::"):
                self.report_finding(Finding(
                    module=self.name,
                    severity=Severity.WARNING,
                    title=f"Listening on all interfaces (port {laddr.port})",
                    detail=f"PID {conn.pid} is listening on {laddr.ip}:{laddr.port}. Bind to 127.0.0.1 instead.",
                ))

            if not raddr:
                continue

            remote_ip = raddr.ip
            remote_port = raddr.port

            # Non-standard remote port
            if remote_port not in _STANDARD_PORTS:
                self.report_finding(Finding(
                    module=self.name,
                    severity=Severity.INFO,
                    title=f"Non-standard port connection: {remote_port}",
                    detail=f"PID {conn.pid} connected to {remote_ip}:{remote_port}.",
                ))

            # Private LAN address (not localhost)
            if _is_private_non_localhost(remote_ip):
                self.report_finding(Finding(
                    module=self.name,
                    severity=Severity.WARNING,
                    title=f"LAN connection to {remote_ip}",
                    detail=f"PID {conn.pid} connected to private LAN address {remote_ip}:{remote_port}.",
                ))

            # Check against known C2 IPs
            if remote_ip in C2_IPS:
                record_ioc_match(remote_ip)
                self.report_finding(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title=f"Known C2 IP: {remote_ip}",
                    detail=f"PID {conn.pid} connected to known C2 IP {remote_ip}:{remote_port}.",
                ))

            # Check against known C2 ports
            if remote_port in C2_PORTS:
                record_ioc_match(str(remote_port))
                self.report_finding(Finding(
                    module=self.name,
                    severity=Severity.WARNING,
                    title=f"Known C2 port: {remote_port}",
                    detail=f"PID {conn.pid} connected to {remote_ip} on known C2 port {remote_port}.",
                ))
