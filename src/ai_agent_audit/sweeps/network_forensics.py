"""Network forensics: snapshot connections for the active agent's processes."""

from __future__ import annotations

import logging
import socket

from ..config import ACTIVE_PROFILE
from ..ioc import C2_IPS, C2_PORTS, EXFIL_DOMAINS, record_ioc_match
from ..models import Finding, ModuleResult, Severity
from .base import BaseSweep

logger = logging.getLogger(__name__)

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

_PROCESS_KEYWORDS = tuple(kw.lower() for kw in ACTIVE_PROFILE.process_keywords)


def _reverse_dns(ip: str) -> str | None:
    """Attempt reverse DNS lookup, return hostname or None."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


def _is_agent_process(proc: "psutil.Process") -> bool:
    """Check if a process belongs to the active agent."""
    try:
        name = proc.name().lower()
        cmdline = " ".join(proc.cmdline()).lower()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False
    return any(kw in name or kw in cmdline for kw in _PROCESS_KEYWORDS)


class NetworkForensicsSweep(BaseSweep):
    name = "network_forensics"

    def run(self) -> ModuleResult:
        findings: list[Finding] = []

        if not HAS_PSUTIL:
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title="psutil not available",
                detail="Install psutil for network forensics.",
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        # Find active-agent processes
        agent_pids: set[int] = set()
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            if _is_agent_process(proc):
                agent_pids.add(proc.pid)

        if not agent_pids:
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title=f"No {ACTIVE_PROFILE.display_name} processes found",
                detail=f"No running processes match {list(_PROCESS_KEYWORDS)}.",
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        # Get connections for active-agent processes
        for pid in agent_pids:
            try:
                proc = psutil.Process(pid)
                connections = proc.net_connections()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            for conn in connections:
                local_addr = (
                    f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                )
                remote_addr = "N/A"
                remote_host = None

                if conn.raddr:
                    remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}"
                    remote_host = _reverse_dns(conn.raddr.ip)

                detail_parts = [
                    f"PID: {pid}",
                    f"Local: {local_addr}",
                    f"Remote: {remote_addr}",
                    f"Status: {conn.status}",
                ]
                if remote_host:
                    detail_parts.append(f"Remote hostname: {remote_host}")

                # Report all connections as info-level findings
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.INFO,
                    title=f"Connection: {conn.status}",
                    detail="; ".join(detail_parts),
                ))

                # Flag listening on 0.0.0.0
                if (
                    conn.status == "LISTEN"
                    and conn.laddr
                    and conn.laddr.ip == "0.0.0.0"
                ):
                    findings.append(Finding(
                        module=self.name,
                        severity=Severity.CRITICAL,
                        title="Listening on all interfaces",
                        detail=(
                            f"PID {pid} listening on 0.0.0.0:{conn.laddr.port}. "
                            f"Should bind to 127.0.0.1."
                        ),
                    ))

                if conn.raddr:
                    # Check remote IP against known C2 IPs
                    if conn.raddr.ip in C2_IPS:
                        record_ioc_match(conn.raddr.ip)
                        findings.append(Finding(
                            module=self.name,
                            severity=Severity.CRITICAL,
                            title="Known C2 IP detected",
                            detail=f"PID {pid} connected to known C2 IP {conn.raddr.ip}:{conn.raddr.port}.",
                        ))

                    # Check remote port against known C2 ports
                    if conn.raddr.port in C2_PORTS:
                        record_ioc_match(str(conn.raddr.port))
                        findings.append(Finding(
                            module=self.name,
                            severity=Severity.CRITICAL,
                            title="Known C2 port detected",
                            detail=f"PID {pid} connected to {conn.raddr.ip} on known C2 port {conn.raddr.port}.",
                        ))

                    # Check if remote IP resolves to an exfil domain
                    if remote_host:
                        for domain in EXFIL_DOMAINS:
                            if remote_host == domain or remote_host.endswith("." + domain):
                                record_ioc_match(domain)
                                findings.append(Finding(
                                    module=self.name,
                                    severity=Severity.CRITICAL,
                                    title="Exfiltration domain detected",
                                    detail=f"PID {pid} connected to {remote_host} ({conn.raddr.ip}), known exfil domain.",
                                ))
                                break

        return ModuleResult(module_name=self.name, findings=findings)
