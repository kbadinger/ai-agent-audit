"""Reverse proxy and gateway configuration audit."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from ..config import OPENCLAW_CONFIG
from ..models import Finding, ModuleResult, Severity
from .base import BaseSweep

logger = logging.getLogger(__name__)

# Loopback addresses that are safe for binding
_LOOPBACK = {"127.0.0.1", "localhost", "::1"}


class ReverseProxyAuditSweep(BaseSweep):
    name = "reverse_proxy_audit"

    def run(self) -> ModuleResult:
        findings: list[Finding] = []

        if not OPENCLAW_CONFIG.exists():
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title="OpenClaw config not found",
                detail=f"{OPENCLAW_CONFIG} does not exist.",
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        try:
            data = json.loads(OPENCLAW_CONFIG.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            findings.append(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title="Config unreadable",
                detail=f"Could not parse {OPENCLAW_CONFIG}: {exc}",
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        gateway = data.get("gateway", {})
        bind_addr = gateway.get("bind", "127.0.0.1")
        trusted_proxies = gateway.get("trustedProxies") or []

        # Non-loopback bind without trustedProxies
        if bind_addr not in _LOOPBACK and not trusted_proxies:
            findings.append(Finding(
                module=self.name,
                severity=Severity.CRITICAL,
                title="Reverse proxy bypass risk",
                detail=(
                    f"Gateway binds to '{bind_addr}' but trustedProxies is empty. "
                    "Clients can spoof X-Forwarded-For headers to bypass IP restrictions."
                ),
                path=str(OPENCLAW_CONFIG),
            ))

        # dangerouslyDisableDeviceAuth
        if gateway.get("dangerouslyDisableDeviceAuth") is True:
            findings.append(Finding(
                module=self.name,
                severity=Severity.CRITICAL,
                title="Device authentication disabled (dangerous flag)",
                detail=(
                    "gateway.dangerouslyDisableDeviceAuth=true. "
                    "Any device on the network can access the gateway."
                ),
                path=str(OPENCLAW_CONFIG),
            ))

        # LAN binding without trustedProxies (e.g. 0.0.0.0, 192.168.*, 10.*)
        if bind_addr not in _LOOPBACK and bind_addr != "" and not trusted_proxies:
            is_lan = (
                bind_addr.startswith("192.168.")
                or bind_addr.startswith("10.")
                or bind_addr.startswith("172.")
                or bind_addr == "0.0.0.0"
            )
            if is_lan:
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title="Gateway bound to LAN without proxy config",
                    detail=(
                        f"Gateway binds to LAN address '{bind_addr}' without "
                        "trustedProxies. Configure trustedProxies or bind to localhost."
                    ),
                    path=str(OPENCLAW_CONFIG),
                ))

        # Tailscale funnel reference
        tailscale_keys = ["tailscale", "funnel", "tsnet"]
        config_str = json.dumps(data).lower()
        for key in tailscale_keys:
            if key in config_str:
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.WARNING,
                    title="Tailscale funnel reference detected",
                    detail=(
                        f"Config references '{key}'. If Tailscale Funnel is active, "
                        "the gateway may be exposed to the internet."
                    ),
                    path=str(OPENCLAW_CONFIG),
                ))
                break

        return ModuleResult(module_name=self.name, findings=findings)
