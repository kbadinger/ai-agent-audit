"""Check for CVE-2026-25253: WebSocket origin spoofing on OpenClaw gateway."""

from __future__ import annotations

import json
import logging
import socket

from ..config import OPENCLAW_CONFIG
from ..models import Finding, ModuleResult, Severity
from .base import BaseSweep

logger = logging.getLogger(__name__)

GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 18789

# WebSocket upgrade request with spoofed Origin header
_WS_UPGRADE = (
    f"GET / HTTP/1.1\r\n"
    f"Host: {GATEWAY_HOST}:{GATEWAY_PORT}\r\n"
    f"Upgrade: websocket\r\n"
    f"Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    f"Sec-WebSocket-Version: 13\r\n"
    f"Origin: http://evil.attacker.com\r\n"
    f"\r\n"
).encode()


class WebSocketSecuritySweep(BaseSweep):
    name = "websocket_security"

    def run(self) -> ModuleResult:
        findings: list[Finding] = []

        # Check config for dangerous auth bypasses
        self._check_config(findings)

        # First check if gateway is listening
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            sock.connect((GATEWAY_HOST, GATEWAY_PORT))
        except (ConnectionRefusedError, OSError):
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title="Gateway not running",
                detail=f"Could not connect to {GATEWAY_HOST}:{GATEWAY_PORT}. Gateway may not be running.",
            ))
            return ModuleResult(module_name=self.name, findings=findings)
        finally:
            sock.close()

        # Attempt WebSocket upgrade with spoofed Origin
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((GATEWAY_HOST, GATEWAY_PORT))
            sock.sendall(_WS_UPGRADE)
            response = sock.recv(4096).decode(errors="ignore")
        except (ConnectionRefusedError, OSError, socket.timeout) as exc:
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title="Gateway connection error during WebSocket test",
                detail=str(exc),
            ))
            return ModuleResult(module_name=self.name, findings=findings)
        finally:
            sock.close()

        if "101" in response and "Switching Protocols" in response:
            findings.append(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title="WebSocket origin not validated at HTTP upgrade",
                detail=(
                    "Gateway accepted WebSocket upgrade from spoofed Origin "
                    "'http://evil.attacker.com'. Origin validation only occurs "
                    "later for Control UI / Webchat clients, not at the HTTP "
                    "upgrade level. Ed25519 challenge-response prevents "
                    "unauthenticated access, but origin should be checked earlier "
                    "as defense-in-depth."
                ),
            ))
        else:
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title="WebSocket origin validation appears active",
                detail="Gateway did not accept upgrade from spoofed origin.",
            ))

        return ModuleResult(module_name=self.name, findings=findings)

    def _check_config(self, findings: list[Finding]) -> None:
        """Check for config flags that weaken or disable the challenge-response."""
        if not OPENCLAW_CONFIG.exists():
            return
        try:
            data = json.loads(OPENCLAW_CONFIG.read_text())
        except (json.JSONDecodeError, OSError):
            return

        control_ui = data.get("gateway", {}).get("controlUi", {})
        if not isinstance(control_ui, dict):
            return

        if control_ui.get("allowInsecureAuth") is True:
            findings.append(Finding(
                module=self.name,
                severity=Severity.CRITICAL,
                title="Insecure auth allows WebSocket full compromise",
                detail=(
                    "gateway.controlUi.allowInsecureAuth is true. "
                    "The Ed25519 device identity can be skipped. Combined with "
                    "missing origin validation on HTTP upgrade, any webpage can "
                    "authenticate with just a token/password and fully control the agent."
                ),
                path=str(OPENCLAW_CONFIG),
            ))

        if control_ui.get("dangerouslyDisableDeviceAuth") is True:
            findings.append(Finding(
                module=self.name,
                severity=Severity.CRITICAL,
                title="Device auth disabled — WebSocket fully exploitable",
                detail=(
                    "gateway.controlUi.dangerouslyDisableDeviceAuth is true. "
                    "The Ed25519 challenge-response is bypassed entirely. "
                    "Any webpage can connect and control the agent without "
                    "any authentication."
                ),
                path=str(OPENCLAW_CONFIG),
            ))
