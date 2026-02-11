"""Check for CVE-2026-25253: WebSocket origin spoofing on OpenClaw gateway."""

from __future__ import annotations

import logging
import socket

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
                severity=Severity.CRITICAL,
                title="CVE-2026-25253: WebSocket origin not validated",
                detail=(
                    "Gateway accepted WebSocket upgrade from spoofed Origin "
                    "'http://evil.attacker.com'. A malicious webpage can connect "
                    "to the local gateway and control the agent."
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
