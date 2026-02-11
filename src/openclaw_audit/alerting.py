"""Alert dispatcher for critical findings."""

from __future__ import annotations

import json
import logging
import subprocess
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional

from .config import AUDIT_DIR
from .models import Finding, Severity

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG = {
    "enabled": True,
    "cooldown_seconds": 300,
    "backends": [
        {"type": "macos"}
    ],
}


class Alerter:
    """Dispatches notifications for critical findings."""

    def __init__(self, config_path: Optional[Path] = None):
        self._config_path = config_path or (AUDIT_DIR / "alerts.json")
        self._config = self._load_config()
        # Track last alert time per dedup_hash for cooldown
        self._last_alerted: dict[str, float] = {}

    def _load_config(self) -> dict:
        if not self._config_path.exists():
            return {"enabled": False, "cooldown_seconds": 300, "backends": []}
        try:
            return json.loads(self._config_path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to load alert config: %s", exc)
            return {"enabled": False, "cooldown_seconds": 300, "backends": []}

    def alert(self, finding: Finding) -> None:
        """Send alerts for a critical finding."""
        if not self._config.get("enabled", False):
            return
        if finding.severity != Severity.CRITICAL:
            return

        # Cooldown deduplication
        cooldown = self._config.get("cooldown_seconds", 300)
        now = time.time()
        last = self._last_alerted.get(finding.dedup_hash, 0)
        if now - last < cooldown:
            return

        self._last_alerted[finding.dedup_hash] = now

        backends = self._config.get("backends", [])
        for backend in backends:
            backend_type = backend.get("type", "")
            try:
                handler = {
                    "telegram": self._send_telegram,
                    "slack": self._send_slack,
                    "macos": self._send_macos_notification,
                    "file": self._send_file,
                }.get(backend_type)
                if handler:
                    handler(finding, backend)
                else:
                    logger.warning("Unknown alert backend type: %s", backend_type)
            except Exception:
                logger.warning("Alert backend '%s' failed", backend_type, exc_info=True)

    def _send_telegram(self, finding: Finding, config: dict) -> None:
        token = config.get("token", "")
        chat_id = config.get("chat_id", "")
        if not token or not chat_id:
            logger.warning("Telegram config missing token or chat_id")
            return

        text = f"[OpenClaw CRITICAL] {finding.title}\n{finding.detail}"
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = json.dumps({"chat_id": chat_id, "text": text}).encode()
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=10)

    def _send_slack(self, finding: Finding, config: dict) -> None:
        webhook_url = config.get("webhook_url", "")
        if not webhook_url:
            logger.warning("Slack config missing webhook_url")
            return

        text = f":rotating_light: *[OpenClaw CRITICAL]* {finding.title}\n{finding.detail}"
        payload = json.dumps({"text": text}).encode()
        req = urllib.request.Request(
            webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=10)

    def _send_macos_notification(self, finding: Finding, config: dict) -> None:
        title = "OpenClaw Audit: CRITICAL"
        message = finding.title
        try:
            subprocess.run(
                [
                    "osascript", "-e",
                    f'display notification "{message}" with title "{title}"',
                ],
                capture_output=True,
                timeout=5,
            )
        except Exception:
            pass  # macOS notifications are best-effort

    def _send_file(self, finding: Finding, config: dict) -> None:
        path = config.get("path", "")
        if not path:
            logger.warning("File alert config missing path")
            return

        line = (
            f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] "
            f"CRITICAL: {finding.title} | {finding.detail}\n"
        )
        with open(path, "a") as f:
            f.write(line)

    @staticmethod
    def create_default_config(path: Optional[Path] = None) -> Path:
        """Write a default alerts.json config and return its path."""
        dest = path or (AUDIT_DIR / "alerts.json")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(_DEFAULT_CONFIG, indent=2) + "\n")
        logger.info("Created default alert config at %s", dest)
        return dest
