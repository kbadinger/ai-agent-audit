"""Monitor openclaw.json for insecure configuration changes."""

from __future__ import annotations

import logging
import re
import threading
from pathlib import Path
from typing import Any

from watchdog.events import FileSystemEventHandler, FileModifiedEvent
from watchdog.observers import Observer

from ..agent_config import AgentConfigError, first_nested, load_agent_config
from ..config import (
    ACTIVE_PROFILE,
    INSECURE_CONFIG_RULES,
    OPENCLAW_CONFIG,
    SECRET_PATTERNS,
)
from ..models import Finding, Severity
from .base import BaseMonitor

logger = logging.getLogger(__name__)


def _resolve_key(data: dict, dotted_key: str) -> Any:
    """Resolve a dotted key from a nested dict (legacy test/helper API)."""
    parts = dotted_key.split(".")
    cur = data
    for part in parts:
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


class _ConfigHandler(FileSystemEventHandler):
    def __init__(self, monitor: ConfigWatcher):
        self._monitor = monitor

    def on_modified(self, event: FileModifiedEvent) -> None:  # type: ignore[override]
        if Path(event.src_path).resolve() == self._monitor._config_path.resolve():
            self._monitor._check_config()


class ConfigWatcher(BaseMonitor):
    """Watches openclaw.json for insecure settings and hardcoded secrets."""

    name = "config_watcher"

    def __init__(self, on_finding, config_path: Path | None = None):
        super().__init__(on_finding)
        self._config_path = config_path or OPENCLAW_CONFIG
        self._observer: Observer | None = None

    def start(self) -> None:
        self._running.set()
        # Initial check
        self._check_config()

        if not self._config_path.parent.exists():
            logger.warning("Config directory %s does not exist, skipping watcher", self._config_path.parent)
            return

        self._observer = Observer()
        self._observer.schedule(_ConfigHandler(self), str(self._config_path.parent), recursive=False)
        self._observer.daemon = True
        self._observer.start()

    def stop(self) -> None:
        self._running.clear()
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None

    def _check_config(self) -> None:
        if not self._config_path.exists():
            return

        try:
            raw = self._config_path.read_text()
            data = load_agent_config(self._config_path)
        except AgentConfigError as exc:
            logger.debug("Could not read config: %s", exc)
            return

        # Check insecure config rules
        for rule in INSECURE_CONFIG_RULES:
            if ACTIVE_PROFILE.slug not in rule.get("profiles", (ACTIVE_PROFILE.slug,)):
                continue
            value = first_nested(data, rule["key"], *rule.get("legacy_keys", ()))
            if rule["check"](value):
                self.report_finding(Finding(
                    module=self.name,
                    severity=Severity[rule["severity"]],
                    title=rule["title"],
                    detail=rule["detail"],
                    path=str(self._config_path),
                ))

        # Scan raw text for hardcoded secrets
        for secret_name, pattern in SECRET_PATTERNS.items():
            if re.search(pattern, raw):
                self.report_finding(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title=f"Hardcoded secret in config: {secret_name}",
                    detail=f"Pattern for '{secret_name}' matched in {self._config_path.name}.",
                    path=str(self._config_path),
                ))
