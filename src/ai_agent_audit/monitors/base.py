"""Abstract base class for always-on monitors."""

from __future__ import annotations

import logging
import threading
from abc import ABC, abstractmethod
from typing import Callable

from ..models import Finding

logger = logging.getLogger(__name__)


class BaseMonitor(ABC):
    """Base class for always-on threaded monitors.

    Subclasses implement `start()` and `stop()`, and call
    `self.report_finding()` whenever something is detected.
    """

    name: str = "base"

    def __init__(self, on_finding: Callable[[Finding], None]):
        self._on_finding = on_finding
        self._running = threading.Event()

    @abstractmethod
    def start(self) -> None:
        """Start monitoring (called from a background thread)."""

    @abstractmethod
    def stop(self) -> None:
        """Stop monitoring and clean up resources."""

    def report_finding(self, finding: Finding) -> None:
        """Report a finding to the engine."""
        logger.info("[%s] %s: %s", self.name, finding.severity.name, finding.title)
        self._on_finding(finding)
