"""Abstract base class for periodic deep sweeps."""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod

from ..models import ModuleResult

logger = logging.getLogger(__name__)


class BaseSweep(ABC):
    """Base class for periodic security sweeps.

    Subclasses implement `run()` which returns a ModuleResult.
    """

    name: str = "base"

    @abstractmethod
    def run(self) -> ModuleResult:
        """Execute the sweep and return results."""

    def execute(self) -> ModuleResult:
        """Run the sweep with timing."""
        start = time.time()
        logger.info("[%s] Starting sweep...", self.name)
        result = self.run()
        result.duration_seconds = time.time() - start
        logger.info(
            "[%s] Completed in %.1fs, %d findings (%s)",
            self.name,
            result.duration_seconds,
            len(result.findings),
            result.status.value,
        )
        return result
