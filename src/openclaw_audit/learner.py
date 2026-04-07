"""Precision tracker — calibrates finding confidence from triage feedback."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from .config import AUDIT_BASELINES
from .models import Finding

logger = logging.getLogger(__name__)

PRECISION_FILE = AUDIT_BASELINES / "precision.json"

# Minimum triage count before we start adjusting confidence.
MIN_SAMPLES = 3


class PrecisionTracker:
    """Learns from human triage feedback to calibrate future confidence scores.

    Tracks precision (confirmed / (confirmed + false_positive)) per detection
    rule (module + title). Rules with low precision get suppressed; rules with
    high precision get boosted.
    """

    def __init__(self, db=None):
        self._db = db
        # key -> {"confirmed": N, "false_positive": N, "precision": float}
        self._stats: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        """Load cached precision scores from disk."""
        try:
            if PRECISION_FILE.exists():
                self._stats = json.loads(PRECISION_FILE.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to load precision data: %s", exc)

    def _save(self) -> None:
        """Persist precision scores to disk."""
        try:
            PRECISION_FILE.parent.mkdir(parents=True, exist_ok=True)
            PRECISION_FILE.write_text(json.dumps(self._stats, indent=2))
        except OSError as exc:
            logger.warning("Failed to save precision data: %s", exc)

    def refresh(self) -> None:
        """Recalculate precision scores from the database."""
        if self._db is None:
            return
        raw = self._db.get_precision_stats()
        for key, counts in raw.items():
            confirmed = counts.get("confirmed", 0)
            fp = counts.get("false_positive", 0)
            total = confirmed + fp
            precision = confirmed / total if total > 0 else 1.0
            self._stats[key] = {
                "confirmed": confirmed,
                "false_positive": fp,
                "precision": precision,
            }
        self._save()

    def calibrate(self, finding: Finding) -> float:
        """Return adjusted confidence for a finding based on triage history.

        Logic:
        - No triage data for this rule: return original confidence unchanged
        - Fewer than MIN_SAMPLES triages: return original (not enough data)
        - Otherwise: base_confidence * precision_multiplier
          where precision_multiplier = 0.2 + 0.8 * precision
          (floors at 0.2 so even bad rules aren't fully invisible)
        """
        key = f"{finding.module}:{finding.title}"
        stats = self._stats.get(key)

        if stats is None:
            return finding.confidence

        total = stats.get("confirmed", 0) + stats.get("false_positive", 0)
        if total < MIN_SAMPLES:
            return finding.confidence

        precision = stats.get("precision", 1.0)
        # Multiplier ranges from 0.2 (all false positives) to 1.0 (all confirmed)
        multiplier = 0.2 + 0.8 * precision
        return round(min(1.0, finding.confidence * multiplier), 3)
