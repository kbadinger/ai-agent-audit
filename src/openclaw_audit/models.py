"""Data models for audit findings and module results."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


class Severity(IntEnum):
    """Finding severity levels, ordered by importance."""
    INFO = 0
    WARNING = 1
    CRITICAL = 2


@dataclass
class Finding:
    """A single security finding."""
    module: str
    severity: Severity
    title: str
    detail: str
    path: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

    @property
    def dedup_hash(self) -> str:
        """Hash for deduplication - same module+title+path = same finding."""
        key = f"{self.module}:{self.title}:{self.path or ''}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]


@dataclass
class ModuleResult:
    """Result from running a monitor check or sweep."""
    module_name: str
    findings: list[Finding] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    duration_seconds: float = 0.0
