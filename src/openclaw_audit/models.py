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
    confidence: float = 0.5
    triage_status: Optional[str] = None  # "confirmed", "false_positive", "dismissed"
    mitre_attack: Optional[str] = None   # e.g. "T1059.004"
    owasp_asi: Optional[str] = None      # e.g. "ASI01"
    remediation: Optional[str] = None
    eu_ai_act: Optional[str] = None      # e.g. "Art.9(1)" — EU AI Act article
    nist_rmf: Optional[str] = None       # e.g. "GV-1.1" — NIST AI RMF subcategory

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
