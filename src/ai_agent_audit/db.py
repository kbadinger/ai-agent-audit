"""SQLite storage for audit findings with deduplication."""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional

from .config import AUDIT_DB, AUDIT_DIR
from .models import Finding, Severity

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dedup_hash TEXT NOT NULL,
    module TEXT NOT NULL,
    severity INTEGER NOT NULL,
    title TEXT NOT NULL,
    detail TEXT NOT NULL,
    path TEXT,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    times_seen INTEGER NOT NULL DEFAULT 1,
    resolved INTEGER NOT NULL DEFAULT 0,
    confidence REAL NOT NULL DEFAULT 0.5,
    triage_status TEXT,
    triage_timestamp REAL,
    mitre_attack TEXT,
    owasp_asi TEXT,
    remediation TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_hash ON findings(dedup_hash);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_last_seen ON findings(last_seen);
"""

# Columns added in Sprint 7 — applied to existing databases via ALTER TABLE.
_MIGRATION_COLUMNS = [
    ("confidence", "REAL NOT NULL DEFAULT 0.5"),
    ("triage_status", "TEXT"),
    ("triage_timestamp", "REAL"),
    ("mitre_attack", "TEXT"),
    ("owasp_asi", "TEXT"),
    ("remediation", "TEXT"),
    ("eu_ai_act", "TEXT"),
    ("nist_rmf", "TEXT"),
]


class FindingsDB:
    """Thread-safe SQLite store for findings."""

    def __init__(self, db_path: Optional[Path] = None):
        self._path = db_path or AUDIT_DB
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False, timeout=30)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        """Add new columns to existing databases (idempotent)."""
        for col_name, col_type in _MIGRATION_COLUMNS:
            try:
                self._conn.execute(
                    f"ALTER TABLE findings ADD COLUMN {col_name} {col_type}"
                )
            except sqlite3.OperationalError:
                pass  # Column already exists
        self._conn.commit()

    def insert(self, finding: Finding) -> None:
        """Insert or update a finding (dedup by hash)."""
        with self._lock:
            row = self._conn.execute(
                "SELECT id, times_seen FROM findings WHERE dedup_hash = ? AND resolved = 0",
                (finding.dedup_hash,),
            ).fetchone()

            if row:
                self._conn.execute(
                    "UPDATE findings SET last_seen = ?, times_seen = ?, detail = ?, confidence = ?,"
                    " mitre_attack = COALESCE(?, mitre_attack),"
                    " owasp_asi = COALESCE(?, owasp_asi),"
                    " remediation = COALESCE(?, remediation),"
                    " eu_ai_act = COALESCE(?, eu_ai_act),"
                    " nist_rmf = COALESCE(?, nist_rmf)"
                    " WHERE id = ?",
                    (finding.timestamp, row["times_seen"] + 1, finding.detail, finding.confidence,
                     finding.mitre_attack, finding.owasp_asi, finding.remediation,
                     finding.eu_ai_act, finding.nist_rmf, row["id"]),
                )
            else:
                self._conn.execute(
                    "INSERT INTO findings (dedup_hash, module, severity, title, detail, path,"
                    " first_seen, last_seen, confidence, mitre_attack, owasp_asi, remediation,"
                    " eu_ai_act, nist_rmf)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        finding.dedup_hash,
                        finding.module,
                        int(finding.severity),
                        finding.title,
                        finding.detail,
                        finding.path,
                        finding.timestamp,
                        finding.timestamp,
                        finding.confidence,
                        finding.mitre_attack,
                        finding.owasp_asi,
                        finding.remediation,
                        finding.eu_ai_act,
                        finding.nist_rmf,
                    ),
                )
            self._conn.commit()

    def insert_many(self, findings: list[Finding]) -> None:
        """Insert multiple findings."""
        for f in findings:
            self.insert(f)

    def get_active_findings(self) -> list[dict]:
        """Get all unresolved findings, ordered by severity desc."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM findings WHERE resolved = 0 ORDER BY severity DESC, last_seen DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    def get_findings_since(self, since: float) -> list[dict]:
        """Get findings seen since a timestamp."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM findings WHERE last_seen >= ? ORDER BY severity DESC",
                (since,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_trend_data(self, days: int = 30) -> list[dict]:
        """Get daily finding counts for trending."""
        cutoff = time.time() - (days * 86400)
        with self._lock:
            rows = self._conn.execute(
                "SELECT date(first_seen, 'unixepoch') as day, severity, COUNT(*) as count "
                "FROM findings WHERE first_seen >= ? GROUP BY day, severity ORDER BY day",
                (cutoff,),
            ).fetchall()
            return [dict(r) for r in rows]

    def resolve_stale(self, module: str, current_hashes: set[str]) -> None:
        """Mark findings as resolved if they no longer appear in current scan."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, dedup_hash FROM findings WHERE module = ? AND resolved = 0",
                (module,),
            ).fetchall()
            for row in rows:
                if row["dedup_hash"] not in current_hashes:
                    self._conn.execute(
                        "UPDATE findings SET resolved = 1 WHERE id = ?", (row["id"],)
                    )
            self._conn.commit()

    def triage(self, finding_id: int, status: str) -> bool:
        """Set triage status on a finding. Returns True if finding was found."""
        if status not in ("confirmed", "false_positive", "dismissed"):
            raise ValueError(f"Invalid triage status: {status}")
        with self._lock:
            cursor = self._conn.execute(
                "UPDATE findings SET triage_status = ?, triage_timestamp = ? WHERE id = ?",
                (status, time.time(), finding_id),
            )
            self._conn.commit()
            return cursor.rowcount > 0

    def get_precision_stats(self) -> dict[str, dict]:
        """Get confirmed/false_positive counts per (module, title) for calibration."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT module, title, triage_status, COUNT(*) as cnt "
                "FROM findings WHERE triage_status IN ('confirmed', 'false_positive') "
                "GROUP BY module, title, triage_status"
            ).fetchall()

        stats: dict[str, dict] = {}
        for row in rows:
            key = f"{row['module']}:{row['title']}"
            if key not in stats:
                stats[key] = {"confirmed": 0, "false_positive": 0}
            stats[key][row["triage_status"]] = row["cnt"]
        return stats

    def get_triageable(self) -> list[dict]:
        """Get active findings that haven't been triaged, for the triage UI."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, module, severity, title, detail, path, confidence, "
                "first_seen, last_seen, times_seen, triage_status "
                "FROM findings WHERE resolved = 0 "
                "ORDER BY severity DESC, confidence DESC, last_seen DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    def close(self) -> None:
        self._conn.close()
