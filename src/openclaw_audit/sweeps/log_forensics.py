"""Log forensics: crash loops, auth failures, leaked secrets, tampering."""

from __future__ import annotations

import logging
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from ..config import OPENCLAW_LOG_DIR, SECRET_PATTERNS
from ..models import Finding, ModuleResult, Severity
from .base import BaseSweep

logger = logging.getLogger(__name__)

# Patterns for log analysis
AUTH_FAIL_PATTERN = re.compile(
    r"(?i)(auth(entication)?\s+(fail|error|denied)|"
    r"unauthorized|invalid\s+(token|credential|password)|"
    r"access\s+denied|login\s+fail)"
)

# ISO-style or common log timestamp at start of line
TIMESTAMP_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"
)

ERROR_PATTERN = re.compile(r"(?i)\b(ERROR|FATAL|EXCEPTION|TRACEBACK)\b")


def _parse_timestamp(line: str) -> datetime | None:
    m = TIMESTAMP_PATTERN.match(line)
    if not m:
        return None
    raw = m.group(1).replace("T", " ")
    try:
        return datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


class LogForensicsSweep(BaseSweep):
    name = "log_forensics"

    def run(self) -> ModuleResult:
        findings: list[Finding] = []

        if not OPENCLAW_LOG_DIR.exists():
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title="Log directory not found",
                detail=f"{OPENCLAW_LOG_DIR} does not exist.",
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        log_files = sorted(OPENCLAW_LOG_DIR.glob("openclaw-*.log"))
        if not log_files:
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title="No log files found",
                detail=f"No openclaw-*.log files in {OPENCLAW_LOG_DIR}.",
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        compiled_secrets = {
            name: re.compile(pat) for name, pat in SECRET_PATTERNS.items()
        }

        for log_file in log_files:
            self._scan_log_file(log_file, compiled_secrets, findings)

        return ModuleResult(module_name=self.name, findings=findings)

    def _scan_log_file(
        self,
        log_file: Path,
        secret_patterns: dict[str, re.Pattern],
        findings: list[Finding],
    ) -> None:
        try:
            # Check for truncated file (non-empty file that doesn't end with newline)
            size = log_file.stat().st_size
            if size == 0:
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.WARNING,
                    title="Empty log file",
                    detail="Log file exists but is empty (possible truncation).",
                    path=str(log_file),
                ))
                return

            lines = log_file.read_text(errors="replace").splitlines()
        except OSError:
            return

        # Track errors for crash-loop detection: {error_msg: [timestamps]}
        error_occurrences: defaultdict[str, list[datetime]] = defaultdict(list)
        prev_ts: datetime | None = None
        auth_fail_count = 0

        for line_num, line in enumerate(lines, 1):
            ts = _parse_timestamp(line)

            # Timestamp gap detection (>1 hour gap between consecutive timestamps)
            if ts and prev_ts and ts > prev_ts:
                gap = ts - prev_ts
                if gap > timedelta(hours=1):
                    findings.append(Finding(
                        module=self.name,
                        severity=Severity.WARNING,
                        title="Timestamp gap in logs",
                        detail=(
                            f"Gap of {gap} between line timestamps "
                            f"({prev_ts} -> {ts}). Possible tampering."
                        ),
                        path=str(log_file),
                    ))

            # Out-of-order timestamp detection (possible tampering)
            if ts and prev_ts and ts < prev_ts:
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.WARNING,
                    title="Out-of-order timestamp",
                    detail=(
                        f"Line {line_num}: timestamp {ts} is earlier than "
                        f"previous {prev_ts}. Possible log tampering."
                    ),
                    path=str(log_file),
                ))

            if ts:
                prev_ts = ts

            # Secret detection
            for secret_name, pattern in secret_patterns.items():
                if pattern.search(line):
                    findings.append(Finding(
                        module=self.name,
                        severity=Severity.CRITICAL,
                        title="Unredacted secret in logs",
                        detail=f"{secret_name} found at line {line_num}.",
                        path=str(log_file),
                    ))

            # Auth failure detection
            if AUTH_FAIL_PATTERN.search(line):
                auth_fail_count += 1

            # Error tracking for crash loops
            if ERROR_PATTERN.search(line) and ts:
                # Use first 120 chars of the error line as a key
                error_key = line.strip()[:120]
                error_occurrences[error_key].append(ts)

        # Report auth failures
        if auth_fail_count > 0:
            sev = Severity.CRITICAL if auth_fail_count >= 10 else Severity.WARNING
            findings.append(Finding(
                module=self.name,
                severity=sev,
                title="Authentication failures detected",
                detail=f"{auth_fail_count} auth failure(s) found.",
                path=str(log_file),
            ))

        # Detect crash loops: same error >5 times within 1 hour window
        for error_key, timestamps in error_occurrences.items():
            if len(timestamps) < 6:
                continue
            timestamps.sort()
            for i in range(len(timestamps) - 5):
                window = timestamps[i + 5] - timestamps[i]
                if window <= timedelta(hours=1):
                    findings.append(Finding(
                        module=self.name,
                        severity=Severity.CRITICAL,
                        title="Crash loop detected",
                        detail=(
                            f"Error repeated {len(timestamps)} times. "
                            f"Pattern: {error_key[:80]}..."
                        ),
                        path=str(log_file),
                    ))
                    break  # One finding per error pattern

        # Detect selective deletion: large sudden drops in log line density
        # If we see timestamped lines, check for sudden gaps in line count
        # between consecutive timestamped lines (indicates deleted lines)
        timestamped_line_nums: list[int] = []
        for line_num, line in enumerate(lines, 1):
            if _parse_timestamp(line) is not None:
                timestamped_line_nums.append(line_num)
        # If a large block of non-timestamped lines appears between two
        # timestamped lines with very close timestamps, lines may have been
        # selectively removed and replaced
        for i in range(1, len(timestamped_line_nums)):
            gap_lines = timestamped_line_nums[i] - timestamped_line_nums[i - 1]
            if gap_lines > 100:
                ts_before = _parse_timestamp(lines[timestamped_line_nums[i - 1] - 1])
                ts_after = _parse_timestamp(lines[timestamped_line_nums[i] - 1])
                if ts_before and ts_after:
                    time_gap = abs((ts_after - ts_before).total_seconds())
                    # >100 lines apart but <10 seconds of time: suspicious
                    if time_gap < 10:
                        findings.append(Finding(
                            module=self.name,
                            severity=Severity.WARNING,
                            title="Possible selective log deletion",
                            detail=(
                                f"Lines {timestamped_line_nums[i-1]}-{timestamped_line_nums[i]}: "
                                f"{gap_lines} lines span only {time_gap:.0f}s. "
                                f"Content may have been inserted or surrounding lines deleted."
                            ),
                            path=str(log_file),
                        ))

        # Check for truncation: file doesn't end with newline
        try:
            with open(log_file, "rb") as f:
                f.seek(-1, os.SEEK_END)
                last_byte = f.read(1)
                if last_byte != b"\n" and size > 0:
                    findings.append(Finding(
                        module=self.name,
                        severity=Severity.WARNING,
                        title="Possible log truncation",
                        detail="File does not end with a newline.",
                        path=str(log_file),
                    ))
        except OSError:
            pass
