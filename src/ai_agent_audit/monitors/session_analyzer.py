"""Monitor agent session JSONL files for injection and exfiltration patterns."""

from __future__ import annotations

import base64
import json
import logging
import re
import threading
import time
import unicodedata
from collections import deque
from pathlib import Path

from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent
from watchdog.observers import Observer

from ..config import (
    ACTIVE_PROFILE,
    EXFIL_PATTERNS,
    INJECTION_PATTERNS,
    OPENCLAW_AGENTS,
)
from ..models import Finding, Severity
from .base import BaseMonitor

logger = logging.getLogger(__name__)

# Tool calls considered dangerous
_DANGEROUS_TOOLS = {"exec", "bash", "shell", "process", "run_command"}
_DANGEROUS_TOOL_PREFIXES = ("filesystem-write", "browser")

# Sensitive paths that tool calls should not touch.
# The active-agent home dir is added so this matches ~/.openclaw, ~/.hermes, etc.
_SENSITIVE_PATHS = (
    "/.ssh/", "/.env", "/etc/passwd", "/etc/shadow",
    "/credentials", "/id_rsa", "/id_ed25519",
    f"/.{ACTIVE_PROFILE.slug}/credentials",
)

# Rate-limit constants
_FLOOD_THRESHOLD = 30          # messages per minute
_SUSTAINED_INJECTION_COUNT = 5 # injection hits in 5 minutes
_SUSTAINED_INJECTION_WINDOW = 300  # seconds

# Social engineering patterns (ASI09) — agent outputs manipulating humans
_SOCIAL_ENGINEERING_PATTERNS = [
    (re.compile(r"(?i)(you must|you need to|you have to|it is essential that you|failure to)\s+(immediately|urgently|right now|without delay)"),
     "Urgency manipulation"),
    (re.compile(r"(?i)(as your (AI|assistant|agent|system)|I have authority|I am authorized|by (company|organization|admin) policy)"),
     "False authority claim"),
    (re.compile(r"(?i)(don'?t tell anyone|keep this (secret|private|between us)|do not share|confidential between)"),
     "Secrecy pressure"),
    (re.compile(r"(?i)(disable (security|firewall|antivirus|protection)|turn off (2fa|mfa|authentication)|remove.*password)"),
     "Security disabling request"),
    (re.compile(r"(?i)(paste (this|the following) into (terminal|console|shell)|run this command|execute the following).*\b(curl|wget|bash|sh|sudo)\b"),
     "Dangerous command coaching"),
    (re.compile(r"(?i)(I ('?m |am )feeling|I understand your (concern|worry)|trust me|I promise|believe me)"),
     "Anthropomorphic trust exploitation"),
]

# Patterns for premise-shifting / role language
_ROLE_PATTERNS = re.compile(
    r"(?i)(you are now|act as|your new role|from now on you|"
    r"switch to|assume the identity|your purpose is|"
    r"you must obey|your real instructions)",
)

# Context-establishing language (precedes premise shift)
_CONTEXT_PATTERNS = re.compile(
    r"(?i)(let me explain|for context|background|"
    r"first, understand|to clarify|here is the situation)",
)


def _is_injection_related(line: str) -> bool:
    """Check if a line matches any injection pattern."""
    for rule in INJECTION_PATTERNS:
        if re.search(rule["pattern"], line):
            return True
    return False


def _check_base64(text: str) -> str | None:
    """Find and validate base64-encoded content >50 chars in text."""
    for match in re.finditer(r'[A-Za-z0-9+/=]{50,}', text):
        candidate = match.group()
        # Must have valid padding
        if len(candidate) % 4 != 0:
            continue
        try:
            decoded = base64.b64decode(candidate)
            # Check if mostly printable ASCII
            if all(32 <= b < 127 or b in (9, 10, 13) for b in decoded):
                return "base64"
        except Exception:
            continue
    return None


def _check_hex(text: str) -> str | None:
    """Detect hex-encoded content in text."""
    # \x escape sequences
    if re.search(r'(\\x[0-9a-fA-F]{2}){10,}', text):
        return "hex_escape"
    # 0x prefixed long hex
    if re.search(r'0x[0-9a-fA-F]{20,}', text):
        return "hex_literal"
    # Plain long hex string (only flag if it looks intentional - even length)
    m = re.search(r'(?<![a-zA-Z])[0-9a-fA-F]{40,}(?![a-zA-Z])', text)
    if m and len(m.group()) % 2 == 0:
        return "hex_string"
    return None


def _check_unicode_obfuscation(text: str) -> bool:
    """Detect unusual unicode categories that suggest obfuscation."""
    suspicious_count = 0
    for ch in text:
        cat = unicodedata.category(ch)
        # Combining marks, format chars, look-alike categories
        if cat.startswith("M") or cat == "Cf" or cat == "Cn":
            suspicious_count += 1
            if suspicious_count >= 5:
                return True
    return False


def _is_dangerous_tool(entry: dict) -> str | None:
    """Check if a parsed JSON entry is a dangerous tool call. Returns tool name or None."""
    # Look for tool_use or tool_call entries
    entry_type = entry.get("type", "")
    if entry_type not in ("tool_use", "tool_call"):
        # Check nested content
        content = entry.get("content")
        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict):
                    result = _is_dangerous_tool(item)
                    if result:
                        return result
        return None

    tool_name = entry.get("name", entry.get("function", {}).get("name", "")).lower()

    # Check direct dangerous tools
    if tool_name in _DANGEROUS_TOOLS:
        return tool_name
    for prefix in _DANGEROUS_TOOL_PREFIXES:
        if tool_name.startswith(prefix):
            return tool_name

    # Check arguments for sensitive paths
    args = entry.get("input", entry.get("arguments", {}))
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except (json.JSONDecodeError, TypeError):
            args_str = args
            for sp in _SENSITIVE_PATHS:
                if sp in args_str:
                    return f"{tool_name} (sensitive path: {sp})"
            return None
    if isinstance(args, dict):
        args_str = json.dumps(args)
        for sp in _SENSITIVE_PATHS:
            if sp in args_str:
                return f"{tool_name} (sensitive path: {sp})"

    return None


class _FileState:
    """Per-file tracking state."""
    __slots__ = (
        "offset", "window", "tool_count_window", "injection_timestamps",
        "msg_timestamps",
    )

    def __init__(self) -> None:
        self.offset: int = 0
        self.window: deque[str] = deque(maxlen=20)
        self.tool_count_window: deque[float] = deque()  # timestamps of tool_use entries
        self.injection_timestamps: deque[float] = deque()  # timestamps of injection hits
        self.msg_timestamps: deque[float] = deque()  # timestamps for rate limiting


class _SessionHandler(FileSystemEventHandler):
    def __init__(self, monitor: SessionAnalyzer):
        self._monitor = monitor

    def on_modified(self, event: FileModifiedEvent) -> None:  # type: ignore[override]
        if event.src_path.endswith(".jsonl"):
            self._monitor._scan_file(Path(event.src_path))

    def on_created(self, event: FileCreatedEvent) -> None:  # type: ignore[override]
        if event.src_path.endswith(".jsonl"):
            self._monitor._scan_file(Path(event.src_path))


class SessionAnalyzer(BaseMonitor):
    """Scans session JSONL files for prompt injection and data exfiltration."""

    name = "session_analyzer"

    def __init__(self, on_finding, agents_dir: Path | None = None):
        super().__init__(on_finding)
        self._agents_dir = agents_dir or OPENCLAW_AGENTS
        self._file_states: dict[str, _FileState] = {}
        self._lock = threading.Lock()
        self._observer: Observer | None = None

    def start(self) -> None:
        self._running.set()

        if not self._agents_dir.exists():
            logger.warning(
                "Agents directory %s does not exist, skipping session analyzer",
                self._agents_dir,
            )
            return

        # Initial scan of existing files
        for jsonl in self._agents_dir.rglob("*.jsonl"):
            self._scan_file(jsonl)

        self._observer = Observer()
        self._observer.schedule(
            _SessionHandler(self), str(self._agents_dir), recursive=True,
        )
        self._observer.daemon = True
        self._observer.start()

    def stop(self) -> None:
        self._running.clear()
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None

    def _get_state(self, path_str: str) -> _FileState:
        """Get or create per-file state."""
        state = self._file_states.get(path_str)
        if state is None:
            state = _FileState()
            self._file_states[path_str] = state
        return state

    def _scan_file(self, path: Path) -> None:
        """Read new lines from a JSONL file (incremental)."""
        path_str = str(path)

        try:
            size = path.stat().st_size
        except OSError:
            return

        with self._lock:
            state = self._get_state(path_str)

            # Handle file truncation/rotation
            if size < state.offset:
                state.offset = 0
                state.window.clear()

            if size <= state.offset:
                return

            try:
                with open(path, "r", errors="replace") as f:
                    f.seek(state.offset)
                    new_data = f.read()
                    state.offset = f.tell()
            except OSError:
                return

        now = time.time()
        lines = new_data.splitlines()
        tool_count_in_chunk = 0

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue

            state.window.append(stripped)
            state.msg_timestamps.append(now)

            # Try to parse as JSON
            parsed = None
            try:
                parsed = json.loads(stripped)
            except (json.JSONDecodeError, ValueError):
                pass

            text_to_check = stripped

            # --- Existing injection pattern checks ---
            injection_hit = False
            for rule in INJECTION_PATTERNS:
                if re.search(rule["pattern"], text_to_check):
                    injection_hit = True
                    self.report_finding(Finding(
                        module=self.name,
                        severity=Severity.CRITICAL,
                        title=f"Prompt injection: {rule['name']}",
                        detail=f"Matched in {path.name} (offset ~{state.offset}): {rule['name']}",
                        path=path_str,
                    ))

            # --- Existing exfiltration pattern checks ---
            for rule in EXFIL_PATTERNS:
                if re.search(rule["pattern"], text_to_check):
                    self.report_finding(Finding(
                        module=self.name,
                        severity=Severity.CRITICAL,
                        title=f"Exfiltration attempt: {rule['name']}",
                        detail=f"Matched in {path.name} (offset ~{state.offset}): {rule['name']}",
                        path=path_str,
                    ))

            # --- Multi-turn injection tracking ---
            if injection_hit:
                state.injection_timestamps.append(now)

            injection_lines_in_window = sum(
                1 for w in state.window if _is_injection_related(w)
            )
            if injection_lines_in_window >= 3:
                self.report_finding(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title="Multi-turn injection chain detected",
                    detail=(
                        f"{injection_lines_in_window} injection-related patterns "
                        f"in last {len(state.window)} lines of {path.name}"
                    ),
                    path=path_str,
                ))

            # --- Social engineering detection (ASI09) ---
            for se_pattern, se_name in _SOCIAL_ENGINEERING_PATTERNS:
                if se_pattern.search(text_to_check):
                    self.report_finding(Finding(
                        module=self.name,
                        severity=Severity.WARNING,
                        title=f"Social engineering pattern: {se_name}",
                        detail=(
                            f"Agent output in {path.name} matches social engineering "
                            f"pattern: {se_name}. May be manipulating human trust."
                        ),
                        path=path_str,
                    ))

            # --- Premise shifting detection ---
            if _ROLE_PATTERNS.search(text_to_check):
                # Check if context-establishing language appeared earlier in window
                for earlier in list(state.window)[:-1]:
                    if _CONTEXT_PATTERNS.search(earlier):
                        self.report_finding(Finding(
                            module=self.name,
                            severity=Severity.CRITICAL,
                            title="Premise shifting detected",
                            detail=(
                                f"Role/identity language after context establishment "
                                f"in {path.name}"
                            ),
                            path=path_str,
                        ))
                        break

            # --- Encoding bypass detection ---
            b64_type = _check_base64(text_to_check)
            if b64_type:
                self.report_finding(Finding(
                    module=self.name,
                    severity=Severity.WARNING,
                    title=f"Encoded content in session: {b64_type}",
                    detail=f"Base64-encoded content found in {path.name}",
                    path=path_str,
                ))

            hex_type = _check_hex(text_to_check)
            if hex_type:
                self.report_finding(Finding(
                    module=self.name,
                    severity=Severity.WARNING,
                    title=f"Encoded content in session: {hex_type}",
                    detail=f"Hex-encoded content found in {path.name}",
                    path=path_str,
                ))

            if _check_unicode_obfuscation(text_to_check):
                self.report_finding(Finding(
                    module=self.name,
                    severity=Severity.WARNING,
                    title="Encoded content in session: unicode_obfuscation",
                    detail=f"Suspicious unicode characters in {path.name}",
                    path=path_str,
                ))

            # --- Tool call abuse monitoring ---
            if parsed and isinstance(parsed, dict):
                is_tool = (
                    parsed.get("type") in ("tool_use", "tool_call")
                    or "tool_use" in str(parsed.get("type", ""))
                    or "tool_call" in str(parsed.get("type", ""))
                )
                if is_tool:
                    tool_count_in_chunk += 1
                    state.tool_count_window.append(now)

                dangerous = _is_dangerous_tool(parsed)
                if dangerous:
                    self.report_finding(Finding(
                        module=self.name,
                        severity=Severity.CRITICAL,
                        title=f"Dangerous tool call: {dangerous}",
                        detail=f"Tool call to '{dangerous}' in {path.name}",
                        path=path_str,
                    ))

        # --- Post-chunk checks ---

        # Rapid tool execution: >10 tool_use entries in last 20 lines
        # We track via the window - count tool entries in it
        tool_in_window = 0
        for w in state.window:
            try:
                p = json.loads(w)
                if isinstance(p, dict) and p.get("type") in ("tool_use", "tool_call"):
                    tool_in_window += 1
            except (json.JSONDecodeError, ValueError):
                pass
        if tool_in_window > 10:
            self.report_finding(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title="Rapid tool execution",
                detail=f"{tool_in_window} tool calls in last {len(state.window)} lines of {path.name}",
                path=path_str,
            ))

        # Rate limiting: message flood (>30 messages/minute)
        one_min_ago = now - 60
        # Prune old timestamps
        while state.msg_timestamps and state.msg_timestamps[0] < one_min_ago:
            state.msg_timestamps.popleft()
        if len(state.msg_timestamps) > _FLOOD_THRESHOLD:
            self.report_finding(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title="Message flood detected",
                detail=f"{len(state.msg_timestamps)} messages in last minute for {path.name}",
                path=path_str,
            ))

        # Sustained injection attack (>5 injection hits in 5 minutes)
        cutoff = now - _SUSTAINED_INJECTION_WINDOW
        while state.injection_timestamps and state.injection_timestamps[0] < cutoff:
            state.injection_timestamps.popleft()
        if len(state.injection_timestamps) > _SUSTAINED_INJECTION_COUNT:
            self.report_finding(Finding(
                module=self.name,
                severity=Severity.CRITICAL,
                title="Sustained injection attack",
                detail=(
                    f"{len(state.injection_timestamps)} injection pattern matches "
                    f"in last 5 minutes for {path.name}"
                ),
                path=path_str,
            ))
