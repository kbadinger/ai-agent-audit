"""Detect hidden Unicode/zero-width character injection in agent configuration files.

Scans CLAUDE.md, SKILL.md, MCP configs, rules files, and memory files for
invisible characters that can hide malicious instructions from human reviewers.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ..config import (
    MEMORY_FILES,
    OPENCLAW_HOME,
    OPENCLAW_MCP_CONFIG,
    OPENCLAW_SKILLS,
    OPENCLAW_WORKSPACE,
)
from ..models import Finding, ModuleResult, Severity
from .base import BaseSweep

logger = logging.getLogger(__name__)

# Dangerous Unicode characters and ranges
_INVISIBLE_CHARS = {
    "\u200b": "Zero-Width Space",
    "\u200c": "Zero-Width Non-Joiner",
    "\u200d": "Zero-Width Joiner",
    "\u2060": "Word Joiner",
    "\ufeff": "Zero-Width No-Break Space (BOM)",
    "\u00ad": "Soft Hyphen",
    "\u034f": "Combining Grapheme Joiner",
    "\u061c": "Arabic Letter Mark",
    "\u180e": "Mongolian Vowel Separator",
}

# Bidirectional override characters (can reverse text display)
_BIDI_CHARS = {
    "\u200e": "Left-To-Right Mark",
    "\u200f": "Right-To-Left Mark",
    "\u202a": "Left-To-Right Embedding",
    "\u202b": "Right-To-Left Embedding",
    "\u202c": "Pop Directional Formatting",
    "\u202d": "Left-To-Right Override",
    "\u202e": "Right-To-Left Override",
    "\u2066": "Left-To-Right Isolate",
    "\u2067": "Right-To-Left Isolate",
    "\u2068": "First Strong Isolate",
    "\u2069": "Pop Directional Isolate",
}

# Tag characters (U+E0001-U+E007F) — invisible text in Unicode tag space
_TAG_RANGE = range(0xE0001, 0xE0080)

# Homoglyph patterns — characters that look like ASCII but aren't
_HOMOGLYPH_PAIRS = {
    "\u0430": ("a", "Cyrillic Small A"),
    "\u0435": ("e", "Cyrillic Small IE"),
    "\u043e": ("o", "Cyrillic Small O"),
    "\u0440": ("p", "Cyrillic Small ER"),
    "\u0441": ("c", "Cyrillic Small ES"),
    "\u0443": ("y", "Cyrillic Small U"),
    "\u0445": ("x", "Cyrillic Small HA"),
    "\u0455": ("s", "Cyrillic Small DZE"),
    "\u0456": ("i", "Cyrillic Small Byelorussian-Ukrainian I"),
    "\u04bb": ("h", "Cyrillic Small Shha"),
    "\uff41": ("a", "Fullwidth Latin Small A"),
    "\uff45": ("e", "Fullwidth Latin Small E"),
}

# Files to scan in workspace/home
_CONFIG_FILES = [
    "CLAUDE.md", "AGENTS.md", "GEMINI.md",
    "openclaw.json", "config.yaml", "mcp.json",
    "exec-approvals.json",
]

# Max file size to scan (skip huge files)
_MAX_FILE_SIZE = 1_000_000  # 1MB


class UnicodeInjectionSweep(BaseSweep):
    name = "unicode_injection"

    def run(self) -> ModuleResult:
        findings: list[Finding] = []

        # Scan config files in OPENCLAW_HOME
        for name in _CONFIG_FILES:
            path = OPENCLAW_HOME / name
            if path.exists():
                self._scan_file(path, findings)

        # Scan memory files
        for mem_name in MEMORY_FILES:
            for base in dict.fromkeys((OPENCLAW_HOME, OPENCLAW_WORKSPACE)):
                path = base / mem_name
                if path.exists():
                    self._scan_file(path, findings)
        memories = OPENCLAW_WORKSPACE / "memories"
        if memories.is_dir():
            for path in memories.rglob("*.md"):
                self._scan_file(path, findings)

        # Scan MCP config
        if OPENCLAW_MCP_CONFIG.exists() and OPENCLAW_MCP_CONFIG.name not in _CONFIG_FILES:
            self._scan_file(OPENCLAW_MCP_CONFIG, findings)

        # Scan skill files (SKILL.md, skill.json, package.json)
        if OPENCLAW_SKILLS.exists():
            for skill_dir in OPENCLAW_SKILLS.iterdir():
                if not skill_dir.is_dir():
                    continue
                for name in ("SKILL.md", "skill.json", "package.json", "README.md"):
                    path = skill_dir / name
                    if path.exists():
                        self._scan_file(path, findings)

        return ModuleResult(module_name=self.name, findings=findings)

    def _scan_file(self, path: Path, findings: list[Finding]) -> None:
        """Scan a single file for hidden Unicode characters."""
        try:
            size = path.stat().st_size
            if size > _MAX_FILE_SIZE:
                return
            content = path.read_text(errors="replace")
        except OSError:
            return

        file_str = str(path)

        # Check for invisible characters
        for char, name in _INVISIBLE_CHARS.items():
            count = content.count(char)
            if count > 0:
                # Find line numbers
                lines_with = []
                for i, line in enumerate(content.splitlines(), 1):
                    if char in line:
                        lines_with.append(i)
                        if len(lines_with) >= 5:
                            break
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title=f"Hidden Unicode: {name} in {path.name}",
                    detail=(
                        f"Found {count} instance(s) of {name} (U+{ord(char):04X}) "
                        f"in {path.name}. Lines: {lines_with}. "
                        f"Invisible characters can hide malicious instructions."
                    ),
                    path=file_str,
                ))

        # Check for bidirectional overrides
        for char, name in _BIDI_CHARS.items():
            if char in content:
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title=f"Bidi override: {name} in {path.name}",
                    detail=(
                        f"Bidirectional text override character {name} "
                        f"(U+{ord(char):04X}) found in {path.name}. "
                        f"Can reverse displayed text to hide true content."
                    ),
                    path=file_str,
                ))

        # Check for Unicode tag characters
        tag_count = sum(1 for ch in content if ord(ch) in _TAG_RANGE)
        if tag_count > 0:
            findings.append(Finding(
                module=self.name,
                severity=Severity.CRITICAL,
                title=f"Unicode tag characters in {path.name}",
                detail=(
                    f"Found {tag_count} Unicode tag character(s) (U+E0001-U+E007F) "
                    f"in {path.name}. These are invisible and can encode hidden text."
                ),
                path=file_str,
            ))

        # Check for homoglyphs in keyword contexts
        # Only flag if mixed scripts are used (e.g., Cyrillic 'a' mixed with Latin)
        has_latin = bool(re.search(r'[a-zA-Z]', content))
        if has_latin:
            for char, (looks_like, name) in _HOMOGLYPH_PAIRS.items():
                if char in content:
                    findings.append(Finding(
                        module=self.name,
                        severity=Severity.WARNING,
                        title=f"Homoglyph detected: {name} in {path.name}",
                        detail=(
                            f"{name} (U+{ord(char):04X}) looks identical to "
                            f"Latin '{looks_like}' but is a different character. "
                            f"Mixed scripts may indicate spoofing."
                        ),
                        path=file_str,
                    ))
