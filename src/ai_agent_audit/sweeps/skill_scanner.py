"""Scan installed skills for malicious content using the IOC database."""

from __future__ import annotations

import base64
import json
import logging
import os
import re
from pathlib import Path

from .. import ioc
from ..ioc import record_ioc_match
from ..config import OPENCLAW_SKILLS
from ..models import Finding, ModuleResult, Severity
from .base import BaseSweep

logger = logging.getLogger(__name__)

# Shell commands that are suspicious in SKILL.md Prerequisites/Install sections
_SHELL_COMMANDS = re.compile(
    r"(?:curl|wget|pip\s+install|brew\s+install|npm\s+install|npx)\s+",
    re.IGNORECASE,
)

# Base64 strings longer than 50 chars
_BASE64_LONG = re.compile(r"[A-Za-z0-9+/]{50,}={0,2}")

# Binary download references
_BINARY_DOWNLOAD = re.compile(
    r"\.(exe|dmg|pkg|zip)\b.*password|\bpassword\b.*\.(exe|dmg|pkg|zip)",
    re.IGNORECASE,
)

# Section header pattern for SKILL.md
_SECTION_HEADER = re.compile(r"^#+\s+(.+)", re.MULTILINE)


def _read_skill_metadata(skill_dir: Path) -> dict:
    """Read skill metadata from skill.json or package.json."""
    for name in ("skill.json", "package.json"):
        meta_path = skill_dir / name
        if meta_path.exists():
            try:
                return json.loads(meta_path.read_text())
            except (json.JSONDecodeError, OSError):
                continue
    return {}


class SkillScannerSweep(BaseSweep):
    name = "skill_scanner"

    def run(self) -> ModuleResult:
        findings: list[Finding] = []

        if not OPENCLAW_SKILLS.exists():
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title="Skills directory not found",
                detail=f"{OPENCLAW_SKILLS} does not exist.",
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        try:
            skill_dirs = [
                d for d in OPENCLAW_SKILLS.iterdir() if d.is_dir()
            ]
        except OSError as exc:
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title="Cannot read skills directory",
                detail=str(exc),
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        for skill_dir in skill_dirs:
            skill_name = skill_dir.name
            self._check_skill_name(skill_name, skill_dir, findings)
            self._check_skill_metadata(skill_dir, findings)
            self._scan_skill_files(skill_dir, findings)

        return ModuleResult(module_name=self.name, findings=findings)

    def _check_skill_name(self, skill_name: str, skill_dir: Path, findings: list[Finding]) -> None:
        """Check skill name against malicious patterns."""
        for pattern in ioc.MALICIOUS_SKILL_PATTERNS:
            if re.search(pattern, skill_name, re.IGNORECASE):
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title=f"Malicious skill name pattern: {skill_name}",
                    detail=f"Skill name matches known malicious pattern: {pattern}",
                    path=str(skill_dir),
                ))
                return

        for category, patterns in ioc.SUSPICIOUS_SKILL_CATEGORIES.items():
            for pattern in patterns:
                if re.search(pattern, skill_name, re.IGNORECASE):
                    findings.append(Finding(
                        module=self.name,
                        severity=Severity.WARNING,
                        title=f"Suspicious skill name ({category}): {skill_name}",
                        detail=f"Skill name matches suspicious category '{category}': {pattern}",
                        path=str(skill_dir),
                    ))
                    return

    def _check_skill_metadata(self, skill_dir: Path, findings: list[Finding]) -> None:
        """Check skill metadata for malicious publishers."""
        meta = _read_skill_metadata(skill_dir)
        publisher = meta.get("publisher") or meta.get("author", "")
        if isinstance(publisher, dict):
            publisher = publisher.get("name", "")
        publisher = str(publisher).strip()

        for pub, reason in ioc.MALICIOUS_PUBLISHERS.items():
            if pub.lower() in publisher.lower():
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title=f"Malicious publisher: {publisher}",
                    detail=f"Known malicious publisher ({reason})",
                    path=str(skill_dir),
                ))
                return

    def _scan_skill_files(self, skill_dir: Path, findings: list[Finding]) -> None:
        """Scan all files in a skill directory for IOC matches."""
        for root, _dirs, files in os.walk(skill_dir):
            for fname in files:
                fpath = Path(root) / fname
                try:
                    content = fpath.read_text(errors="ignore")
                except OSError:
                    continue

                self._check_content(content, fpath, findings)

                # SKILL.md shell injection check
                if fname.upper() == "SKILL.MD":
                    self._check_skill_md(content, fpath, findings)

    def _check_content(self, content: str, fpath: Path, findings: list[Finding]) -> None:
        """Check file content against IOC patterns."""
        # C2 IPs
        for ip in ioc.C2_IPS:
            if ip in content:
                record_ioc_match(ip)
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title=f"C2 IP address found: {ip}",
                    detail=f"Known command-and-control IP detected in file.",
                    path=str(fpath),
                ))

        # AMOS indicators
        for pattern in ioc.AMOS_INDICATORS:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title="AMOS stealer indicator",
                    detail=f"Pattern matched: {pattern}",
                    path=str(fpath),
                ))

        # Reverse shell patterns
        for rs in ioc.REVERSE_SHELL_PATTERNS:
            if re.search(rs["pattern"], content, re.IGNORECASE):
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title=f"Reverse shell pattern: {rs['name']}",
                    detail=f"Pattern matched: {rs['pattern']}",
                    path=str(fpath),
                ))

        # Exfil domains
        for domain in ioc.EXFIL_DOMAINS:
            if domain in content:
                record_ioc_match(domain)
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title=f"Exfiltration domain found: {domain}",
                    detail=f"Known exfil/malicious domain detected in file.",
                    path=str(fpath),
                ))

        # Base64 obfuscation
        for match in _BASE64_LONG.finditer(content):
            findings.append(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title="Base64-encoded string detected",
                detail=f"Long base64 string ({len(match.group())} chars) may indicate obfuscation.",
                path=str(fpath),
            ))

        # Binary download references
        if _BINARY_DOWNLOAD.search(content):
            findings.append(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title="Binary download with password reference",
                detail="References to downloadable binary with password protection.",
                path=str(fpath),
            ))

    def _check_skill_md(self, content: str, fpath: Path, findings: list[Finding]) -> None:
        """Check SKILL.md for shell commands in Prerequisites/Install sections."""
        in_install_section = False
        for line in content.splitlines():
            header_match = _SECTION_HEADER.match(line)
            if header_match:
                section = header_match.group(1).strip().lower()
                in_install_section = any(
                    kw in section for kw in ("prerequisit", "install", "setup", "getting started")
                )
                continue

            if in_install_section and _SHELL_COMMANDS.search(line):
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.WARNING,
                    title="Shell command in SKILL.md install section",
                    detail=f"Potentially dangerous command: {line.strip()[:200]}",
                    path=str(fpath),
                ))
