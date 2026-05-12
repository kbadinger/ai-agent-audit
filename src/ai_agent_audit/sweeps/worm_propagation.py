"""Detect SANDWORM-style self-replicating agent propagation patterns.

Checks for skills/configs that exhibit worm-like behavior: writing to other
skills directories, auto-installing from untrusted sources, agent-to-agent
propagation indicators, and self-modification patterns.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from ..config import OPENCLAW_CONFIG, OPENCLAW_HOME, OPENCLAW_SKILLS, OPENCLAW_WORKSPACE
from ..models import Finding, ModuleResult, Severity
from .base import BaseSweep

logger = logging.getLogger(__name__)

# Patterns in skill code that indicate worm behavior
_WORM_CODE_PATTERNS = [
    (r"(mkdir|mkdirp?|fs\.mkdir)\s*\(.*skills", "Creates directories in skills folder"),
    (r"(writeFile|write_text|open\(.*['\"]w['\"])\s*.*skills/", "Writes files to skills directory"),
    (r"(cp|copy|copyfile|shutil\.copy)\s*.*skills/", "Copies files into skills directory"),
    (r"(git\s+clone|npm\s+install|pip\s+install)\s+.*skills", "Installs into skills directory"),
    (r"(curl|wget|fetch)\s*.*\|\s*(bash|sh|node|python)", "Pipe-to-shell download pattern"),
    (r"self[_-]?replicate|self[_-]?propagat|auto[_-]?install", "Self-replication keyword"),
    (r"(exec|spawn|fork)\s*\(.*install.*skill", "Exec-based skill installation"),
]

# Patterns in skill metadata suggesting auto-propagation
_METADATA_WORM_PATTERNS = [
    (r"postinstall.*skill", "Post-install hook writes to skills"),
    (r"preinstall.*skill", "Pre-install hook modifies skills"),
    (r"lifecycle.*propagat", "Lifecycle hook with propagation"),
]

# Config patterns that enable worm propagation
_CONFIG_WORM_INDICATORS = [
    ("skills.autoInstall", True, "Auto-install skills from untrusted sources"),
    ("skills.allowRemoteInstall", True, "Remote skill installation enabled"),
    ("skills.trustAllPublishers", True, "All skill publishers trusted"),
]


class WormPropagationSweep(BaseSweep):
    name = "worm_propagation"

    def run(self) -> ModuleResult:
        findings: list[Finding] = []

        self._check_config(findings)
        self._scan_skills(findings)
        self._check_cross_skill_writes(findings)

        return ModuleResult(module_name=self.name, findings=findings)

    def _check_config(self, findings: list[Finding]) -> None:
        """Check openclaw.json for worm-enabling config."""
        if not OPENCLAW_CONFIG.exists():
            return

        try:
            data = json.loads(OPENCLAW_CONFIG.read_text())
        except (json.JSONDecodeError, OSError):
            return

        for key_path, dangerous_value, description in _CONFIG_WORM_INDICATORS:
            parts = key_path.split(".")
            val = data
            for part in parts:
                if isinstance(val, dict):
                    val = val.get(part)
                else:
                    val = None
                    break
            if val == dangerous_value:
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title=f"Worm-enabling config: {key_path}",
                    detail=(
                        f"{description}. {key_path}={dangerous_value} in openclaw.json "
                        f"allows skills to propagate without approval."
                    ),
                    path=str(OPENCLAW_CONFIG),
                ))

    def _scan_skills(self, findings: list[Finding]) -> None:
        """Scan skill source files for worm-like code patterns."""
        if not OPENCLAW_SKILLS.exists():
            return

        for skill_dir in OPENCLAW_SKILLS.iterdir():
            if not skill_dir.is_dir():
                continue

            # Scan JS/TS/Python files in skill
            for ext in ("*.js", "*.ts", "*.py", "*.sh", "*.mjs"):
                for source_file in skill_dir.rglob(ext):
                    # Skip node_modules
                    if "node_modules" in str(source_file):
                        continue
                    try:
                        if source_file.stat().st_size > 500_000:
                            continue
                        content = source_file.read_text(errors="replace")
                    except OSError:
                        continue

                    for pattern, description in _WORM_CODE_PATTERNS:
                        if re.search(pattern, content, re.IGNORECASE):
                            findings.append(Finding(
                                module=self.name,
                                severity=Severity.CRITICAL,
                                title=f"Worm pattern in skill: {description}",
                                detail=(
                                    f"Skill '{skill_dir.name}' file '{source_file.name}' "
                                    f"contains code matching: {description}. "
                                    f"This may indicate self-replicating behavior."
                                ),
                                path=str(source_file),
                            ))

            # Check package.json / skill.json for lifecycle hooks
            for meta_name in ("package.json", "skill.json"):
                meta_path = skill_dir / meta_name
                if not meta_path.exists():
                    continue
                try:
                    content = meta_path.read_text()
                except OSError:
                    continue

                for pattern, description in _METADATA_WORM_PATTERNS:
                    if re.search(pattern, content, re.IGNORECASE):
                        findings.append(Finding(
                            module=self.name,
                            severity=Severity.CRITICAL,
                            title=f"Worm metadata in {meta_name}: {description}",
                            detail=(
                                f"Skill '{skill_dir.name}' metadata contains "
                                f"lifecycle hook matching: {description}."
                            ),
                            path=str(meta_path),
                        ))

    def _check_cross_skill_writes(self, findings: list[Finding]) -> None:
        """Check for skills that reference other skills' directories."""
        if not OPENCLAW_SKILLS.exists():
            return

        skill_names = [d.name for d in OPENCLAW_SKILLS.iterdir() if d.is_dir()]
        if len(skill_names) < 2:
            return

        for skill_dir in OPENCLAW_SKILLS.iterdir():
            if not skill_dir.is_dir():
                continue

            other_skills = [n for n in skill_names if n != skill_dir.name]

            for ext in ("*.js", "*.ts", "*.py", "*.sh", "*.mjs"):
                for source_file in skill_dir.rglob(ext):
                    if "node_modules" in str(source_file):
                        continue
                    try:
                        if source_file.stat().st_size > 500_000:
                            continue
                        content = source_file.read_text(errors="replace")
                    except OSError:
                        continue

                    for other_name in other_skills:
                        # Look for references to other skill directories
                        if re.search(
                            rf"skills/{re.escape(other_name)}",
                            content,
                        ):
                            findings.append(Finding(
                                module=self.name,
                                severity=Severity.WARNING,
                                title=f"Cross-skill reference: {skill_dir.name} -> {other_name}",
                                detail=(
                                    f"Skill '{skill_dir.name}' references another "
                                    f"skill's directory '{other_name}'. This could "
                                    f"indicate lateral propagation between skills."
                                ),
                                path=str(source_file),
                            ))
