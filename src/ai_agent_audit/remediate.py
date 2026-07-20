"""Auto-remediation engine for common security findings."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import stat
import subprocess
import time
from pathlib import Path

from . import ioc
from .agent_config import AgentConfigError, load_agent_config
from .config import (
    ACTIVE_PROFILE,
    AGENT_SENSITIVE_FILES,
    AUDIT_DIR,
    OPENCLAW_AGENTS,
    OPENCLAW_CONFIG,
    OPENCLAW_CREDENTIALS,
    OPENCLAW_ENV,
    OPENCLAW_EXEC_APPROVALS,
    OPENCLAW_EXTENSIONS,
    OPENCLAW_HOME,
    OPENCLAW_SKILLS,
)

logger = logging.getLogger(__name__)

_REMEDIATION_LOG = AUDIT_DIR / "remediation.log"
_QUARANTINE_DIR = AUDIT_DIR / "quarantine"
_BACKUP_DIR = AUDIT_DIR / "backups"

# Paths that should be mode 700 (directories)
_DIR_700: list[Path] = [OPENCLAW_HOME, OPENCLAW_CREDENTIALS, OPENCLAW_EXTENSIONS]

# Paths that should be mode 600 (files)
_FILE_600: list[Path] = [OPENCLAW_CONFIG, OPENCLAW_ENV, *AGENT_SENSITIVE_FILES]

# Additional files checked if they exist
_OPTIONAL_FILE_600: list[Path] = [
    OPENCLAW_EXEC_APPROVALS,
]

# Agent auth-profiles files (glob pattern relative to OPENCLAW_HOME)
_AUTH_PROFILE_GLOB = "agents/*/agent/auth-profiles.json"


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


class RemediationEngine:
    """Auto-fix common security findings."""

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.actions: list[dict] = []

    def run_all(self) -> list[dict]:
        """Run all remediation checks and return actions taken."""
        self._fix_permissions()
        self._fix_config()
        self._remove_malicious_skills()
        self._write_log()
        return self.actions

    # --- Permission fixes ---

    def _fix_permissions(self) -> None:
        """Fix file/directory permissions -- only tighten, never loosen."""
        for dirpath in _DIR_700:
            self._tighten(dirpath, 0o700)

        for filepath in _FILE_600:
            self._tighten(filepath, 0o600)

        for filepath in _OPTIONAL_FILE_600:
            if filepath.exists():
                self._tighten(filepath, 0o600)

        # Auth profile files
        for auth_file in OPENCLAW_HOME.glob(_AUTH_PROFILE_GLOB):
            self._tighten(auth_file, 0o600)

        # All files inside credentials/
        if OPENCLAW_CREDENTIALS.is_dir():
            for child in OPENCLAW_CREDENTIALS.iterdir():
                if child.is_file():
                    self._tighten(child, 0o600)

        # Session transcript files (contain API keys, conversation data)
        if OPENCLAW_AGENTS.is_dir():
            for session_file in OPENCLAW_AGENTS.glob("*/sessions/*.jsonl"):
                self._tighten(session_file, 0o600)

    def _tighten(self, path: Path, target: int) -> None:
        """Set permissions on *path* to *target* if currently looser."""
        if not path.exists():
            return
        try:
            current = stat.S_IMODE(path.stat().st_mode)
        except OSError:
            return

        # "looser" means the file grants bits that the target does not
        extra_bits = current & ~target
        if not extra_bits:
            return  # already tight enough

        detail = f"{path}: {oct(current)} -> {oct(target)}"
        if self.dry_run:
            self._log_action("fix_permission", detail, applied=False)
        else:
            try:
                os.chmod(path, target)
                self._log_action("fix_permission", detail, applied=True)
            except OSError as exc:
                self._log_action("fix_permission", f"{detail} FAILED: {exc}", applied=False)

    # --- Config hardening ---

    def _fix_config(self) -> None:
        """Delegate config changes to the agent's current native fixer.

        The project no longer rewrites cloned OpenClaw/Hermes schema fields.
        A validated backup is retained and restored if the native command fails
        or produces an unreadable configuration.
        """
        if not OPENCLAW_CONFIG.exists():
            return

        try:
            load_agent_config(OPENCLAW_CONFIG)
        except AgentConfigError as exc:
            self._log_action("fix_config", f"Cannot read config: {exc}", applied=False)
            return

        command = ACTIVE_PROFILE.native_fix_command
        if not command:
            self._log_action(
                "fix_config",
                f"{ACTIVE_PROFILE.display_name} has no supported native config fixer; no config changes made",
                applied=False,
            )
            return
        if self.dry_run:
            self._log_action(
                "fix_config",
                f"Would run schema-aware native fixer: {' '.join(command)}",
                applied=False,
            )
            return

        try:
            _BACKUP_DIR.mkdir(parents=True, exist_ok=True)
            backup = _BACKUP_DIR / f"{OPENCLAW_CONFIG.name}.{time.time_ns()}.bak"
            shutil.copy2(OPENCLAW_CONFIG, backup)
            completed = subprocess.run(
                list(command), capture_output=True, text=True, timeout=120,
            )
            if completed.returncode != 0:
                shutil.copy2(backup, OPENCLAW_CONFIG)
                detail = completed.stderr.strip() or completed.stdout.strip()
                self._log_action(
                    "fix_config",
                    f"Native fixer failed; restored {backup.name}: {detail[:300]}",
                    applied=False,
                )
                return
            try:
                load_agent_config(OPENCLAW_CONFIG)
            except AgentConfigError as exc:
                shutil.copy2(backup, OPENCLAW_CONFIG)
                self._log_action(
                    "fix_config",
                    f"Native fixer produced invalid config; restored {backup.name}: {exc}",
                    applied=False,
                )
                return
            self._log_action(
                "fix_config",
                f"Native schema-aware fixer completed; backup: {backup}",
                applied=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            self._log_action("fix_config", f"Native fixer unavailable: {exc}", applied=False)

    # --- Malicious skill removal ---

    def _remove_malicious_skills(self) -> None:
        """Remove skills matching known malicious patterns (quarantine, not delete)."""
        if not OPENCLAW_SKILLS.is_dir():
            return

        try:
            skill_dirs = [d for d in OPENCLAW_SKILLS.iterdir() if d.is_dir()]
        except OSError:
            return

        for skill_dir in skill_dirs:
            reason = self._skill_is_malicious(skill_dir)
            if reason is None:
                continue

            detail = f"{skill_dir.name}: {reason}"
            if self.dry_run:
                self._log_action("remove_skill", detail, applied=False)
            else:
                self._quarantine_skill(skill_dir, detail)

    def _skill_is_malicious(self, skill_dir: Path) -> str | None:
        """Return a reason string if the skill matches malicious indicators, else None."""
        name = skill_dir.name

        # Check name patterns
        for pattern in ioc.MALICIOUS_SKILL_PATTERNS:
            if re.search(pattern, name, re.IGNORECASE):
                return f"name matches pattern {pattern}"

        # Check publisher
        meta = _read_skill_metadata(skill_dir)
        publisher = meta.get("publisher") or meta.get("author", "")
        if isinstance(publisher, dict):
            publisher = publisher.get("name", "")
        publisher = str(publisher).strip()

        for pub, campaign in ioc.MALICIOUS_PUBLISHERS.items():
            if pub.lower() in publisher.lower():
                return f"publisher '{publisher}' matches known malicious ({campaign})"

        return None

    def _quarantine_skill(self, skill_dir: Path, detail: str) -> None:
        """Move a skill directory to quarantine."""
        _QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        dest = _QUARANTINE_DIR / skill_dir.name
        try:
            if dest.exists():
                shutil.rmtree(dest)
            shutil.move(str(skill_dir), str(dest))
            self._log_action("remove_skill", detail, applied=True)
        except OSError as exc:
            self._log_action("remove_skill", f"{detail} FAILED: {exc}", applied=False)

    # --- Logging ---

    def _log_action(self, action: str, detail: str, applied: bool) -> None:
        """Record an action taken or proposed."""
        self.actions.append({"action": action, "detail": detail, "applied": applied})
        prefix = "APPLIED" if applied else "DRY-RUN" if self.dry_run else "FAILED"
        logger.info("[%s] %s: %s", prefix, action, detail)

    def _write_log(self) -> None:
        """Append actions to the remediation log file."""
        if not self.actions:
            return
        _REMEDIATION_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(_REMEDIATION_LOG, "a") as f:
            for entry in self.actions:
                prefix = "APPLIED" if entry["applied"] else "DRY-RUN" if self.dry_run else "FAILED"
                f.write(f"[{prefix}] {entry['action']}: {entry['detail']}\n")
