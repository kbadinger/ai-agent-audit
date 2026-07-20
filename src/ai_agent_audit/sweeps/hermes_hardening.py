"""Hermes-specific default-posture hardening checks.

Backed by the April/May 2026 Hermes-Agent audits (CSA, Repello): unrestricted
filesystem writes when HERMES_WRITE_SAFE_ROOT is unset, container approval
auto-bypass (tools/approval.py), --yolo mode, and agent-writable skill
manifests that run shell via setup.commands. Only runs for the Hermes profile.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from ..config import ACTIVE_PROFILE, AGENT_SKILLS
from ..models import Finding, ModuleResult, ModuleStatus, Severity
from .base import BaseSweep

logger = logging.getLogger(__name__)

_SKILL_MANIFESTS = ("skill.json", "package.json", "hermes.json")


class HermesHardeningSweep(BaseSweep):
    name = "hermes_hardening"

    def run(self) -> ModuleResult:
        findings: list[Finding] = []

        if ACTIVE_PROFILE.slug != "hermes":
            return ModuleResult(module_name=self.name, findings=findings)

        self._check_write_safe_root(findings)
        self._check_container_approval(findings)
        process_visible = self._check_yolo(findings)
        self._check_skill_setup_commands(findings)

        if not findings:
            findings.append(Finding(
                module=self.name, severity=Severity.INFO,
                title="Hermes hardening: no issues detected",
                detail="HERMES_WRITE_SAFE_ROOT set, no container approval bypass, "
                       "no --yolo process, no skill setup.commands found.",
            ))

        return ModuleResult(
            module_name=self.name,
            findings=findings,
            status=ModuleStatus.OK if process_visible else ModuleStatus.DEGRADED,
            message=None if process_visible else "Process visibility unavailable; --yolo could not be checked",
        )

    def _check_write_safe_root(self, findings: list[Finding]) -> None:
        if not os.environ.get("HERMES_WRITE_SAFE_ROOT"):
            findings.append(Finding(
                module=self.name, severity=Severity.WARNING,
                title="HERMES_WRITE_SAFE_ROOT not set",
                detail=(
                    "Hermes file writes are unrestricted when HERMES_WRITE_SAFE_ROOT "
                    "is unset. Set it to confine agent writes to a safe root."
                ),
            ))

    def _check_container_approval(self, findings: list[Finding]) -> None:
        if Path("/.dockerenv").exists() or Path("/run/.containerenv").exists():
            findings.append(Finding(
                module=self.name, severity=Severity.CRITICAL,
                title="Container approval auto-bypass active",
                detail=(
                    "Running inside a container. Hermes tools/approval.py skips "
                    "command-approval checks in containerized environments, so the "
                    "agent can execute commands without prompting."
                ),
            ))

    def _check_yolo(self, findings: list[Finding]) -> bool:
        try:
            import psutil
        except ImportError:
            return False
        try:
            procs = list(psutil.process_iter(["cmdline"]))
        except (psutil.Error, OSError):
            return False
        for proc in procs:
            try:
                cmdline = " ".join(proc.info.get("cmdline") or [])
            except (psutil.Error, KeyError, TypeError):
                continue
            lowered = cmdline.lower()
            if "hermes" in lowered and "--yolo" in lowered:
                findings.append(Finding(
                    module=self.name, severity=Severity.CRITICAL,
                    title="Hermes running in --yolo mode",
                    detail=(
                        "A Hermes process was launched with --yolo, which disables "
                        "all security checks. Relaunch without --yolo."
                    ),
                ))
                break
        return True

    def _check_skill_setup_commands(self, findings: list[Finding]) -> None:
        skills = AGENT_SKILLS
        if not skills.exists():
            return
        for entry in skills.iterdir():
            if not entry.is_dir():
                continue
            for manifest_name in _SKILL_MANIFESTS:
                manifest = entry / manifest_name
                if not manifest.exists():
                    continue
                try:
                    data = json.loads(manifest.read_text())
                except (json.JSONDecodeError, OSError):
                    continue
                setup = data.get("setup")
                commands = setup.get("commands") if isinstance(setup, dict) else None
                if commands:
                    findings.append(Finding(
                        module=self.name, severity=Severity.CRITICAL,
                        title=f"Skill setup.commands in {entry.name}",
                        detail=(
                            f"Skill '{entry.name}' declares setup.commands, which run "
                            "shell on install — the highest-risk Hermes skill injection "
                            "vector. Review and remove before installing."
                        ),
                        path=str(manifest),
                    ))
                break

        return
