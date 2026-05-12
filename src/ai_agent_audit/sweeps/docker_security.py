"""Docker container security sweep for the active agent's containers."""

from __future__ import annotations

import json
import logging
import subprocess

from ..config import ACTIVE_PROFILE
from ..models import Finding, ModuleResult, Severity
from .base import BaseSweep

logger = logging.getLogger(__name__)

_PROCESS_KEYWORDS = tuple(kw.lower() for kw in ACTIVE_PROFILE.process_keywords)


class DockerSecuritySweep(BaseSweep):
    name = "docker_security"

    def run(self) -> ModuleResult:
        findings: list[Finding] = []

        # Find active-agent-related containers
        try:
            result = subprocess.run(
                ["docker", "ps", "--format", "{{.ID}} {{.Names}} {{.Image}}"],
                capture_output=True, text=True, timeout=10,
            )
        except FileNotFoundError:
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title="Docker not installed",
                detail="docker command not found. Skipping container audit.",
            ))
            return ModuleResult(module_name=self.name, findings=findings)
        except subprocess.TimeoutExpired:
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title="Docker command timed out",
                detail="docker ps timed out. Docker may not be running.",
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        if result.returncode != 0:
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title="Docker not running",
                detail=f"docker ps failed: {result.stderr.strip()[:200]}",
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        # Filter for active-agent containers
        container_ids: list[str] = []
        for line in result.stdout.strip().splitlines():
            if not line:
                continue
            lower = line.lower()
            if any(kw in lower for kw in _PROCESS_KEYWORDS):
                container_ids.append(line.split()[0])

        if not container_ids:
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title=f"No {ACTIVE_PROFILE.display_name} containers found",
                detail=f"No running Docker containers match {list(_PROCESS_KEYWORDS)}.",
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        # Inspect each container
        for cid in container_ids:
            try:
                inspect_result = subprocess.run(
                    ["docker", "inspect", cid],
                    capture_output=True, text=True, timeout=10,
                )
            except (subprocess.TimeoutExpired, OSError):
                continue

            if inspect_result.returncode != 0:
                continue

            try:
                info_list = json.loads(inspect_result.stdout)
            except json.JSONDecodeError:
                continue

            if not info_list:
                continue

            info = info_list[0]
            name = info.get("Name", cid).lstrip("/")
            host_cfg = info.get("HostConfig", {})
            cfg = info.get("Config", {})

            # Running as root
            user = cfg.get("User", "")
            if user in ("", "root", "0"):
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title=f"Container '{name}' runs as root",
                    detail="Container runs as root user. Use a non-root user.",
                    path=name,
                ))

            # Docker socket mounted
            binds = host_cfg.get("Binds") or []
            for bind in binds:
                if "/var/run/docker.sock" in bind:
                    findings.append(Finding(
                        module=self.name,
                        severity=Severity.CRITICAL,
                        title=f"Docker socket mounted in '{name}'",
                        detail="Docker socket is bind-mounted. Container can control the host Docker daemon.",
                        path=name,
                    ))
                    break

            # Privileged mode
            if host_cfg.get("Privileged") is True:
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.CRITICAL,
                    title=f"Container '{name}' is privileged",
                    detail="Container runs in privileged mode with full host access.",
                    path=name,
                ))

            # Host network mode
            network_mode = host_cfg.get("NetworkMode", "")
            if network_mode == "host":
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.WARNING,
                    title=f"Container '{name}' uses host network",
                    detail="Container shares the host network namespace.",
                    path=name,
                ))

            # Unrestricted capabilities
            cap_add = host_cfg.get("CapAdd") or []
            if "ALL" in cap_add or "SYS_ADMIN" in cap_add:
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.WARNING,
                    title=f"Container '{name}' has elevated capabilities",
                    detail=f"Container has added capabilities: {cap_add}",
                    path=name,
                ))

            # No read-only rootfs
            if host_cfg.get("ReadonlyRootfs") is not True:
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.WARNING,
                    title=f"Container '{name}' has writable rootfs",
                    detail="Container root filesystem is writable. Consider ReadonlyRootfs=true.",
                    path=name,
                ))

        return ModuleResult(module_name=self.name, findings=findings)
