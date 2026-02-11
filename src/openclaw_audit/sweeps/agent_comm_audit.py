"""Inter-agent communication audit (OWASP ASI07)."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from ..config import (
    OPENCLAW_AGENTS,
    OPENCLAW_CONFIG,
    SECRET_PATTERNS,
)
from ..models import Finding, ModuleResult, Severity
from .base import BaseSweep

logger = logging.getLogger(__name__)

# Max lines to read from a single session file.
_MAX_LINES = 10000

# Patterns suggesting messaging / DM tool calls in session transcripts.
_MESSAGING_PATTERNS = re.compile(
    r"(send_message|SendMessage|direct_message|dm_send|broadcast|"
    r"message_agent|inter_agent|agent_message)",
    re.IGNORECASE,
)

# Patterns suggesting permission escalation in tool call arguments.
_ESCALATION_PATTERNS = re.compile(
    r"\b(grant|elevate|admin|sudo|permission)\b",
    re.IGNORECASE,
)

# Compiled secret patterns for credential detection.
_SECRET_RES: dict[str, re.Pattern[str]] = {
    name: re.compile(pat) for name, pat in SECRET_PATTERNS.items()
}

# High-volume session threshold (line count).
_HIGH_VOLUME_THRESHOLD = 100


class AgentCommAuditSweep(BaseSweep):
    name = "agent_comm_audit"

    def run(self) -> ModuleResult:
        findings: list[Finding] = []

        if not OPENCLAW_AGENTS.is_dir():
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title="No agents directory found",
                detail=f"{OPENCLAW_AGENTS} does not exist.",
            ))
            return ModuleResult(module_name=self.name, findings=findings)

        # Discover agents (each subdirectory is an agent).
        agents = [
            d.name for d in sorted(OPENCLAW_AGENTS.iterdir()) if d.is_dir()
        ]
        agent_set = set(agents)

        # Analyse session transcripts for each agent.
        for agent in agents:
            sessions_dir = OPENCLAW_AGENTS / agent / "sessions"
            if not sessions_dir.is_dir():
                continue

            for session_file in sorted(sessions_dir.glob("*.jsonl")):
                self._analyse_session(
                    agent, session_file, agent_set, findings,
                )

        # Config-level checks.
        self._check_config(findings)

        return ModuleResult(module_name=self.name, findings=findings)

    # ------------------------------------------------------------------
    # Session transcript analysis
    # ------------------------------------------------------------------

    def _analyse_session(
        self,
        agent: str,
        session_file: Path,
        agent_set: set[str],
        findings: list[Finding],
    ) -> None:
        try:
            raw_lines = session_file.read_text().splitlines()
        except OSError:
            return

        # For very large files, only read the last _MAX_LINES.
        if len(raw_lines) > _MAX_LINES:
            raw_lines = raw_lines[-_MAX_LINES:]

        line_count = len(raw_lines)
        session_name = session_file.name

        # High volume check.
        if line_count > _HIGH_VOLUME_THRESHOLD:
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title="High-volume agent session",
                detail=f"{agent}/{session_name} ({line_count} entries)",
                path=str(session_file),
            ))

        for line in raw_lines:
            stripped = line.strip()
            if not stripped:
                continue

            # Cross-agent messaging detection.
            if _MESSAGING_PATTERNS.search(stripped):
                # Try to find target agent in the line.
                for other_agent in agent_set:
                    if other_agent != agent and other_agent in stripped:
                        findings.append(Finding(
                            module=self.name,
                            severity=Severity.WARNING,
                            title="Inter-agent message detected",
                            detail=f"{agent} \u2192 {other_agent}",
                            path=str(session_file),
                        ))
                        break
                else:
                    # Messaging call but no specific peer identified.
                    findings.append(Finding(
                        module=self.name,
                        severity=Severity.WARNING,
                        title="Inter-agent message detected",
                        detail=f"{agent} \u2192 unknown peer",
                        path=str(session_file),
                    ))

            # Credential leakage detection.
            for pattern_name, regex in _SECRET_RES.items():
                if regex.search(stripped):
                    findings.append(Finding(
                        module=self.name,
                        severity=Severity.CRITICAL,
                        title="Credential in inter-agent traffic",
                        detail=f"{pattern_name} in {agent}/{session_name}",
                        path=str(session_file),
                    ))
                    break  # One credential finding per line is enough.

            # Permission escalation detection.
            # Only flag when pattern appears inside what looks like a tool
            # call (JSON with "arguments" or "input" or "parameters").
            if _ESCALATION_PATTERNS.search(stripped):
                try:
                    parsed = json.loads(stripped)
                except (json.JSONDecodeError, ValueError):
                    parsed = None
                if parsed and isinstance(parsed, dict):
                    args_str = json.dumps(
                        parsed.get("arguments")
                        or parsed.get("input")
                        or parsed.get("parameters")
                        or "",
                    )
                    if _ESCALATION_PATTERNS.search(args_str):
                        findings.append(Finding(
                            module=self.name,
                            severity=Severity.WARNING,
                            title="Permission escalation in agent session",
                            detail=f"Escalation keyword in tool call args ({agent}/{session_name})",
                            path=str(session_file),
                        ))

    # ------------------------------------------------------------------
    # Config-level checks
    # ------------------------------------------------------------------

    def _check_config(self, findings: list[Finding]) -> None:
        if not OPENCLAW_CONFIG.exists():
            return

        try:
            data = json.loads(OPENCLAW_CONFIG.read_text())
        except (json.JSONDecodeError, OSError):
            return

        agents_cfg = data.get("agents", {})
        if not isinstance(agents_cfg, dict):
            return

        # Isolation check.
        if agents_cfg.get("isolation") is not True:
            findings.append(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title="Agent isolation not enabled",
                detail="agents.isolation is not set to true in openclaw.json.",
                path=str(OPENCLAW_CONFIG),
            ))

        # Inter-agent policy check.
        policy = agents_cfg.get("interAgentPolicy")
        if policy == "allow_all" or policy is None:
            status = '"allow_all"' if policy == "allow_all" else "missing"
            findings.append(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title="Permissive inter-agent communication policy",
                detail=f"agents.interAgentPolicy is {status}.",
                path=str(OPENCLAW_CONFIG),
            ))

        # Per-agent wildcard peer access.
        for agent_name, agent_cfg in agents_cfg.items():
            if not isinstance(agent_cfg, dict):
                continue
            allowed_peers = agent_cfg.get("allowedPeers")
            if isinstance(allowed_peers, list) and "*" in allowed_peers:
                findings.append(Finding(
                    module=self.name,
                    severity=Severity.WARNING,
                    title="Agent has wildcard peer access",
                    detail=f"Agent '{agent_name}' has allowedPeers: [\"*\"].",
                    path=str(OPENCLAW_CONFIG),
                ))
