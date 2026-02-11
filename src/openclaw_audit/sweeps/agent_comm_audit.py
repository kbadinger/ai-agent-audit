"""Inter-agent communication audit (OWASP ASI07)."""

from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
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

        # Aggregation counters
        high_volume_sessions: list[str] = []
        messaging_counts: defaultdict[str, int] = defaultdict(int)  # "agent -> peer" -> count
        credential_leaks: list[str] = []  # "pattern_name in agent/session"
        escalation_findings: list[Finding] = []  # keep individual (should be rare)

        # Analyse session transcripts for each agent.
        for agent in agents:
            sessions_dir = OPENCLAW_AGENTS / agent / "sessions"
            if not sessions_dir.is_dir():
                continue

            for session_file in sorted(sessions_dir.glob("*.jsonl")):
                self._analyse_session(
                    agent, session_file, agent_set,
                    high_volume_sessions, messaging_counts,
                    credential_leaks, escalation_findings,
                )

        # Emit aggregated findings

        if high_volume_sessions:
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title=f"{len(high_volume_sessions)} high-volume agent sessions",
                detail=f"Sessions with >{_HIGH_VOLUME_THRESHOLD} entries: "
                       + ", ".join(high_volume_sessions[:10])
                       + (f" (+{len(high_volume_sessions) - 10} more)" if len(high_volume_sessions) > 10 else ""),
            ))

        total_messages = sum(messaging_counts.values())
        if total_messages:
            top_pairs = sorted(messaging_counts.items(), key=lambda x: -x[1])[:5]
            detail_lines = [f"  {pair}: {count}x" for pair, count in top_pairs]
            findings.append(Finding(
                module=self.name,
                severity=Severity.WARNING,
                title=f"{total_messages} inter-agent messages detected",
                detail="Top communication pairs:\n" + "\n".join(detail_lines),
            ))

        if credential_leaks:
            samples = credential_leaks[:5]
            extra = f"\n  ... and {len(credential_leaks) - 5} more" if len(credential_leaks) > 5 else ""
            findings.append(Finding(
                module=self.name,
                severity=Severity.INFO,
                title=f"{len(credential_leaks)} credentials present in session transcripts",
                detail="Credentials in transcripts are expected (agent API keys). "
                       "Ensure session files are permission-restricted to 0o600.\n"
                       + "\n".join(f"  - {s}" for s in samples) + extra,
            ))

        findings.extend(escalation_findings)

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
        high_volume_sessions: list[str],
        messaging_counts: defaultdict[str, int],
        credential_leaks: list[str],
        escalation_findings: list[Finding],
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
            high_volume_sessions.append(f"{agent}/{session_name} ({line_count})")

        for line in raw_lines:
            stripped = line.strip()
            if not stripped:
                continue

            # Cross-agent messaging detection.
            if _MESSAGING_PATTERNS.search(stripped):
                # Try to find target agent in the line.
                peer = "unknown"
                for other_agent in agent_set:
                    if other_agent != agent and other_agent in stripped:
                        peer = other_agent
                        break
                messaging_counts[f"{agent} \u2192 {peer}"] += 1

            # Credential leakage detection.
            for pattern_name, regex in _SECRET_RES.items():
                if regex.search(stripped):
                    credential_leaks.append(f"{pattern_name} in {agent}/{session_name}")
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
                        escalation_findings.append(Finding(
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
