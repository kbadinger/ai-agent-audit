"""Agent profiles — what defines an auditable AI agent installation.

Each AgentProfile describes the on-disk layout, process identity, and
persistence-mechanism keywords for a specific AI agent product.

Built-in profiles: OpenClaw, Hermes. Resolve the active profile via the
AI_AGENT_AUDIT_PROFILE environment variable (`openclaw`, `hermes`, or
`auto` — the default — which picks whichever install is present).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class AgentProfile:
    """Describes a single auditable AI agent product."""

    slug: str
    display_name: str
    home: Path
    config_filename: str
    process_keywords: tuple[str, ...]
    persistence_keywords: tuple[str, ...]
    vscode_extension_patterns: tuple[str, ...]
    memory_files: tuple[str, ...] = (
        "SOUL.md",
        "MEMORY.md",
        "IDENTITY.md",
        "AGENTS.md",
        "TOOLS.md",
    )
    log_dir_override: Optional[Path] = None

    @property
    def config_path(self) -> Path:
        return self.home / self.config_filename

    @property
    def env_path(self) -> Path:
        return self.home / ".env"

    @property
    def credentials_path(self) -> Path:
        return self.home / "credentials"

    @property
    def agents_path(self) -> Path:
        return self.home / "agents"

    @property
    def extensions_path(self) -> Path:
        return self.home / "extensions"

    @property
    def workspace_path(self) -> Path:
        return self.home / "workspace"

    @property
    def skills_path(self) -> Path:
        return self.workspace_path / "skills"

    @property
    def exec_approvals_path(self) -> Path:
        return self.home / "exec-approvals.json"

    @property
    def mcp_config_path(self) -> Path:
        return self.home / "mcp.json"

    @property
    def identity_path(self) -> Path:
        return self.home / "identity"

    @property
    def audit_dir(self) -> Path:
        return self.home / ".audit"

    @property
    def log_dir(self) -> Path:
        return self.log_dir_override or Path(f"/tmp/{self.slug}")


def _openclaw_profile() -> AgentProfile:
    home_env = os.environ.get("OPENCLAW_HOME")
    return AgentProfile(
        slug="openclaw",
        display_name="OpenClaw",
        home=Path(home_env) if home_env else (Path.home() / ".openclaw"),
        config_filename="openclaw.json",
        process_keywords=("openclaw",),
        persistence_keywords=("openclaw", "clawdbot", "moltbot"),
        vscode_extension_patterns=("clawdbot", "openclaw", "moltbot"),
    )


def _hermes_profile() -> AgentProfile:
    home_env = os.environ.get("HERMES_HOME")
    return AgentProfile(
        slug="hermes",
        display_name="Hermes",
        home=Path(home_env) if home_env else (Path.home() / ".hermes"),
        config_filename="hermes.json",
        process_keywords=("hermes",),
        persistence_keywords=("hermes", "hermesd", "hermes-agent"),
        vscode_extension_patterns=("hermes", "hermesd", "hermesbot"),
    )


def all_profiles() -> dict[str, AgentProfile]:
    """All built-in profiles. Fresh dataclasses each call so env changes take effect."""
    return {"openclaw": _openclaw_profile(), "hermes": _hermes_profile()}


SUPPORTED_PROFILES: tuple[str, ...] = ("openclaw", "hermes")


def get_active_profile() -> AgentProfile:
    """Resolve the active profile from AI_AGENT_AUDIT_PROFILE.

    Values:
      - "openclaw" / "hermes": pick the named profile explicitly.
      - "auto" (default): pick the first profile whose home directory exists;
        fall back to OpenClaw to preserve historical behaviour when nothing is
        detected.

    Set AI_AGENT_AUDIT_PROFILE *before* importing this package's config so the
    paths resolve correctly. The CLI does this in main().
    """
    name = (os.environ.get("AI_AGENT_AUDIT_PROFILE") or "auto").lower()
    profiles = all_profiles()
    if name == "auto":
        for slug in SUPPORTED_PROFILES:
            candidate = profiles[slug]
            if candidate.home.exists():
                return candidate
        return profiles["openclaw"]
    if name in profiles:
        return profiles[name]
    raise ValueError(
        f"Unknown agent profile: {name!r}. Choose from: {list(profiles)} or 'auto'."
    )
