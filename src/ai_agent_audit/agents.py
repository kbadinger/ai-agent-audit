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
    # Command that prints the installed agent version (e.g. ("openclaw", "--version")).
    version_command: tuple[str, ...] = ()
    # Skills directory, relative to home (OpenClaw uses workspace/skills; Hermes uses skills).
    skills_relpath: str = "workspace/skills"
    extensions_relpath: str = "extensions"
    # Workspace/memory root, relative to home. Hermes keeps SOUL.md at its home root.
    workspace_relpath: str = "workspace"
    # Modern agents embed MCP settings in their main config. A filename is only
    # needed for legacy/separate layouts.
    mcp_config_filename: Optional[str] = None
    # Native audit/fix commands used by the adapter and remediation engine.
    native_audit_command: tuple[str, ...] = ()
    native_fix_command: tuple[str, ...] = ()
    sensitive_file_relpaths: tuple[str, ...] = ()
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
        return self.home / self.extensions_relpath

    @property
    def workspace_path(self) -> Path:
        return self.home / self.workspace_relpath

    @property
    def skills_path(self) -> Path:
        return self.home / self.skills_relpath

    @property
    def exec_approvals_path(self) -> Path:
        return self.home / "exec-approvals.json"

    @property
    def mcp_config_path(self) -> Path:
        if self.mcp_config_filename:
            return self.home / self.mcp_config_filename
        return self.config_path

    @property
    def identity_path(self) -> Path:
        return self.home / "identity"

    @property
    def sensitive_files(self) -> tuple[Path, ...]:
        return tuple(self.home / relpath for relpath in self.sensitive_file_relpaths)

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
        version_command=("openclaw", "--version"),
        skills_relpath="workspace/skills",
        native_audit_command=("openclaw", "security", "audit", "--json"),
        native_fix_command=("openclaw", "security", "audit", "--fix", "--json"),
    )


def _hermes_profile() -> AgentProfile:
    home_env = os.environ.get("HERMES_HOME")
    return AgentProfile(
        slug="hermes",
        display_name="Hermes",
        home=Path(home_env) if home_env else (Path.home() / ".hermes"),
        config_filename="config.yaml",
        process_keywords=("hermes",),
        persistence_keywords=("hermes", "hermesd", "hermes-agent"),
        vscode_extension_patterns=("hermes", "hermesd", "hermesbot"),
        version_command=("hermes", "--version"),
        skills_relpath="skills",
        extensions_relpath="plugins",
        workspace_relpath=".",
        native_audit_command=("hermes", "audit", "--json"),
        sensitive_file_relpaths=("auth.json",),
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
