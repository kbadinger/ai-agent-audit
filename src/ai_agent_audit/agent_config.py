"""Current agent configuration adapters.

OpenClaw accepts JSON5 in ``openclaw.json`` and stores MCP servers in the main
configuration. Hermes uses YAML in ``~/.hermes/config.yaml``. This module is
the single parsing/normalization boundary so sweeps do not clone either
product's schema.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import json5
import yaml

from .agents import AgentProfile


class AgentConfigError(ValueError):
    """Raised when an agent configuration cannot be read as a mapping."""


def load_agent_config(path: Path) -> dict[str, Any]:
    """Load JSON5 or YAML agent configuration from *path*."""
    try:
        raw = path.read_text()
        if path.suffix.lower() in {".yaml", ".yml"}:
            parsed = yaml.safe_load(raw)
        else:
            parsed = json5.loads(raw)
    except (OSError, ValueError, TypeError, yaml.YAMLError) as exc:
        raise AgentConfigError(f"Could not parse {path}: {exc}") from exc
    if parsed is None:
        return {}
    if not isinstance(parsed, dict):
        raise AgentConfigError(f"Expected an object/mapping in {path}")
    return parsed


def get_nested(data: dict[str, Any], dotted_key: str) -> Any:
    """Resolve a dotted path, returning ``None`` when any segment is absent."""
    current: Any = data
    for key in dotted_key.split("."):
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def first_nested(data: dict[str, Any], *keys: str) -> Any:
    """Return the first explicitly present dotted-path value."""
    for key in keys:
        value = get_nested(data, key)
        if value is not None:
            return value
    return None


def extract_mcp_servers(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Normalize current and legacy MCP server configuration layouts."""
    candidates = (
        get_nested(data, "mcp.servers"),
        data.get("mcpServers"),
    )
    for candidate in candidates:
        if isinstance(candidate, dict):
            return {
                str(name): config
                for name, config in candidate.items()
                if isinstance(config, dict)
            }
    return {}


def auth_enabled(data: dict[str, Any], profile: AgentProfile) -> bool | None:
    """Return the normalized gateway authentication state."""
    if profile.slug == "openclaw":
        mode = get_nested(data, "gateway.auth.mode")
        if isinstance(mode, str):
            normalized = mode.lower()
            if normalized == "none":
                return False
            if normalized in {"token", "password", "trusted-proxy"}:
                return True
            return None
        legacy = get_nested(data, "gateway.auth.enabled")
        return legacy if isinstance(legacy, bool) else None
    return None


def sandbox_enabled(data: dict[str, Any], profile: AgentProfile) -> bool | None:
    """Return the normalized agent sandbox state."""
    if profile.slug == "openclaw":
        mode = get_nested(data, "agents.defaults.sandbox.mode")
        if isinstance(mode, str):
            normalized = mode.lower()
            if normalized in {"off", "none", "disabled"}:
                return False
            if normalized in {"all", "non-main"}:
                return True
            return None
        legacy = get_nested(data, "sandbox.enabled")
        return legacy if isinstance(legacy, bool) else None
    # Hermes treats the terminal backend/OS isolation as the security boundary;
    # no boolean in config is equivalent to OpenClaw's sandbox mode.
    return None


def redaction_enabled(data: dict[str, Any], profile: AgentProfile) -> bool | None:
    """Return the normalized sensitive-log-redaction state."""
    if profile.slug == "openclaw":
        value = first_nested(data, "logging.redactSensitive", "logging.redactSecrets")
        return value if isinstance(value, bool) else None
    return None


def dm_policy_open(data: dict[str, Any]) -> bool | None:
    """Return whether any configured channel explicitly permits open DMs."""
    channels = data.get("channels")
    if not isinstance(channels, dict):
        legacy = get_nested(data, "gateway.auth.allowOpenDM")
        return legacy if isinstance(legacy, bool) else None

    saw_policy = False
    for channel in channels.values():
        if not isinstance(channel, dict):
            continue
        accounts = channel.get("accounts")
        configs = [channel]
        if isinstance(accounts, dict):
            configs.extend(v for v in accounts.values() if isinstance(v, dict))
        for config in configs:
            policy = config.get("dmPolicy")
            if not isinstance(policy, str):
                continue
            saw_policy = True
            if policy.lower() in {"open", "allow", "anyone"}:
                return True
    return False if saw_policy else None


def mcp_config_present(data: dict[str, Any]) -> bool:
    """Return whether an MCP configuration section is explicitly present."""
    return isinstance(get_nested(data, "mcp.servers"), dict) or isinstance(
        data.get("mcpServers"), dict
    )
