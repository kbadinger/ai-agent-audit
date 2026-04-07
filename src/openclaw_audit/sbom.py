"""CycloneDX 1.5 SBOM generation for agent dependencies.

Scans installed skills, MCP servers, and extensions to produce
a Software Bill of Materials in CycloneDX format.
"""

from __future__ import annotations

import json
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import OPENCLAW_EXTENSIONS, OPENCLAW_MCP_CONFIG, OPENCLAW_SKILLS

logger = logging.getLogger(__name__)


def _make_bom_ref(component_type: str, name: str) -> str:
    """Generate a deterministic BOM reference."""
    seed = f"{component_type}:{name}"
    return hashlib.sha256(seed.encode()).hexdigest()[:16]


def generate_sbom() -> dict[str, Any]:
    """Generate a CycloneDX 1.5 SBOM for the OpenClaw installation."""
    components: list[dict] = []

    # Scan skills
    _scan_skills(components)

    # Scan MCP servers
    _scan_mcp_servers(components)

    # Scan extensions
    _scan_extensions(components)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{hashlib.sha256(now.encode()).hexdigest()[:32]}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [
                {
                    "vendor": "openclaw-audit",
                    "name": "openclaw-audit",
                    "version": "0.1.0",
                }
            ],
            "component": {
                "type": "application",
                "name": "openclaw",
                "description": "OpenClaw AI agent installation",
            },
        },
        "components": components,
    }


def _scan_skills(components: list[dict]) -> None:
    """Scan installed skills and add as components."""
    if not OPENCLAW_SKILLS.exists():
        return

    for skill_dir in sorted(OPENCLAW_SKILLS.iterdir()):
        if not skill_dir.is_dir():
            continue

        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": _make_bom_ref("skill", skill_dir.name),
            "name": skill_dir.name,
            "group": "openclaw-skills",
        }

        # Try to read metadata
        for meta_name in ("skill.json", "package.json"):
            meta_path = skill_dir / meta_name
            if meta_path.exists():
                try:
                    data = json.loads(meta_path.read_text())
                    if data.get("version"):
                        component["version"] = str(data["version"])
                    if data.get("description"):
                        component["description"] = str(data["description"])[:500]
                    if data.get("author"):
                        author = data["author"]
                        if isinstance(author, str):
                            component["author"] = author
                        elif isinstance(author, dict):
                            component["author"] = author.get("name", "")
                    if data.get("license"):
                        lic = data["license"]
                        if isinstance(lic, str):
                            component["licenses"] = [{"license": {"id": lic}}]
                except (json.JSONDecodeError, OSError):
                    pass
                break

        if "version" not in component:
            component["version"] = "unknown"

        components.append(component)


def _scan_mcp_servers(components: list[dict]) -> None:
    """Scan MCP server configs and add as components."""
    if not OPENCLAW_MCP_CONFIG.exists():
        return

    try:
        data = json.loads(OPENCLAW_MCP_CONFIG.read_text())
    except (json.JSONDecodeError, OSError):
        return

    servers = data.get("mcpServers", {})
    for server_name, server_cfg in sorted(servers.items()):
        if not isinstance(server_cfg, dict):
            continue

        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": _make_bom_ref("mcp-server", server_name),
            "name": server_name,
            "group": "mcp-servers",
        }

        # Extract version info
        version = server_cfg.get("version", "")
        image = server_cfg.get("image", "")
        package = server_cfg.get("package", "")

        if version:
            component["version"] = version
        elif ":" in image:
            component["version"] = image.split(":")[-1]
        elif "@" in package:
            component["version"] = package.split("@")[-1]
        else:
            component["version"] = "latest"

        # Source info
        if image:
            component["description"] = f"Docker image: {image}"
        elif package:
            component["description"] = f"Package: {package}"
        elif server_cfg.get("command"):
            component["description"] = f"Command: {server_cfg['command']}"

        # Tool count
        tools = server_cfg.get("tools", [])
        if isinstance(tools, list):
            component["properties"] = [
                {"name": "tool-count", "value": str(len(tools))},
            ]

        components.append(component)


def _scan_extensions(components: list[dict]) -> None:
    """Scan installed extensions and add as components."""
    if not OPENCLAW_EXTENSIONS.exists():
        return

    for ext_dir in sorted(OPENCLAW_EXTENSIONS.iterdir()):
        if not ext_dir.is_dir():
            continue

        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": _make_bom_ref("extension", ext_dir.name),
            "name": ext_dir.name,
            "group": "openclaw-extensions",
            "version": "unknown",
        }

        # Try package.json
        pkg = ext_dir / "package.json"
        if pkg.exists():
            try:
                data = json.loads(pkg.read_text())
                if data.get("version"):
                    component["version"] = str(data["version"])
                if data.get("description"):
                    component["description"] = str(data["description"])[:500]
            except (json.JSONDecodeError, OSError):
                pass

        components.append(component)


def sbom_to_json(sbom: dict[str, Any], indent: int = 2) -> str:
    """Serialize SBOM to JSON string."""
    return json.dumps(sbom, indent=indent)
