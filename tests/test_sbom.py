"""Tests for CycloneDX SBOM generation."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from openclaw_audit.sbom import generate_sbom, sbom_to_json


class TestSBOMGeneration:
    def test_sbom_structure(self):
        with patch("openclaw_audit.sbom.OPENCLAW_SKILLS", Path("/nonexistent")), \
             patch("openclaw_audit.sbom.OPENCLAW_MCP_CONFIG", Path("/nonexistent")), \
             patch("openclaw_audit.sbom.OPENCLAW_EXTENSIONS", Path("/nonexistent")):
            sbom = generate_sbom()
        assert sbom["bomFormat"] == "CycloneDX"
        assert sbom["specVersion"] == "1.5"
        assert "metadata" in sbom
        assert "components" in sbom

    def test_sbom_metadata(self):
        with patch("openclaw_audit.sbom.OPENCLAW_SKILLS", Path("/nonexistent")), \
             patch("openclaw_audit.sbom.OPENCLAW_MCP_CONFIG", Path("/nonexistent")), \
             patch("openclaw_audit.sbom.OPENCLAW_EXTENSIONS", Path("/nonexistent")):
            sbom = generate_sbom()
        assert sbom["metadata"]["component"]["name"] == "openclaw"

    def test_skills_as_components(self):
        tmp = Path(tempfile.mkdtemp())
        skills = tmp / "skills"
        skills.mkdir()
        skill_dir = skills / "my-skill"
        skill_dir.mkdir()
        (skill_dir / "skill.json").write_text(json.dumps({
            "version": "1.2.3",
            "description": "A test skill",
            "author": "testuser",
        }))

        with patch("openclaw_audit.sbom.OPENCLAW_SKILLS", skills), \
             patch("openclaw_audit.sbom.OPENCLAW_MCP_CONFIG", Path("/nonexistent")), \
             patch("openclaw_audit.sbom.OPENCLAW_EXTENSIONS", Path("/nonexistent")):
            sbom = generate_sbom()

        skill_components = [c for c in sbom["components"] if c.get("group") == "openclaw-skills"]
        assert len(skill_components) == 1
        assert skill_components[0]["name"] == "my-skill"
        assert skill_components[0]["version"] == "1.2.3"

    def test_mcp_servers_as_components(self):
        tmp = Path(tempfile.mkdtemp())
        mcp_config = tmp / "mcp.json"
        mcp_config.write_text(json.dumps({
            "mcpServers": {
                "my-server": {
                    "package": "my-pkg@2.0.0",
                    "tools": [{"name": "t1"}, {"name": "t2"}],
                }
            }
        }))

        with patch("openclaw_audit.sbom.OPENCLAW_SKILLS", Path("/nonexistent")), \
             patch("openclaw_audit.sbom.OPENCLAW_MCP_CONFIG", mcp_config), \
             patch("openclaw_audit.sbom.OPENCLAW_EXTENSIONS", Path("/nonexistent")):
            sbom = generate_sbom()

        mcp_components = [c for c in sbom["components"] if c.get("group") == "mcp-servers"]
        assert len(mcp_components) == 1
        assert mcp_components[0]["name"] == "my-server"
        assert mcp_components[0]["version"] == "2.0.0"

    def test_json_roundtrip(self):
        with patch("openclaw_audit.sbom.OPENCLAW_SKILLS", Path("/nonexistent")), \
             patch("openclaw_audit.sbom.OPENCLAW_MCP_CONFIG", Path("/nonexistent")), \
             patch("openclaw_audit.sbom.OPENCLAW_EXTENSIONS", Path("/nonexistent")):
            sbom = generate_sbom()
        text = sbom_to_json(sbom)
        parsed = json.loads(text)
        assert parsed["bomFormat"] == "CycloneDX"

    def test_empty_no_crash(self):
        with patch("openclaw_audit.sbom.OPENCLAW_SKILLS", Path("/nonexistent")), \
             patch("openclaw_audit.sbom.OPENCLAW_MCP_CONFIG", Path("/nonexistent")), \
             patch("openclaw_audit.sbom.OPENCLAW_EXTENSIONS", Path("/nonexistent")):
            sbom = generate_sbom()
        assert sbom["components"] == []
