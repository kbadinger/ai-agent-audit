"""Bundled and automatically refreshed agent security advisory catalog."""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path
from typing import Any

from .config import AUDIT_DIR

logger = logging.getLogger(__name__)

CATALOG_CACHE = AUDIT_DIR / "advisories.json"
_REPOSITORIES = {
    "openclaw": "openclaw/openclaw",
    "hermes": "NousResearch/hermes-agent",
}


def _read_json(path: Any) -> dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return {}


def load_catalog(slug: str) -> list[dict[str, Any]]:
    """Load bundled advisories plus a newer cached GitHub refresh."""
    bundled_path = files("ai_agent_audit").joinpath("data/advisories.json")
    bundled = _read_json(bundled_path).get("advisories", {}).get(slug, [])
    cached = _read_json(CATALOG_CACHE).get("advisories", {}).get(slug, [])
    merged: dict[str, dict[str, Any]] = {}
    for advisory in [*bundled, *cached]:
        if isinstance(advisory, dict) and advisory.get("id"):
            merged[str(advisory["id"])] = advisory
    return list(merged.values())


def _version_text(value: Any) -> str | None:
    """Extract a date-style or semantic version from a GitHub range string."""
    text = str(value or "")
    date = re.search(r"(20\d{2}(?:\.\d+){2,3})", text)
    if date:
        return date.group(1)
    semver = re.search(r"(?<!\d)(\d+\.\d+\.\d+)(?!\d)", text)
    return semver.group(1) if semver else None


class AdvisoryCatalogUpdater:
    """Refresh repository advisories from GitHub's public REST API."""

    def _fetch(self, repository: str) -> object:
        request = urllib.request.Request(
            f"https://api.github.com/repos/{repository}/security-advisories?per_page=100",
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "ai-agent-audit",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode())

    def update(self, slug: str) -> dict[str, Any]:
        repository = _REPOSITORIES.get(slug)
        if not repository:
            return {"error": f"No advisory repository configured for {slug}"}
        try:
            payload = self._fetch(repository)
        except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError) as exc:
            logger.warning("Advisory refresh failed for %s: %s", slug, exc)
            return {"error": str(exc)}
        if not isinstance(payload, list):
            return {"error": "Unexpected GitHub advisory response"}

        normalized: list[dict[str, Any]] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            advisory_id = item.get("ghsa_id") or item.get("cve_id")
            vulnerabilities = item.get("vulnerabilities") or []
            ranges = [v for v in vulnerabilities if isinstance(v, dict)]
            fixed = next(
                (_version_text(v.get("patched_versions")) for v in ranges if _version_text(v.get("patched_versions"))),
                None,
            )
            if not advisory_id or not fixed:
                continue
            introduced = next(
                (_version_text(v.get("vulnerable_version_range")) for v in ranges if ">=" in str(v.get("vulnerable_version_range") or "")),
                None,
            )
            record = {
                "id": advisory_id,
                "cve": item.get("cve_id"),
                "fixed": fixed,
                "title": item.get("summary") or "Security advisory",
                "severity": item.get("severity") or "warning",
                "url": item.get("html_url"),
            }
            if introduced:
                record["introduced"] = introduced
            normalized.append(record)

        current = _read_json(CATALOG_CACHE)
        advisories = current.get("advisories")
        if not isinstance(advisories, dict):
            advisories = {}
        advisories[slug] = normalized
        output = {
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "advisories": advisories,
        }
        try:
            CATALOG_CACHE.parent.mkdir(parents=True, exist_ok=True)
            CATALOG_CACHE.write_text(json.dumps(output, indent=2) + "\n")
        except OSError as exc:
            return {"error": str(exc)}
        return {"advisories_loaded": len(normalized), "repository": repository}
