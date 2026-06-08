"""IOC feed updater -- supplements hardcoded IOCs with external data."""

from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path
from typing import Union

from . import ioc
from .config import AUDIT_DIR

logger = logging.getLogger(__name__)

CUSTOM_IOC_PATH = AUDIT_DIR / "ioc-custom.json"

# abuse.ch ThreatFox recent-IOC export. No API key required, refreshed every
# 5 minutes, IOCs older than 6 months are expired upstream.
THREATFOX_FEED_URL = "https://threatfox.abuse.ch/export/json/recent/"
THREATFOX_MIN_CONFIDENCE = 75

_EMPTY: dict = {
    "c2_ips": [],
    "malicious_domains": [],
    "malicious_publishers": {},
    "file_hashes": {},
}


def _looks_like_threatfox(raw: object) -> bool:
    """ThreatFox export is {id: [ {ioc_value, ioc_type, ...} ]}."""
    if not isinstance(raw, dict):
        return False
    for value in raw.values():
        return (
            isinstance(value, list)
            and bool(value)
            and isinstance(value[0], dict)
            and "ioc_value" in value[0]
        )
    return False


def _url_host(url: str) -> str | None:
    """Extract the host from a URL IOC; fall back to None if unparseable."""
    try:
        host = urllib.parse.urlparse(url).hostname
    except ValueError:
        return None
    return host


def parse_threatfox(raw: dict, min_confidence: int = THREATFOX_MIN_CONFIDENCE) -> dict:
    """Convert a ThreatFox export into this tool's IOC schema."""
    out: dict = {"c2_ips": [], "malicious_domains": [], "malicious_publishers": {}, "file_hashes": {}}
    for entries in raw.values():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            try:
                confidence = int(entry.get("confidence_level") or 0)
            except (TypeError, ValueError):
                confidence = 0
            if confidence < min_confidence:
                continue
            value = (entry.get("ioc_value") or "").strip()
            if not value:
                continue
            ioc_type = (entry.get("ioc_type") or "").lower()
            label = (
                entry.get("malware_printable")
                or entry.get("malware")
                or entry.get("threat_type")
                or "threatfox"
            )
            if ioc_type == "ip:port":
                out["c2_ips"].append(value.split(":", 1)[0])
            elif ioc_type in ("domain", "hostname"):
                out["malicious_domains"].append(value)
            elif ioc_type == "url":
                host = _url_host(value)
                if host:
                    out["malicious_domains"].append(host)
            elif ioc_type in ("sha256_hash", "sha1_hash", "md5_hash"):
                out["file_hashes"][value] = label
    return out


class IOCUpdater:
    """Updates IOC database from external feeds or local files."""

    def _fetch_url(self, url: str) -> object:
        """Fetch and JSON-decode a URL. Raises on network/parse errors."""
        req = urllib.request.Request(url, headers={"User-Agent": "ai-agent-audit"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())

    def _normalize(self, raw: object) -> dict:
        """Accept either this tool's IOC schema or a ThreatFox export."""
        if _looks_like_threatfox(raw):
            return parse_threatfox(raw)
        return raw if isinstance(raw, dict) else {}

    def update_from_url(self, url: str) -> dict:
        """Download IOC data from a URL (JSON) and merge with custom IOCs.

        Accepts this tool's native schema or an abuse.ch ThreatFox export.
        Returns stats dict with counts of new entries added.
        """
        try:
            raw = self._fetch_url(url)
        except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError) as exc:
            logger.error("Failed to fetch IOC feed from %s: %s", url, exc)
            return {"error": str(exc)}

        return self._merge(self._normalize(raw))

    def update_from_threatfox(self, min_confidence: int = THREATFOX_MIN_CONFIDENCE) -> dict:
        """Fetch recent IOCs from abuse.ch ThreatFox (no API key) and merge."""
        try:
            raw = self._fetch_url(THREATFOX_FEED_URL)
        except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError) as exc:
            logger.error("Failed to fetch ThreatFox feed: %s", exc)
            return {"error": str(exc)}

        if not _looks_like_threatfox(raw):
            return {"error": "Unexpected ThreatFox response format"}

        return self._merge(parse_threatfox(raw, min_confidence))

    def update_from_file(self, path: Union[str, Path]) -> dict:
        """Load IOC data from a local JSON file and merge.

        Accepts this tool's native schema or an abuse.ch ThreatFox export.
        Returns stats dict with counts of new entries added.
        """
        path = Path(path)
        try:
            raw = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            logger.error("Failed to load IOC file %s: %s", path, exc)
            return {"error": str(exc)}

        return self._merge(self._normalize(raw))

    def get_merged_iocs(self) -> dict:
        """Return combined hardcoded + custom IOCs."""
        custom = self._load_custom()
        return {
            "c2_ips": ioc.C2_IPS | set(custom.get("c2_ips", [])),
            "malicious_domains": ioc.MALICIOUS_DOMAINS | set(custom.get("malicious_domains", [])),
            "malicious_publishers": {**ioc.MALICIOUS_PUBLISHERS, **custom.get("malicious_publishers", {})},
            "file_hashes": {**ioc.MALICIOUS_HASHES, **custom.get("file_hashes", {})},
        }

    def stats(self) -> dict:
        """Return counts of all IOC entries (hardcoded + custom)."""
        merged = self.get_merged_iocs()
        return {
            "c2_ips": len(merged["c2_ips"]),
            "malicious_domains": len(merged["malicious_domains"]),
            "malicious_publishers": len(merged["malicious_publishers"]),
            "file_hashes": len(merged["file_hashes"]),
        }

    # --- internal helpers ---

    def _merge(self, new_data: dict) -> dict:
        """Merge new IOC data into the custom IOC file. Return add-counts."""
        custom = self._load_custom()

        existing_ips = set(custom.get("c2_ips", []))
        existing_domains = set(custom.get("malicious_domains", []))
        existing_publishers = custom.get("malicious_publishers", {})
        existing_hashes = custom.get("file_hashes", {})

        new_ips = set(new_data.get("c2_ips", [])) - existing_ips
        new_domains = set(new_data.get("malicious_domains", [])) - existing_domains
        new_publishers = {
            k: v for k, v in new_data.get("malicious_publishers", {}).items()
            if k not in existing_publishers
        }
        new_hashes = {
            k: v for k, v in new_data.get("file_hashes", {}).items()
            if k not in existing_hashes
        }

        custom["c2_ips"] = sorted(existing_ips | new_ips)
        custom["malicious_domains"] = sorted(existing_domains | new_domains)
        custom["malicious_publishers"] = {**existing_publishers, **new_publishers}
        custom["file_hashes"] = {**existing_hashes, **new_hashes}

        self._save_custom(custom)

        stats = {
            "c2_ips_added": len(new_ips),
            "malicious_domains_added": len(new_domains),
            "malicious_publishers_added": len(new_publishers),
            "file_hashes_added": len(new_hashes),
        }
        logger.info("IOC merge complete: %s", stats)
        return stats

    def _load_custom(self) -> dict:
        """Load custom IOC file if it exists."""
        if not CUSTOM_IOC_PATH.exists():
            return {
                "c2_ips": [],
                "malicious_domains": [],
                "malicious_publishers": {},
                "file_hashes": {},
            }
        try:
            return json.loads(CUSTOM_IOC_PATH.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Corrupt custom IOC file, starting fresh: %s", exc)
            return {
                "c2_ips": [],
                "malicious_domains": [],
                "malicious_publishers": {},
                "file_hashes": {},
            }

    def _save_custom(self, data: dict) -> None:
        """Save custom IOC data to disk."""
        CUSTOM_IOC_PATH.parent.mkdir(parents=True, exist_ok=True)
        CUSTOM_IOC_PATH.write_text(json.dumps(data, indent=2) + "\n")
