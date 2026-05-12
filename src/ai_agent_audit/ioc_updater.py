"""IOC feed updater -- supplements hardcoded IOCs with external data."""

from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
from pathlib import Path
from typing import Union

from . import ioc
from .config import AUDIT_DIR

logger = logging.getLogger(__name__)

CUSTOM_IOC_PATH = AUDIT_DIR / "ioc-custom.json"

_EMPTY: dict = {
    "c2_ips": [],
    "malicious_domains": [],
    "malicious_publishers": {},
    "file_hashes": {},
}


class IOCUpdater:
    """Updates IOC database from external feeds or local files."""

    def update_from_url(self, url: str) -> dict:
        """Download IOC data from a URL (JSON) and merge with custom IOCs.

        Returns stats dict with counts of new entries added.
        """
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ai-agent-audit"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = json.loads(resp.read().decode())
        except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError) as exc:
            logger.error("Failed to fetch IOC feed from %s: %s", url, exc)
            return {"error": str(exc)}

        return self._merge(raw)

    def update_from_file(self, path: Union[str, Path]) -> dict:
        """Load IOC data from a local JSON file and merge.

        Returns stats dict with counts of new entries added.
        """
        path = Path(path)
        try:
            raw = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            logger.error("Failed to load IOC file %s: %s", path, exc)
            return {"error": str(exc)}

        return self._merge(raw)

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
