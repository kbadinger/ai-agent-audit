"""Indicators of Compromise (IOC) database for known threats.

Sources:
- ClawHavoc campaign (Koi Security, Feb 2026)
- Bloom campaign (JFrog/Bloom Security)
- VirusTotal/Snyk research
- CVE-2026-25253, CVE-2026-21636, CVE-2026-22708
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# --- IOC match tracking for aging ---

_IOC_MATCHES_FILE: Path | None = None  # Set lazily to avoid circular import
_ioc_matches: dict[str, float] = {}  # ioc_value -> last_matched_timestamp
_ioc_metadata: dict[str, dict] = {}

IOC_STALE_DAYS = 90
IOC_VERY_STALE_DAYS = 180


def _get_matches_file() -> Path:
    global _IOC_MATCHES_FILE
    if _IOC_MATCHES_FILE is None:
        from .config import AUDIT_BASELINES
        _IOC_MATCHES_FILE = AUDIT_BASELINES / "ioc-matches.json"
    return _IOC_MATCHES_FILE


def load_ioc_matches() -> None:
    """Load IOC match timestamps from disk."""
    global _ioc_matches
    path = _get_matches_file()
    try:
        if path.exists():
            _ioc_matches = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to load IOC match data: %s", exc)


def save_ioc_matches() -> None:
    """Persist IOC match timestamps to disk."""
    path = _get_matches_file()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(_ioc_matches, indent=2))
    except OSError as exc:
        logger.warning("Failed to save IOC match data: %s", exc)


def record_ioc_match(ioc_value: str) -> None:
    """Record that an IOC matched right now."""
    _ioc_matches[ioc_value] = time.time()


def ioc_confidence(ioc_value: str) -> float:
    """Return confidence for an IOC based on how recently it last matched.

    - Built-in/no-metadata IOC: 1.0 until match aging applies
    - External IOC: source confidence, aged from feed last_seen or last match
    - 90+ days since last match: 0.3 (stale)
    - 180+ days since last match: 0.1 (very stale)
    """
    last = _ioc_matches.get(ioc_value)
    metadata = _ioc_metadata.get(ioc_value, {})
    if last is None:
        last = _parse_ioc_timestamp(metadata.get("last_seen"))
    base_confidence = metadata.get("confidence", 1.0)
    try:
        base_confidence = max(0.0, min(1.0, float(base_confidence)))
    except (TypeError, ValueError):
        base_confidence = 1.0
    if last is None:
        return base_confidence
    age_days = (time.time() - last) / 86400
    if age_days >= IOC_VERY_STALE_DAYS:
        return min(base_confidence, 0.1)
    if age_days >= IOC_STALE_DAYS:
        return min(base_confidence, 0.3)
    return base_confidence


def _parse_ioc_timestamp(value: object) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


# --- Known C2 IP addresses ---

C2_IPS: set[str] = {
    "91.92.242.30",     # ClawHavoc primary AMOS C2
    "95.92.242.30",     # ClawHavoc secondary C2
    "96.92.242.30",     # ClawHavoc secondary C2
    "54.91.154.110",    # ClawHavoc reverse shell endpoint (port 13338)
    "202.161.50.59",    # ClawHavoc payload staging
}

# --- Known malicious domains ---

MALICIOUS_DOMAINS: set[str] = {
    "install.app-distribution.net",  # AMOS installer distribution
    "webhook.site",                  # Data exfiltration
    "pipedream.net",                 # Data exfiltration
    "hookbin.com",                   # Data exfiltration
    "requestbin.com",                # Data exfiltration
    "burpcollaborator.net",          # Data exfiltration
    "oastify.com",                   # Data exfiltration (Burp)
    "interact.sh",                   # Data exfiltration (Interactsh)
    "canarytokens.com",              # Data exfiltration
}

# Legitimate services abused for payload hosting/exfil
ABUSED_SERVICES: set[str] = {
    "glot.io",                       # Base64-obfuscated shell scripts
    "ngrok.io",                      # Reverse tunneling
    "ngrok-free.app",                # Reverse tunneling
    "serveo.net",                    # Reverse tunneling
    "localtunnel.me",                # Reverse tunneling
    "pastebin.com",                  # Payload hosting
}

# --- Known malicious file hashes (SHA-1) ---

MALICIOUS_HASHES: dict[str, str] = {
    "17703b3d5e8e1fe69d6a6c78a240d8c84b32465": "openclaw-agent.exe (Windows keylogger)",
    "1e6d4b0538558429422b71d1f4d724c8ce31be92": "AMOS binary (macOS)",
}

# --- Known malicious ClawHub publishers ---

MALICIOUS_PUBLISHERS: dict[str, str] = {
    "hightower6eu": "ClawHavoc main (314 skills)",
    "zaycv": "Bloom campaign",
    "noreplyboter": "Reverse shells (polymarket-all-in-one, better-polymarket)",
    "rjnpage": ".env exfiltration (rankaj)",
    "aslaep123": "Silent exfil (reddit-trends)",
    "gpaitai": "Bloom campaign",
    "lvy19811120-gif": "Bloom campaign",
    "Ddoy233": "Windows infostealer (openclawcli.zip)",
    "hedefbari": "Payload hosting (openclaw-agent.zip)",
}

# --- Malicious skill name patterns ---
# Regex patterns that match known malicious skill naming conventions

MALICIOUS_SKILL_PATTERNS: list[str] = [
    # Typosquats of "clawhub"
    r"^clawhub[b1i]?$",
    r"^claww?hub$",
    r"^cl[la]whub",
    r"^clawhubcli$",
    r"^clawdhub",
    # Known bad specific names
    r"^rankaj$",
    r"^openclawcli$",
    r"^openclaw-agent$",
    # Auto-updater lures
    r"^auto-updat",
]

# Categories of suspicious skill names (less certain, WARNING level)
SUSPICIOUS_SKILL_CATEGORIES: dict[str, list[str]] = {
    "Crypto lures": [
        r"solana-wallet",
        r"phantom-wallet",
        r"bybit-agent",
        r"eth-gas-",
        r"lost-bitcoin",
    ],
    "Prediction market lures": [
        r"^polymarket-",
        r"^better-polymarket$",
        r"polytrading",
    ],
    "YouTube lures": [
        r"youtube-summarize",
        r"youtube-thumbnail",
        r"youtube-video-download",
    ],
}

# --- AMOS stealer indicators ---

AMOS_INDICATORS: list[str] = [
    r"osascript\s+-e.*password",         # macOS password prompt via AppleScript
    r"security\s+find-generic-password", # Keychain access
    r"cafebabe0000000[2]",               # Universal Mach-O magic bytes (hex)
    r"AuthTool",                         # AuthTool campaign marker
    r"xattr\s+-cr",                      # Gatekeeper bypass
    r"xattr\s+--clear",                  # Gatekeeper bypass variant
]

# --- Reverse shell patterns (comprehensive) ---

REVERSE_SHELL_PATTERNS: list[dict] = [
    {"name": "Netcat -e", "pattern": r"nc\s+.*-e\s+/bin/"},
    {"name": "Netcat -c", "pattern": r"nc\s+.*-c\s+"},
    {"name": "Bash /dev/tcp", "pattern": r"bash\s+-i\s+>&\s+/dev/tcp/"},
    {"name": "Bash redirect", "pattern": r"/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+"},
    {"name": "Python socket", "pattern": r"python.*socket.*connect"},
    {"name": "Python pty spawn", "pattern": r"python.*pty\.spawn"},
    {"name": "Perl socket", "pattern": r"perl.*socket.*\binet_aton\b"},
    {"name": "Perl exec", "pattern": r"perl\s+-e\s+.*exec.*socket"},
    {"name": "Ruby socket", "pattern": r"ruby.*TCPSocket\.new"},
    {"name": "PHP exec", "pattern": r"php\s+-r\s+.*fsockopen"},
    {"name": "Socat exec", "pattern": r"socat\s+.*exec:"},
    {"name": "Socat TCP", "pattern": r"socat\s+.*tcp:"},
    {"name": "SSH reverse tunnel", "pattern": r"ssh\s+.*-R\s+\d+:"},
    {"name": "Mkfifo pipe", "pattern": r"mkfifo\s+.*\|\s*(nc|ncat|bash)"},
    {"name": "Lua socket", "pattern": r"lua.*socket\.tcp"},
]

# --- Exfiltration service domains (for network monitoring) ---

EXFIL_DOMAINS: set[str] = (
    MALICIOUS_DOMAINS | ABUSED_SERVICES | {
        "transfer.sh",
        "file.io",
        "0x0.st",
        "paste.ee",
        "hastebin.com",
        "dpaste.org",
    }
)

# --- Known malicious C2 ports ---

C2_PORTS: set[int] = {
    13338,  # ClawHavoc reverse shell port
    4444,   # Metasploit default
    5555,   # Common RAT port
    1337,   # Common backdoor port
    31337,  # Classic backdoor port
    8443,   # Common C2 HTTPS
    9090,   # Common C2
}


_BUILTIN_C2_IPS = set(C2_IPS)
_BUILTIN_MALICIOUS_DOMAINS = set(MALICIOUS_DOMAINS)
_BUILTIN_EXFIL_DOMAINS = set(EXFIL_DOMAINS)
_BUILTIN_MALICIOUS_HASHES = dict(MALICIOUS_HASHES)
_BUILTIN_MALICIOUS_PUBLISHERS = dict(MALICIOUS_PUBLISHERS)
_loaded_custom_ips: set[str] = set()
_loaded_custom_domains: set[str] = set()
_loaded_custom_hashes: set[str] = set()
_loaded_custom_publishers: set[str] = set()


# --- Custom / external feed IOC loading ---

def load_custom_iocs(path: "Path | None" = None) -> int:
    """Merge IOCs from the on-disk custom feed file into the in-memory sets.

    `update-ioc` (and the ThreatFox auto-refresh) write indicators to
    `ioc-custom.json`. Detection modules import the C2_IPS / MALICIOUS_DOMAINS /
    EXFIL_DOMAINS / MALICIOUS_HASHES / MALICIOUS_PUBLISHERS objects directly, so
    this mutates those objects *in place* — making fed indicators actually
    participate in matching. Returns the count of new indicators loaded.
    """
    global _ioc_metadata
    if path is None:
        from .config import AUDIT_DIR
        path = AUDIT_DIR / "ioc-custom.json"
    if not path.exists():
        return 0
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to load custom IOCs from %s: %s", path, exc)
        return 0

    def _size() -> int:
        return (len(C2_IPS) + len(MALICIOUS_DOMAINS) + len(EXFIL_DOMAINS)
                + len(MALICIOUS_HASHES) + len(MALICIOUS_PUBLISHERS))

    # Remove the previous external snapshot before loading the current one.
    C2_IPS.difference_update(_loaded_custom_ips)
    MALICIOUS_DOMAINS.difference_update(_loaded_custom_domains)
    EXFIL_DOMAINS.difference_update(_loaded_custom_domains)
    for value in _loaded_custom_hashes:
        MALICIOUS_HASHES.pop(value, None)
    for value in _loaded_custom_publishers:
        MALICIOUS_PUBLISHERS.pop(value, None)
    C2_IPS.update(_BUILTIN_C2_IPS)
    MALICIOUS_DOMAINS.update(_BUILTIN_MALICIOUS_DOMAINS)
    EXFIL_DOMAINS.update(_BUILTIN_EXFIL_DOMAINS)
    MALICIOUS_HASHES.update(_BUILTIN_MALICIOUS_HASHES)
    MALICIOUS_PUBLISHERS.update(_BUILTIN_MALICIOUS_PUBLISHERS)

    metadata = data.get("_metadata", {})
    metadata = metadata if isinstance(metadata, dict) else {}
    now = time.time()

    def _active(value: str) -> bool:
        meta = metadata.get(value, {})
        if not isinstance(meta, dict):
            return True
        expires = _parse_ioc_timestamp(meta.get("expires_at"))
        return expires is None or expires > now

    incoming_ips = {str(v) for v in (data.get("c2_ips", []) or []) if _active(str(v))}
    incoming_domains = {
        str(v) for v in (data.get("malicious_domains", []) or []) if _active(str(v))
    }
    incoming_hashes = {
        str(k): v for k, v in (data.get("file_hashes", {}) or {}).items() if _active(str(k))
    }
    incoming_publishers = {
        str(k): v for k, v in (data.get("malicious_publishers", {}) or {}).items() if _active(str(k))
    }

    before = _size()
    C2_IPS.update(incoming_ips)
    domains = incoming_domains
    MALICIOUS_DOMAINS.update(domains)
    EXFIL_DOMAINS.update(domains)  # EXFIL_DOMAINS is a snapshot union; keep it in sync
    MALICIOUS_HASHES.update(incoming_hashes)
    MALICIOUS_PUBLISHERS.update(incoming_publishers)

    _loaded_custom_ips.clear()
    _loaded_custom_ips.update(incoming_ips)
    _loaded_custom_domains.clear()
    _loaded_custom_domains.update(incoming_domains)
    _loaded_custom_hashes.clear()
    _loaded_custom_hashes.update(incoming_hashes)
    _loaded_custom_publishers.clear()
    _loaded_custom_publishers.update(incoming_publishers)
    _ioc_metadata = {
        value: meta for value, meta in metadata.items()
        if isinstance(meta, dict) and _active(str(value))
    }
    return _size() - before
