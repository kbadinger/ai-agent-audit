"""Indicators of Compromise (IOC) database for known threats.

Sources:
- ClawHavoc campaign (Koi Security, Feb 2026)
- Bloom campaign (JFrog/Bloom Security)
- VirusTotal/Snyk research
- CVE-2026-25253, CVE-2026-21636, CVE-2026-22708
"""

from __future__ import annotations

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
