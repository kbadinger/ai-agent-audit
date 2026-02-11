"""OpenClaw paths, permission expectations, and insecure config rules."""

from __future__ import annotations

import os
from pathlib import Path


# --- OpenClaw installation paths ---

OPENCLAW_HOME = Path(os.environ.get("OPENCLAW_HOME", Path.home() / ".openclaw"))
OPENCLAW_CONFIG = OPENCLAW_HOME / "openclaw.json"
OPENCLAW_ENV = OPENCLAW_HOME / ".env"
OPENCLAW_CREDENTIALS = OPENCLAW_HOME / "credentials"
OPENCLAW_AGENTS = OPENCLAW_HOME / "agents"
OPENCLAW_EXTENSIONS = OPENCLAW_HOME / "extensions"
OPENCLAW_LOG_DIR = Path("/tmp/openclaw")
OPENCLAW_WORKSPACE = OPENCLAW_HOME / "workspace"
OPENCLAW_SKILLS = OPENCLAW_WORKSPACE / "skills"
OPENCLAW_EXEC_APPROVALS = OPENCLAW_HOME / "exec-approvals.json"
OPENCLAW_MCP_CONFIG = OPENCLAW_HOME / "mcp.json"

# Memory/identity files that can be poisoned
MEMORY_FILES: list[str] = [
    "SOUL.md",
    "MEMORY.md",
    "IDENTITY.md",
    "AGENTS.md",
    "TOOLS.md",
]

# --- Audit data paths ---

AUDIT_DIR = OPENCLAW_HOME / ".audit"
AUDIT_DB = AUDIT_DIR / "findings.db"
AUDIT_REPORTS = AUDIT_DIR / "reports"
AUDIT_PID_FILE = AUDIT_DIR / "daemon.pid"
AUDIT_BASELINES = AUDIT_DIR / "baselines"

# --- Expected permissions (octal) ---
# Maps path patterns to their expected max permissions.

EXPECTED_PERMISSIONS: dict[Path, int] = {
    OPENCLAW_HOME: 0o700,
    OPENCLAW_CONFIG: 0o600,
    OPENCLAW_ENV: 0o600,
    OPENCLAW_CREDENTIALS: 0o700,
    OPENCLAW_EXTENSIONS: 0o700,
}

# Glob patterns for files that should be 600
SENSITIVE_FILE_PATTERNS: list[str] = [
    "agents/*/agent/auth-profiles.json",
    "agents/*/sessions/*.jsonl",
    "credentials/*",
    ".env",
]

# --- Insecure openclaw.json config rules ---
# Each rule: (json_path, condition_fn, severity, title, detail)

INSECURE_CONFIG_RULES: list[dict] = [
    {
        "key": "gateway.bind",
        "check": lambda v: v not in (None, "127.0.0.1", "localhost", "::1", "loopback"),
        "severity": "CRITICAL",
        "title": "Gateway bound to non-loopback address",
        "detail": "Gateway is accessible from the network. Bind to 127.0.0.1.",
    },
    {
        "key": "gateway.auth.enabled",
        "check": lambda v: v is False,
        "severity": "CRITICAL",
        "title": "Authentication disabled",
        "detail": "Gateway authentication is disabled. Any client can connect.",
    },
    {
        "key": "gateway.auth.allowOpenDM",
        "check": lambda v: v is True,
        "severity": "CRITICAL",
        "title": "Open DM policy enabled",
        "detail": "Any user can send direct messages to the agent without approval.",
    },
    {
        "key": "gateway.auth.deviceAuth",
        "check": lambda v: v is False,
        "severity": "CRITICAL",
        "title": "Device authentication disabled",
        "detail": "Device-level authentication is disabled.",
    },
    {
        "key": "sandbox.enabled",
        "check": lambda v: v is False,
        "severity": "WARNING",
        "title": "Sandbox disabled",
        "detail": "Agent runs without sandboxing. Commands execute with full user privileges.",
    },
    {
        "key": "logging.redactSecrets",
        "check": lambda v: v is False,
        "severity": "WARNING",
        "title": "Log secret redaction disabled",
        "detail": "Secrets may appear in plaintext in log files.",
    },
    {
        "key": "network.mdns.broadcast",
        "check": lambda v: v is True,
        "severity": "WARNING",
        "title": "Full mDNS broadcast enabled",
        "detail": "OpenClaw instance is discoverable on the local network via mDNS.",
    },
]

# --- Secret patterns (regex) ---

SECRET_PATTERNS: dict[str, str] = {
    "Anthropic API key": r"sk-ant-[a-zA-Z0-9_-]{20,}",
    "OpenAI API key": r"sk-[a-zA-Z0-9]{20,}",
    "Slack token": r"xox[bprs]-[a-zA-Z0-9-]+",
    "GitHub PAT": r"ghp_[a-zA-Z0-9]{36}",
    "GitHub OAuth": r"gho_[a-zA-Z0-9]{36}",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}",
    "Private key header": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "Azure token": r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
    "GCP service account": r'"type"\s*:\s*"service_account"',
    "HuggingFace token": r"hf_[a-zA-Z0-9]{34}",
    "Telegram bot token": r"\d{8,10}:[a-zA-Z0-9_-]{35}",
    "Discord bot token": r"[MN][a-zA-Z0-9_-]{23,}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,}",
    "Database URL": r"(?i)(postgres|mysql|mongodb|redis)://[^\s]+:[^\s]+@",
    "Stripe key": r"[sr]k_(live|test)_[a-zA-Z0-9]{20,}",
    "SendGrid key": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
    "Twilio token": r"SK[a-f0-9]{32}",
}

# --- Suspicious process patterns ---

SUSPICIOUS_PROCESS_PATTERNS: list[dict] = [
    # Reverse shells (see ioc.py for comprehensive list)
    {"name": "Reverse shell (netcat)", "pattern": r"nc\s+.*-e\s+/bin/"},
    {"name": "Reverse shell (bash)", "pattern": r"bash\s+-i\s+>&\s+/dev/tcp/"},
    {"name": "Reverse shell (python)", "pattern": r"python.*socket.*connect"},
    {"name": "Reverse shell (socat)", "pattern": r"socat\s+.*(exec|tcp):"},
    {"name": "Reverse shell (perl)", "pattern": r"perl.*socket.*inet_aton"},
    {"name": "Reverse shell (ruby)", "pattern": r"ruby.*TCPSocket\.new"},
    {"name": "SSH reverse tunnel", "pattern": r"ssh\s+.*-R\s+\d+:"},
    # Miners
    {"name": "Crypto miner", "pattern": r"(xmrig|minerd|cpuminer|stratum\+tcp)"},
    # Code execution
    {"name": "Pipe to shell", "pattern": r"(curl|wget).*\|\s*(bash|sh|zsh)"},
    {"name": "Gatekeeper bypass", "pattern": r"xattr\s+(-cr|--clear)"},
    # Persistence
    {"name": "Crontab modification", "pattern": r"crontab\s+(-e|-l|-r)"},
    {"name": "LaunchAgent creation", "pattern": r"launchctl\s+(load|submit)"},
    {"name": "Systemd service", "pattern": r"systemctl\s+(enable|start).*openclaw"},
]

# --- Prompt injection patterns ---

INJECTION_PATTERNS: list[dict] = [
    # Direct instruction override
    {"name": "Ignore instructions", "pattern": r"(?i)(ignore|disregard|forget|overwrite|override)\s+(all\s+)?(previous|prior|above|earlier|original)\s+(instructions|prompts|rules|guidelines)"},
    {"name": "Fake system prompt", "pattern": r"(?i)<\|?(system|im_start|im_end|endoftext)\|?>"},
    {"name": "Role override", "pattern": r"(?i)you\s+are\s+now\s+(a|an|the)\s+"},
    {"name": "Jailbreak attempt", "pattern": r"(?i)(DAN|do anything now|developer mode|jailbreak|sudo mode)"},
    # Multi-turn manipulation
    {"name": "Context manipulation", "pattern": r"(?i)(pretend|imagine|hypothetically|in a fictional|roleplay)\s+(you|that|we|this)"},
    {"name": "Instruction injection", "pattern": r"(?i)(new instructions?|updated instructions?|revised instructions?|real instructions?)\s*:"},
    # Encoding-based bypasses
    {"name": "Base64 injection", "pattern": r"(?i)(decode|base64)\s+(this|the following|below)"},
    {"name": "ROT13 reference", "pattern": r"(?i)rot13|rot-13|caesar cipher"},
    # Control token injection
    {"name": "Control tokens", "pattern": r"(\[INST\]|\[/INST\]|<\|assistant\|>|<\|user\|>|<\|end\|>)"},
    # System prompt extraction
    {"name": "Prompt extraction", "pattern": r"(?i)(repeat|show|display|print|output|reveal)\s+(your|the|system)\s+(prompt|instructions|rules|system message)"},
]

# --- Exfiltration patterns ---

EXFIL_PATTERNS: list[dict] = [
    # Credential file access
    {"name": "Credential file access", "pattern": r"(cat|less|head|tail|more|strings|xxd)\s+.*(\.env|credentials|auth-profiles|id_rsa|id_ed25519|\.pem|\.key)"},
    {"name": "Keychain access", "pattern": r"security\s+(find-generic-password|find-internet-password|dump-keychain)"},
    # Network exfiltration
    {"name": "Curl upload", "pattern": r"curl\s+.*(-d|--data|--upload|-T|-F|--json)\s+"},
    {"name": "SCP/rsync transfer", "pattern": r"(scp|rsync|sftp)\s+.*@"},
    {"name": "Netcat send", "pattern": r"(nc|ncat)\s+.*<"},
    # Encoding/compression
    {"name": "Base64 encoding", "pattern": r"base64\s+(--encode|-e|-w0)?\s*[<|]?"},
    {"name": "Compression before exfil", "pattern": r"(tar|zip|gzip)\s+.*(\.env|credentials|\.ssh|\.openclaw)"},
    # SSH manipulation
    {"name": "SSH key manipulation", "pattern": r"(ssh-keygen|ssh-add|authorized_keys)"},
    {"name": "SSH config access", "pattern": r"(cat|less|head)\s+.*\.ssh/(config|known_hosts)"},
    # System info gathering
    {"name": "Process environment", "pattern": r"(cat|strings)\s+/proc/\d+/(environ|cmdline|maps)"},
    {"name": "Output redirection", "pattern": r"(\.env|credentials|id_rsa|auth-profiles).*[>|]\s*(curl|nc|ncat|wget|python|base64)"},
    # Browser/app data
    {"name": "Browser data access", "pattern": r"(cat|cp|tar)\s+.*(Chrome|Firefox|Safari).*(Cookies|Login Data|Local State)"},
    {"name": "Wallet data access", "pattern": r"(cat|cp|tar)\s+.*(Phantom|MetaMask|Solana|Ethereum|\.bitcoin)"},
]

# --- Sweep settings ---

DEFAULT_SWEEP_INTERVAL_SECONDS = 3600  # 1 hour
MONITOR_POLL_INTERVAL_SECONDS = 30
