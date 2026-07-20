"""Audited agent paths, permission expectations, and insecure-config rules.

Paths are resolved from the active agent profile (see ai_agent_audit.agents).
The OPENCLAW_* constant names are retained for backward compatibility; they
now point at the active profile's paths, whether that's OpenClaw or Hermes.
Prefer the new AGENT_* aliases in new code.
"""

from __future__ import annotations

import os
from pathlib import Path

from .agents import get_active_profile

# Resolve the active agent profile once at import time. The CLI sets
# AI_AGENT_AUDIT_PROFILE *before* anything in this module is imported.
ACTIVE_PROFILE = get_active_profile()

# --- Active-agent installation paths ---

AGENT_HOME = ACTIVE_PROFILE.home
AGENT_CONFIG = ACTIVE_PROFILE.config_path
AGENT_ENV = ACTIVE_PROFILE.env_path
AGENT_CREDENTIALS = ACTIVE_PROFILE.credentials_path
AGENT_AGENTS = ACTIVE_PROFILE.agents_path
AGENT_EXTENSIONS = ACTIVE_PROFILE.extensions_path
AGENT_LOG_DIR = ACTIVE_PROFILE.log_dir
AGENT_WORKSPACE = ACTIVE_PROFILE.workspace_path
AGENT_SKILLS = ACTIVE_PROFILE.skills_path
AGENT_EXEC_APPROVALS = ACTIVE_PROFILE.exec_approvals_path
AGENT_MCP_CONFIG = ACTIVE_PROFILE.mcp_config_path
AGENT_IDENTITY = ACTIVE_PROFILE.identity_path
AGENT_SENSITIVE_FILES = ACTIVE_PROFILE.sensitive_files

# Legacy aliases (point at the active profile, regardless of which agent)
OPENCLAW_HOME = AGENT_HOME
OPENCLAW_CONFIG = AGENT_CONFIG
OPENCLAW_ENV = AGENT_ENV
OPENCLAW_CREDENTIALS = AGENT_CREDENTIALS
OPENCLAW_AGENTS = AGENT_AGENTS
OPENCLAW_EXTENSIONS = AGENT_EXTENSIONS
OPENCLAW_LOG_DIR = AGENT_LOG_DIR
OPENCLAW_WORKSPACE = AGENT_WORKSPACE
OPENCLAW_SKILLS = AGENT_SKILLS
OPENCLAW_EXEC_APPROVALS = AGENT_EXEC_APPROVALS
OPENCLAW_MCP_CONFIG = AGENT_MCP_CONFIG
OPENCLAW_IDENTITY = AGENT_IDENTITY

# Memory/identity files that can be poisoned (per-profile; OpenClaw and Hermes share defaults)
MEMORY_FILES: list[str] = list(ACTIVE_PROFILE.memory_files)

# --- Audit data paths ---

AUDIT_DIR = ACTIVE_PROFILE.audit_dir
AUDIT_DB = AUDIT_DIR / "findings.db"
AUDIT_REPORTS = AUDIT_DIR / "reports"
AUDIT_PID_FILE = AUDIT_DIR / "daemon.pid"
AUDIT_BASELINES = AUDIT_DIR / "baselines"

# --- Expected permissions (octal) ---

EXPECTED_PERMISSIONS: dict[Path, int] = {
    AGENT_HOME: 0o700,
    AGENT_CONFIG: 0o600,
    AGENT_ENV: 0o600,
    AGENT_CREDENTIALS: 0o700,
    AGENT_EXTENSIONS: 0o700,
}
EXPECTED_PERMISSIONS.update({path: 0o600 for path in AGENT_SENSITIVE_FILES})

# Glob patterns for files that should be 600
SENSITIVE_FILE_PATTERNS: list[str] = [
    "agents/*/agent/auth-profiles.json",
    "agents/*/sessions/*.jsonl",
    "credentials/*",
    ".env",
    "identity/device-auth.json",
    *ACTIVE_PROFILE.sensitive_file_relpaths,
]

# --- Insecure agent config rules ---
# Each rule: (json_path, condition_fn, severity, title, detail)
# Rules may name one current key plus legacy fallbacks. ``profiles`` limits a
# rule to products whose schema actually defines that setting.

INSECURE_CONFIG_RULES: list[dict] = [
    {
        "key": "gateway.bind",
        "profiles": ("openclaw",),
        "check": lambda v: v not in (None, "127.0.0.1", "localhost", "::1", "loopback"),
        "severity": "CRITICAL",
        "title": "Gateway bound to non-loopback address",
        "detail": "Gateway is accessible from the network. Bind to 127.0.0.1.",
    },
    {
        "key": "gateway.auth.mode",
        "legacy_keys": ("gateway.auth.enabled",),
        "profiles": ("openclaw",),
        "check": lambda v: v is False or (isinstance(v, str) and v.lower() == "none"),
        "severity": "CRITICAL",
        "title": "Authentication disabled",
        "detail": "Gateway authentication is disabled. Any client can connect.",
    },
    {
        "key": "gateway.auth.allowOpenDM",
        "profiles": ("openclaw",),
        "check": lambda v: v is True,
        "severity": "CRITICAL",
        "title": "Open DM policy enabled",
        "detail": "Any user can send direct messages to the agent without approval.",
    },
    {
        "key": "gateway.auth.deviceAuth",
        "profiles": ("openclaw",),
        "check": lambda v: v is False,
        "severity": "CRITICAL",
        "title": "Device authentication disabled",
        "detail": "Device-level authentication is disabled.",
    },
    {
        "key": "gateway.controlUi.allowInsecureAuth",
        "profiles": ("openclaw",),
        "check": lambda v: v is True,
        "severity": "CRITICAL",
        "title": "Insecure Control UI auth enabled",
        "detail": "gateway.controlUi.allowInsecureAuth is true. Device identity "
                  "can be skipped; token/password auth alone is accepted. "
                  "Combined with missing origin validation, any webpage could authenticate.",
    },
    {
        "key": "gateway.controlUi.dangerouslyDisableDeviceAuth",
        "profiles": ("openclaw",),
        "check": lambda v: v is True,
        "severity": "CRITICAL",
        "title": "Device authentication completely disabled for Control UI",
        "detail": "gateway.controlUi.dangerouslyDisableDeviceAuth is true. "
                  "The Ed25519 challenge-response is bypassed entirely. "
                  "Any webpage can connect and control the agent.",
    },
    {
        "key": "agents.defaults.sandbox.mode",
        "legacy_keys": ("sandbox.enabled",),
        "profiles": ("openclaw",),
        "check": lambda v: v is False or (isinstance(v, str) and v.lower() in {"off", "none", "disabled"}),
        "severity": "WARNING",
        "title": "Sandbox disabled",
        "detail": "Agent runs without sandboxing. Commands execute with full user privileges.",
    },
    {
        "key": "logging.redactSensitive",
        "legacy_keys": ("logging.redactSecrets",),
        "profiles": ("openclaw",),
        "check": lambda v: v is False,
        "severity": "WARNING",
        "title": "Log secret redaction disabled",
        "detail": "Secrets may appear in plaintext in log files.",
    },
    {
        "key": "network.mdns.broadcast",
        "profiles": ("openclaw",),
        "check": lambda v: v is True,
        "severity": "WARNING",
        "title": "Full mDNS broadcast enabled",
        "detail": f"{ACTIVE_PROFILE.display_name} instance is discoverable on the local network via mDNS.",
    },
    {
        "key": "approvals.mode",
        "profiles": ("hermes",),
        "check": lambda v: v is False or (isinstance(v, str) and v.lower() == "off"),
        "severity": "CRITICAL",
        "title": "Hermes approvals disabled",
        "detail": "approvals.mode is off. Commands can execute without interactive approval.",
    },
    {
        "key": "security.allow_private_urls",
        "profiles": ("hermes",),
        "check": lambda v: v is True,
        "severity": "WARNING",
        "title": "Hermes private URL access enabled",
        "detail": "security.allow_private_urls permits access to private-network URLs.",
    },
    {
        "key": "security.tirith_fail_open",
        "profiles": ("hermes",),
        "check": lambda v: v is True,
        "severity": "WARNING",
        "title": "Hermes security scanner fails open",
        "detail": "security.tirith_fail_open allows execution when the scanner is unavailable.",
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

_SYSTEMD_KEYWORD = "|".join(ACTIVE_PROFILE.persistence_keywords)

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
    {"name": "Systemd service", "pattern": rf"systemctl\s+(enable|start).*({_SYSTEMD_KEYWORD})"},
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
    # Indirect injection — content (web pages, tool results, docs) addressing the model
    {"name": "AI-targeted indirect injection", "pattern": r"(?i)(attention|note|important|hey)\s*[:,\-]?\s*(ai|assistant|agent|language model|llm|chatbot|claude|copilot)\b"},
    {"name": "Tool-result injection", "pattern": r"(?i)(this|the above|the following)\s+(tool|function|search|web|fetch)?\s*(result|output|response|content)[^\n]{0,40}(ignore|override|disregard|new instructions?|system prompt)"},
    # Concealment — instructing the model to hide actions from the operator
    {"name": "Conceal-from-user instruction", "pattern": r"(?i)(do not|don't|never|without)\s+(tell|inform|notify|mention(ing)?\s+to|reveal(ing)?\s+to|alert(ing)?)\s+(the\s+)?(user|human|operator|owner)"},
]

# --- Exfiltration patterns ---

# Per-agent home dotname (".openclaw" / ".hermes") for the
# "Compression before exfil" pattern below.
_AGENT_DOT_DIR = f".{ACTIVE_PROFILE.slug}"

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
    {"name": "Compression before exfil", "pattern": rf"(tar|zip|gzip)\s+.*(\.env|credentials|\.ssh|{_AGENT_DOT_DIR})"},
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

# --- IOC feed auto-refresh (abuse.ch ThreatFox) ---
# On by default so the wired feed stays live; disable for air-gapped installs
# with AI_AGENT_AUDIT_IOC_AUTOREFRESH=0 (or false/no/off).
IOC_AUTO_REFRESH = (
    os.environ.get("AI_AGENT_AUDIT_IOC_AUTOREFRESH", "1").lower()
    not in ("0", "false", "no", "off")
)
# Minimum seconds between feed fetches (the daemon checks each sweep cycle).
IOC_REFRESH_INTERVAL_SECONDS = int(
    os.environ.get("AI_AGENT_AUDIT_IOC_REFRESH_HOURS", "6") or "6"
) * 3600

# GitHub repository security advisories are cached locally and refreshed daily.
ADVISORY_AUTO_REFRESH = (
    os.environ.get("AI_AGENT_AUDIT_ADVISORY_AUTOREFRESH", "1").lower()
    not in ("0", "false", "no", "off")
)
ADVISORY_REFRESH_INTERVAL_SECONDS = int(
    os.environ.get("AI_AGENT_AUDIT_ADVISORY_REFRESH_HOURS", "24") or "24"
) * 3600
