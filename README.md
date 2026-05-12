# ai-agent-audit

Security audit daemon for local AI agent installations. Ships with built-in
profiles for [OpenClaw](https://github.com/openclaw) and Hermes, and adding a
new agent is a single dataclass entry away. Runs 7 always-on monitors and 25
periodic security sweeps with self-learning confidence calibration, produces
reports in 7 formats (SARIF, JSONL, CSV, ATT&CK Navigator, STIX 2.1, CycloneDX
SBOM), and optionally auto-remediates common issues.

## Supported Agents

| Slug | Display name | Home (default) | Config file | Override env |
|------|--------------|----------------|-------------|--------------|
| `openclaw` | OpenClaw | `~/.openclaw/` | `openclaw.json` | `OPENCLAW_HOME` |
| `hermes`   | Hermes   | `~/.hermes/`   | `hermes.json`   | `HERMES_HOME`   |

The auditor auto-detects which agent is installed and picks that profile.
Force a profile with `--agent {openclaw,hermes}` or by setting
`AI_AGENT_AUDIT_PROFILE=hermes` in the environment. Findings, the database,
and the daemon PID file are all stored under the profile's home (e.g.
`~/.hermes/.audit/`), so per-agent runs do not collide.

## Why This Exists

Local AI agents like OpenClaw run with full user-level permissions and ship
to hundreds of thousands of developer machines. Recent findings:

- **512 vulnerabilities** found in a single audit (8 critical)
- **135,000+ exposed instances** with zero authentication
- **ClawHavoc campaign**: 341 malicious skills on ClawHub distributing the AMOS stealer
- **CVE-2026-25253**: 1-click RCE via WebSocket origin validation bypass
- **CVE-2026-28363**: safeBins sandbox bypass (CVSS 9.9)
- **CVE-2026-21636**: Node.js permission model bypass via Unix Domain Sockets

The same risk patterns appear across other local agents — Hermes ships the
same gateway/sandbox/skill schema, so the same monitors and sweeps apply
once the profile abstraction tells them where to look.

## Installation

```bash
git clone https://github.com/kbadinger/ai-agent-audit.git
cd ai-agent-audit
pip install .
```

Requires **Python 3.10+**. Three dependencies: `watchdog`, `psutil`, `jinja2`.

## Quick Start

```bash
# Run a one-shot security scan (auto-detects OpenClaw or Hermes)
ai-agent-audit sweep

# Force a specific agent profile
ai-agent-audit --agent hermes sweep

# Generate an HTML report
ai-agent-audit report --open

# Export findings as SARIF (GitHub Code Scanning)
ai-agent-audit export --format sarif --output findings.sarif

# Triage findings
ai-agent-audit triage               # List all findings
ai-agent-audit triage 42 --confirm  # Mark as true positive

# Start the background daemon (monitors + hourly sweeps)
ai-agent-audit start
```

## What It Checks

### Always-On Monitors (7)

Run continuously in the background daemon:

| Monitor | What It Watches |
|---------|----------------|
| **config_watcher** | Active agent's config file for insecure settings (auth disabled, gateway exposed, sandbox off) |
| **permission_monitor** | File permission changes on the active agent's home critical paths |
| **credential_guard** | SHA-256 hashes credential files, alerts on any change or hardcoded secrets |
| **process_monitor** | Agent child processes: reverse shells, crypto miners, pipe-to-shell |
| **network_monitor** | Outbound connections: C2 IPs, exfiltration domains, unusual ports |
| **session_analyzer** | Session transcripts: prompt injection, exfiltration, encoding bypasses, tool abuse, social engineering patterns |
| **memory_poisoning_monitor** | SOUL.md, MEMORY.md, IDENTITY.md for injection payloads + path traversal in extraPaths |

### Periodic Deep Sweeps (25)

Run hourly (configurable) or on-demand via `ai-agent-audit sweep`:

| Sweep | What It Checks |
|-------|---------------|
| **permission_audit** | Full recursive permission scan + orphaned .tmp detection |
| **plugin_integrity** | SHA-256 hash all extensions, compare to baseline |
| **log_forensics** | Parse logs for crashes, auth failures, unredacted secrets, timestamp tampering |
| **network_forensics** | Snapshot connections, match against C2 IPs/domains from IOC database |
| **security_score** | Weighted 0-140 score across 18 checks, A-F grade |
| **skill_scanner** | Scan skills for C2 IPs, AMOS indicators, reverse shells, exfil endpoints |
| **websocket_security** | CVE-2026-25253 WebSocket origin validation + auth bypass checks |
| **exec_approvals_audit** | `exec-approvals.json` for unsafe command permissions |
| **persistence_detection** | LaunchAgents, crontabs, systemd services referencing the active agent |
| **dm_policy_audit** | Channel DM policies (open access, wildcard allowFrom) |
| **tool_policy_audit** | Elevated tools with wildcard access or empty deny lists |
| **mcp_security** | MCP server restrictions, tool description injection, IOC cross-reference |
| **docker_security** | Root containers, Docker socket mounts, privileged mode |
| **reverse_proxy_audit** | Localhost trust bypass, Tailscale auth, missing trustedProxies |
| **node_cve_check** | CVE-2026-21636 Node.js permission model bypass |
| **vscode_trojan_check** | Fake agent VS Code extensions (per profile patterns) |
| **behavioral_baseline** | Process/network/file count anomaly detection (rolling 7-snapshot, mean +/- 2 sigma) |
| **credential_rotation** | Tracks credential ages, alerts on stale (>90d) or very stale (>180d) |
| **agent_comm_audit** | Inter-agent communication: unauthorized messaging, credential leakage, escalation |
| **safebins_bypass** | CVE-2026-28363 safeBins sandbox bypass (CVSS 9.9) |
| **mcp_rugpull** | MCP tool description mutation detection (rug-pull attacks) |
| **unicode_injection** | Hidden Unicode/zero-width chars in config, memory, and skill files |
| **worm_propagation** | SANDWORM-style self-replicating agent propagation patterns |
| **custom_rules** | User-defined YAML detection rules |
| **correlation** | Multi-indicator attack chain detection (8 patterns) |

## Self-Learning Confidence System

Every finding carries a confidence score (0.0-1.0) that calibrates automatically:

1. **Initial enrichment** — findings are tagged with baseline confidence from 130+ mapping entries
2. **Triage feedback** — when you mark findings as true/false positives, the `PrecisionTracker` adjusts future confidence for that finding type
3. **IOC aging** — IOCs that haven't matched in 90+ days get reduced confidence
4. **Environment profiling** — sweeps irrelevant to your setup (no Docker? skip docker_security) are automatically skipped
5. **Alerting gates** — findings below confidence 0.2 are stored but not alerted on

```bash
ai-agent-audit triage               # List findings with confidence scores
ai-agent-audit triage 42 --confirm  # True positive — boosts similar findings
ai-agent-audit triage 43 --fp       # False positive — suppresses similar findings
```

## Export Formats (7)

```bash
ai-agent-audit export --format sarif      # SARIF v2.1.0 — GitHub Code Scanning
ai-agent-audit export --format jsonl      # JSONL — SIEM ingestion (Splunk, Elastic, Wazuh)
ai-agent-audit export --format csv        # CSV — spreadsheets, non-technical stakeholders
ai-agent-audit export --format navigator  # ATT&CK Navigator layer — visual coverage maps
ai-agent-audit export --format stix       # STIX 2.1 — threat intel sharing
ai-agent-audit export --format stix-ioc   # STIX 2.1 — IOC database as bundle
ai-agent-audit export --format sbom       # CycloneDX 1.5 — agent dependency inventory

# Write to file instead of stdout
ai-agent-audit export --format sarif --output findings.sarif
```

## Compliance Framework Tags

Every finding is automatically tagged with applicable compliance framework references:

| Framework | Coverage | Example Tag |
|-----------|----------|-------------|
| **OWASP Agentic Top 10** | ASI01-ASI10 | `ASI03` |
| **MITRE ATT&CK** | 40+ technique IDs | `T1190` |
| **EU AI Act** | Articles 9-17 | `Art.15(1),Art.9(2)` |
| **NIST AI RMF** | GV/MG/MP subcategories | `GV-1.1,MG-3.1` |

Tags appear in all export formats (SARIF, JSONL, STIX, Navigator).

## OWASP Agentic Top 10 Coverage

| Risk | Coverage | Key Modules |
|------|----------|-------------|
| ASI01 Agent Goal Hijack | ~80% | session_analyzer, memory_poisoning_monitor, unicode_injection |
| ASI02 Tool Misuse | ~60% | process_monitor, tool_policy_audit, exec_approvals_audit |
| ASI03 Identity & Privilege Abuse | ~70% | permission_audit, credential_guard, credential_rotation |
| ASI04 Supply Chain | ~80% | skill_scanner, plugin_integrity, mcp_security, mcp_rugpull |
| ASI05 Code Execution | ~65% | process_monitor, safebins_bypass, docker_security |
| ASI06 Memory Poisoning | ~70% | memory_poisoning_monitor, security_score |
| ASI07 Inter-Agent Comms | ~60% | agent_comm_audit, network_monitor |
| ASI08 Cascading Failures | ~55% | correlation (cascade + resource exhaustion), behavioral_baseline |
| ASI09 Human-Agent Trust | ~65% | session_analyzer (social engineering), dm_policy_audit |
| ASI10 Rogue Agents | ~75% | worm_propagation, persistence_detection, network_monitor, correlation |

## Custom YAML Rules

Extend detection without writing Python. Drop `.yaml` files in
`<agent-home>/.audit/rules/` (e.g. `~/.openclaw/.audit/rules/` or
`~/.hermes/.audit/rules/`):

```yaml
name: Detect hardcoded API key
target: file_content
pattern: sk-ant-[a-zA-Z0-9]{20,}
severity: critical
mitre_attack: T1552.001
owasp_asi: ASI03
remediation: Move API keys to environment variables.
```

**Rule targets:**
- `file_content` — scan files matching a glob for regex matches
- `config_value` — check a specific key in the active agent's config
- `file_exists` — alert if files matching a pattern exist

## Adding a New Agent Profile

Profiles live in `src/ai_agent_audit/agents.py`. Each profile is a dataclass
declaring where the agent stores config, credentials, skills, etc., plus the
process/persistence/vscode-extension keywords used by detectors. To add a
third agent:

1. Add a `_my_agent_profile()` helper following the OpenClaw/Hermes pattern.
2. Register it in `all_profiles()` and `SUPPORTED_PROFILES`.
3. (Optional) Add the new slug to `--agent` choices in `cli.py`.

Every monitor, sweep, and exporter that already reads from `ACTIVE_PROFILE`
or the legacy `OPENCLAW_*` constants will immediately apply to the new agent.

## CLI Reference

```
ai-agent-audit [--agent {openclaw,hermes,auto}] <command>

  start                  Start background daemon
  stop                   Stop daemon
  status                 Show active profile + daemon PID + finding summary
  sweep                  Run all 25 sweeps in foreground
  triage [ID] [--confirm|--fp|--dismiss]  Triage findings
  export [-f FORMAT] [-o FILE]            Export findings (7 formats)
  report [--open]        Generate HTML report
  fix [--dry-run]        Auto-remediate findings
  update-ioc [--url|--file]  Update IOC database
```

## Auto-Remediation

`ai-agent-audit fix` performs three types of fixes against the active agent:

- **Permission tightening**: Sets agent home to 700, config/credential files to 600 (only tightens, never loosens)
- **Config hardening**: Binds gateway to 127.0.0.1, enables auth, disables open DM, enables sandbox
- **Skill quarantine**: Moves skills matching known malicious patterns to a quarantine directory

Always run with `--dry-run` first.

## Alerting

Configure in `<agent-home>/.audit/alerts.json` (e.g. `~/.openclaw/.audit/alerts.json` or `~/.hermes/.audit/alerts.json`):

```json
{
  "enabled": true,
  "cooldown_seconds": 300,
  "min_alert_confidence": 0.5,
  "backends": [
    {"type": "macos"},
    {"type": "slack", "webhook_url": "https://hooks.slack.com/services/..."},
    {"type": "telegram", "token": "BOT_TOKEN", "chat_id": "CHAT_ID"},
    {"type": "webhook", "url": "https://your-endpoint.com/alerts", "headers": {"Authorization": "Bearer TOKEN"}},
    {"type": "file", "path": "/var/log/ai-agent-audit-alerts.log"}
  ]
}
```

5 backends: macOS notifications, Slack, Telegram, generic webhook (any URL), file log. Only CRITICAL findings with sufficient confidence trigger alerts.

## IOC Database

Ships with hardcoded IOCs from ClawHavoc and other campaigns. IOCs age automatically — unmatched for 90+ days get reduced confidence, 180+ days marked stale.

```bash
ai-agent-audit update-ioc --url https://example.com/ioc-feed.json
ai-agent-audit update-ioc --file /path/to/custom-iocs.json
ai-agent-audit update-ioc  # Show current stats
```

## Attack Chain Detection

The correlation engine detects 8 multi-indicator patterns:

| Pattern | Indicators | Window |
|---------|-----------|--------|
| Active Breach | Auth failures + suspicious processes + C2 connections | 1 hour |
| Privilege Escalation | Permission loosening + credential changes | 1 hour |
| Supply Chain Compromise | Extension changes + suspicious skills | 24 hours |
| Data Exfiltration | Exfil patterns + unusual network activity | 30 min |
| Coordinated Attack | 3+ CRITICAL findings from different modules | 15 min |
| Escalating Threat | Finding count >50% increase vs previous hour | 1 hour |
| Cascading Failure | 4+ modules failing + crashes/anomalies | 30 min |
| Resource Exhaustion | Process/connection spikes + crashes | 1 hour |

## Architecture

```
ai-agent-audit
  |
  +-- AgentProfile registry (OpenClaw, Hermes, ...)
  |     +-- ACTIVE_PROFILE resolved at startup from --agent / env / auto-detect
  |
  +-- AuditEngine (orchestrator)
  |     |-- 7 Monitors (always-on, threaded, callback-based)
  |     |-- 25 Sweeps (periodic, run-and-return)
  |     |-- PrecisionTracker (self-learning confidence calibration)
  |     |-- EnvironmentProfiler (skip irrelevant sweeps)
  |     +-- Alerter (5 backends, confidence-gated)
  |
  +-- FindingsDB (SQLite, thread-safe, dedup, triage, compliance tags)
  |
  +-- Export (SARIF, JSONL, CSV, Navigator, STIX, SBOM)
  |
  +-- ReportGenerator (Jinja2 HTML, dark theme, 30-day trends)
  |
  +-- RemediationEngine (permissions, config, skill quarantine)
  |
  +-- IOC Database (hardcoded + custom feeds, aging)
  |
  +-- Custom Rules Engine (YAML, no dependencies)
```

## Development

```bash
pip install -e .
pip install pytest
pytest tests/ -v   # 188 tests
```

## Platform Support

- **macOS**: Full support (primary target)
- **Linux**: Full support
- **Windows**: Sweep and report commands work. Daemon mode requires WSL.

## License

MIT
