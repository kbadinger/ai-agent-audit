# openclaw-audit

Security audit daemon for [OpenClaw](https://github.com/openclaw) installations. Runs 7 always-on monitors and 20 periodic security sweeps, produces HTML reports, and optionally auto-remediates common issues.

## Why This Exists

OpenClaw is an open-source AI agent with 100k+ GitHub stars that runs locally with full user-level permissions. It connects to messaging platforms, manages SSH keys, .env files, and browser sessions. Recent findings:

- **512 vulnerabilities** found in a single audit (8 critical)
- **~1,000 publicly exposed instances** with zero authentication
- **ClawHavoc campaign**: 341 malicious skills on ClawHub distributing the AMOS stealer
- **CVE-2026-25253**: 1-click RCE via WebSocket origin validation bypass
- **CVE-2026-21636**: Node.js permission model bypass via Unix Domain Sockets

`openclaw-audit` monitors your installation for these threats and more.

## Installation

```bash
git clone https://github.com/kbadinger/openclaw-audit.git
cd openclaw-audit
pip install .
```

Requires **Python 3.10+**. Three dependencies: `watchdog`, `psutil`, `jinja2`.

## Quick Start

```bash
# Run a one-shot security scan
openclaw-audit sweep

# Generate an HTML report
openclaw-audit report --open

# Start the background daemon (monitors + hourly sweeps)
openclaw-audit start
```

## What It Checks

### Always-On Monitors (7)

These run continuously in the background daemon, reporting findings in real-time:

| Monitor | What It Watches |
|---------|----------------|
| **config_watcher** | `openclaw.json` for insecure settings (auth disabled, gateway exposed, sandbox off) |
| **permission_monitor** | File permission changes on `~/.openclaw/` critical paths |
| **credential_guard** | SHA-256 hashes credential files, alerts on any change or hardcoded secrets |
| **process_monitor** | OpenClaw child processes: reverse shells, crypto miners, pipe-to-shell |
| **network_monitor** | Outbound connections: C2 IPs, exfiltration domains, unusual ports |
| **session_analyzer** | Session transcripts: prompt injection, exfiltration patterns, encoding bypasses, tool abuse |
| **memory_poisoning_monitor** | SOUL.md, MEMORY.md, IDENTITY.md for injection payloads |

### Periodic Deep Sweeps (20)

These run hourly (configurable) or on-demand via `openclaw-audit sweep`:

| Sweep | What It Checks |
|-------|---------------|
| **permission_audit** | Full recursive `~/.openclaw/` permission scan |
| **plugin_integrity** | SHA-256 hash all extensions, compare to baseline |
| **log_forensics** | Parse logs for crashes, auth failures, unredacted secrets, timestamp tampering |
| **network_forensics** | Snapshot all listening/established connections, match against C2 IPs |
| **security_score** | Weighted 0-135 score across 17 checks, A-F grade |
| **skill_scanner** | Scan installed skills for C2 IPs, AMOS indicators, reverse shells, exfil endpoints |
| **websocket_security** | CVE-2026-25253 WebSocket origin validation check |
| **exec_approvals_audit** | `exec-approvals.json` for unsafe command permissions |
| **persistence_detection** | LaunchAgents, crontabs, systemd services referencing OpenClaw |
| **dm_policy_audit** | Channel DM policies (open access, wildcard allowFrom) |
| **tool_policy_audit** | Elevated tools with wildcard access or empty deny lists |
| **mcp_security** | MCP server restrictions, tool description injection |
| **docker_security** | Root containers, Docker socket mounts, privileged mode |
| **reverse_proxy_audit** | Localhost trust bypass, missing trustedProxies |
| **node_cve_check** | CVE-2026-21636 Node.js permission model bypass |
| **vscode_trojan_check** | Fake ClawdBot/OpenClaw VS Code extensions |
| **behavioral_baseline** | Process/network/file count anomaly detection vs stored baseline |
| **credential_rotation** | Tracks credential ages, alerts on stale (>90d) or very stale (>180d) |
| **agent_comm_audit** | Inter-agent communication: unauthorized messaging, credential leakage, escalation |
| **correlation** | Multi-indicator attack chain detection (6 patterns) |

## OWASP Agentic Top 10 Coverage

| Risk | Coverage | Modules |
|------|----------|---------|
| ASI01 Agent Goal Hijack | ~70% | session_analyzer, memory_poisoning_monitor |
| ASI02 Tool Misuse | ~60% | process_monitor, tool_policy_audit, exec_approvals_audit |
| ASI03 Identity & Privilege Abuse | ~70% | permission_audit, credential_guard, credential_rotation |
| ASI04 Supply Chain | ~70% | skill_scanner, plugin_integrity, mcp_security |
| ASI05 Code Execution | ~50% | process_monitor, exec_approvals_audit, docker_security |
| ASI06 Memory Poisoning | ~70% | memory_poisoning_monitor, security_score |
| ASI07 Inter-Agent Comms | ~60% | agent_comm_audit, network_monitor |
| ASI08 Cascading Failures | ~30% | log_forensics, behavioral_baseline, correlation |
| ASI09 Human-Agent Trust | ~50% | dm_policy_audit, tool_policy_audit |
| ASI10 Rogue Agents | ~60% | network_monitor, process_monitor, persistence_detection, correlation |

## CLI Reference

```
openclaw-audit start                  # Start background daemon
openclaw-audit stop                   # Stop daemon
openclaw-audit status                 # Show daemon PID + finding summary
openclaw-audit sweep                  # Run all 20 sweeps in foreground
openclaw-audit report [--open]        # Generate HTML report (--open to view)
openclaw-audit fix [--dry-run]        # Auto-remediate findings (--dry-run to preview)
openclaw-audit update-ioc [--url URL | --file PATH]  # Update IOC database
```

### Auto-Remediation

`openclaw-audit fix` performs three types of fixes:

- **Permission tightening**: Sets `~/.openclaw/` to 700, config/credential files to 600 (only tightens, never loosens)
- **Config hardening**: Binds gateway to 127.0.0.1, enables auth, disables open DM, enables sandbox
- **Skill quarantine**: Moves skills matching known malicious patterns to a quarantine directory

Always run with `--dry-run` first to preview changes.

## Alerting

Configure alerts in `~/.openclaw/.audit/alerts.json`:

```json
{
  "enabled": true,
  "cooldown_seconds": 300,
  "backends": [
    {"type": "macos"},
    {"type": "slack", "webhook_url": "https://hooks.slack.com/services/..."},
    {"type": "telegram", "token": "BOT_TOKEN", "chat_id": "CHAT_ID"},
    {"type": "file", "path": "/var/log/openclaw-alerts.log"}
  ]
}
```

Only CRITICAL findings trigger alerts. Duplicate alerts are suppressed for the cooldown period (default 5 minutes).

## IOC Database

The tool ships with hardcoded Indicators of Compromise from the ClawHavoc campaign and other sources:

- 5 C2 IP addresses
- 9 malicious domains + 6 abused services
- 9 known malicious ClawHub publishers
- 15 reverse shell patterns
- AMOS stealer indicators

Add your own threat intel:

```bash
# From a URL (JSON format)
openclaw-audit update-ioc --url https://example.com/ioc-feed.json

# From a local file
openclaw-audit update-ioc --file /path/to/custom-iocs.json

# View current IOC stats
openclaw-audit update-ioc
```

Custom IOCs are stored in `~/.openclaw/.audit/ioc-custom.json` and merged with the built-in database at runtime.

**Feed JSON format:**

```json
{
  "c2_ips": ["1.2.3.4"],
  "malicious_domains": ["evil.example.com"],
  "malicious_publishers": {"badactor": "Campaign name"},
  "file_hashes": {"sha1hash": "Description"}
}
```

## Attack Chain Detection

The correlation engine detects multi-indicator attack patterns by analyzing findings across modules within time windows:

| Pattern | Indicators | Window |
|---------|-----------|--------|
| **Active Breach** | Auth failures + suspicious processes + C2 connections | 1 hour |
| **Privilege Escalation** | Permission loosening + credential changes | 1 hour |
| **Supply Chain Compromise** | Extension changes + suspicious skills | 24 hours |
| **Data Exfiltration** | Exfil patterns in sessions + unusual network activity | 30 min |
| **Coordinated Attack** | 3+ CRITICAL findings from different modules | 15 min |
| **Escalating Threat** | Finding count >50% increase vs previous hour | 1 hour |

## Architecture

```
openclaw-audit
  |
  +-- AuditEngine (orchestrator)
  |     |-- 7 Monitors (always-on, threaded, callback-based)
  |     |-- 20 Sweeps (periodic, run-and-return)
  |     +-- Alerter (dispatches CRITICAL findings to configured backends)
  |
  +-- FindingsDB (SQLite, thread-safe, deduplication via SHA-256)
  |
  +-- ReportGenerator (Jinja2 HTML, dark theme, 30-day trend chart)
  |
  +-- RemediationEngine (permission tightening, config hardening, skill quarantine)
  |
  +-- IOCUpdater (merge external threat intel feeds)
```

**Data stored in** `~/.openclaw/.audit/`:
- `findings.db` - SQLite database of all findings
- `baselines/` - Extension hashes, behavioral baseline, credential ages
- `reports/` - Generated HTML reports
- `alerts.json` - Alert configuration
- `ioc-custom.json` - Custom IOC data from feeds
- `quarantine/` - Quarantined malicious skills
- `audit.log` - Daemon log file

## Threat Intelligence Sources

- [ClawHavoc campaign](https://koisecurity.com) - 341 malicious ClawHub skills, AMOS stealer C2 infrastructure
- [CVE-2026-25253](https://nvd.nist.gov) - WebSocket origin validation bypass (1-click RCE)
- [CVE-2026-21636](https://nvd.nist.gov) - Node.js permission model bypass via UDS
- [OWASP Agentic Security Top 10](https://owasp.org/www-project-agentic-ai-threats/) - ASI01-ASI10
- [MAESTRO Framework](https://github.com/peterychang/maestro) - 7-layer threat model for agentic AI

## Development

```bash
pip install -e .
pip install pytest
pytest tests/ -v   # 43 tests
```

## Platform Support

- **macOS**: Full support (primary target)
- **Linux**: Full support
- **Windows**: Sweep and report commands work. Daemon mode (start/stop) requires WSL.

## License

MIT
