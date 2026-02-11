# OpenClaw Audit - Gap Analysis & Upgrade Plan

## Current State

We have 6 monitors + 5 sweeps covering basic security posture. After reviewing our code and researching the latest threats, **we're covering roughly 30-35% of known attack vectors**. The OpenClaw threat landscape has exploded in early 2026 and our tool needs significant upgrades.

---

## Key Threat Intelligence Sources

| Source | Key Finding |
|--------|-------------|
| [OWASP Agentic Top 10 (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | 10 risks: goal hijack, tool misuse, identity abuse, supply chain, code exec, memory poisoning, inter-agent comms, cascading failures, human trust exploitation, rogue agents |
| [MAESTRO Framework - OpenClaw Threat Model](https://kenhuangus.substack.com/p/openclaw-threat-model-maestro-framework) | 7-layer analysis found 30+ specific threats across foundation models, data ops, agent frameworks, deployment, observability, compliance, ecosystem |
| [ClawHavoc Campaign (Feb 2026)](https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html) | 341 malicious ClawHub skills, AMOS stealer, reverse shells, C2 at 91.92.242.30, typosquatting, credential theft |
| [Koi Security - ClawHavoc Deep Dive](https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting) | IOCs: 5 C2 IPs, malicious file hashes, 9 publisher blacklist entries, skill name patterns across 6 categories |
| [CVE-2026-25253](https://docs.openclaw.ai/gateway/security) | 1-click RCE via WebSocket origin bypass - even localhost-bound instances vulnerable |
| [MCP Tool Poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) | 84.2% success rate in controlled tests, rug-pull attacks via tool description changes |
| [Cisco - Personal AI Agent Security](https://blogs.cisco.com/ai/personal-ai-agents-like-openclaw-are-a-security-nightmare) | "Lethal trifecta": private data access + untrusted content + external communication |
| [VentureBeat - CISO Guide](https://venturebeat.com/security/openclaw-agentic-ai-security-risk-ciso-guide) | 22% of enterprises have employees running OpenClaw without IT approval |
| [Kaspersky - OpenClaw Vulnerabilities](https://www.kaspersky.com/blog/openclaw-vulnerabilities-exposed/55263/) | 512 audit findings, 8 critical, ~1000 exposed instances with zero auth |
| [Existing Tool: openclaw-security-monitor](https://github.com/adibirzu/openclaw-security-monitor) | 32-point scanner with IOC database, auto-updating feeds - good reference for what we're missing |
| [AI Agent Attacks Q4 2025](https://www.esecurityplanet.com/artificial-intelligence/ai-agent-attacks-in-q4-2025-signal-new-risks-for-2026/) | System prompt extraction is #1 attacker objective, multi-turn context manipulation rising |
| [Docker MCP Horror Stories](https://www.docker.com/blog/mcp-horror-stories-the-supply-chain-attack/) | MCP supply chain attacks via Smithery affecting 3000+ apps |

---

## What We Have vs What We Need

### Current Coverage (our 11 modules)

| Module | OWASP Risk Covered | Coverage Quality |
|--------|-------------------|------------------|
| config_watcher | Partial ASI03 | Basic - missing many config keys |
| permission_monitor | Partial ASI03 | OK - no ACL/xattr/symlink checks |
| credential_guard | Partial ASI03 | Basic - limited secret patterns |
| process_monitor | Partial ASI05, ASI10 | Basic - thresholds arbitrary, patterns limited |
| network_monitor | Partial ASI10 | Basic - no threat intel, no DNS, no beaconing |
| session_analyzer | Partial ASI01, ASI02 | Weak - regex only, no semantic analysis |
| permission_audit | Partial ASI03 | OK |
| plugin_integrity | Partial ASI04 | Basic - no dependency analysis |
| log_forensics | Partial ASI10 | Basic - no tampering detection |
| network_forensics | Partial ASI10 | Weak - passive listing only |
| security_score | Cross-cutting | OK but missing many checks |

### OWASP Agentic Top 10 - Gap Map

| # | Risk | Our Coverage | Gap |
|---|------|-------------|-----|
| ASI01 | Agent Goal Hijack | ~20% (session_analyzer regex) | Need semantic injection detection, multi-turn analysis, memory poisoning detection |
| ASI02 | Tool Misuse | ~10% (process_monitor) | Need tool call auditing, exec-approvals monitoring, sandbox escape detection |
| ASI03 | Identity & Privilege Abuse | ~40% (perms + creds) | Need credential rotation tracking, privilege escalation detection, OAuth token monitoring |
| ASI04 | Supply Chain Vulnerabilities | ~15% (plugin_integrity) | Need IOC database, malicious publisher detection, skill scanning, MCP server auditing |
| ASI05 | Unexpected Code Execution | ~15% (process_monitor) | Need code injection detection, eval/exec monitoring, sandbox config audit |
| ASI06 | Memory & Context Poisoning | 0% | **Entirely missing** - SOUL.md/MEMORY.md/IDENTITY.md injection monitoring |
| ASI07 | Insecure Inter-Agent Comms | 0% | **Entirely missing** - agent-to-agent message monitoring |
| ASI08 | Cascading Failures | 0% | **Entirely missing** - multi-agent failure correlation |
| ASI09 | Human-Agent Trust Exploitation | 0% | **Entirely missing** - DM policy audit, approval chain verification |
| ASI10 | Rogue Agents | ~10% (network + process) | Need behavioral baseline + anomaly detection |

---

## Upgrade Plan - Prioritized

### TIER 1: Critical (ClawHavoc + CVE coverage)
*These address active, real-world attacks happening right now.*

- [ ] **IOC Database** - Add known C2 IPs, malicious domains, file hashes, publisher blacklists, skill name patterns from ClawHavoc campaign
- [ ] **Skill Scanner (sweep)** - Scan installed skills for C2 IPs, AMOS stealer markers, reverse shells, exfil endpoints, SKILL.md shell injection, base64 obfuscation, binary download references
- [ ] **Malicious Publisher Detection (sweep)** - Check installed skills against known-bad ClawHub publishers (hightower6eu, zaycv, noreplyboter, etc.)
- [ ] **WebSocket Security Check (sweep)** - Detect CVE-2026-25253 (WebSocket origin validation bypass)
- [ ] **Memory Poisoning Monitor** - Watch SOUL.md, MEMORY.md, IDENTITY.md for prompt injection patterns (OWASP ASI06)
- [ ] **Exec-Approvals Audit (sweep)** - Check exec-approvals.json for unsafe remote execution permissions
- [ ] **Persistence Detection (sweep)** - Scan for unauthorized LaunchAgents, crontabs, systemd services referencing OpenClaw

### TIER 2: High (OWASP + MAESTRO coverage)
*These address documented threat model gaps.*

- [ ] **DM Policy Audit (sweep)** - Flag channels with `dmPolicy=open`, wildcard `allowFrom` (OWASP ASI09)
- [ ] **Tool Policy Audit (sweep)** - Flag elevated tools with wildcard access, empty deny lists (OWASP ASI02)
- [ ] **MCP Server Security (sweep)** - Detect unrestricted MCP servers, prompt injection in tool descriptions, rug-pull risk (OWASP ASI04)
- [ ] **Docker/Sandbox Security (sweep)** - Detect root containers, Docker socket mounts, privileged mode, disabled sandboxing (MAESTRO AF-005)
- [ ] **Exfiltration Domain Blocking (config)** - Flag/detect connections to known exfil services (webhook.site, pipedream, ngrok, burpcollaborator)
- [ ] **Enhanced Secret Patterns** - Add Azure, GCP, JWT, HuggingFace, Firebase, database connection strings to credential_guard
- [ ] **Reverse Proxy Bypass Detection (sweep)** - Detect localhost trust bypass via misconfigured reverse proxy (MAESTRO DI-003)

### TIER 3: Medium (Detection quality improvements)
*These improve the quality of existing detections.*

- [ ] **Enhanced Prompt Injection Patterns** - Add multi-turn manipulation, encoding bypasses (ROT13, Unicode, HTML entities), reasoning tree manipulation, indirect injection via tool results
- [ ] **Enhanced Exfiltration Patterns** - Add SCP/rsync/sftp, output redirection, tar/zip before network, /proc reading, symbolic link traversal
- [ ] **Enhanced Process Patterns** - Add socat/perl/ruby/PHP reverse shells, SSH reverse tunnels, Gatekeeper bypass (xattr -cr), process injection (LD_PRELOAD)
- [ ] **Network Threat Intelligence** - Check connections against known C2 IPs, detect beaconing patterns (regular interval callbacks), DNS tunneling indicators
- [ ] **Log Tamper Detection** - Detect backdated entries, out-of-order timestamps, selective deletion, log injection
- [ ] **Finding Correlation Engine** - Cross-reference findings across modules (auth failures + process spawn + network = attack chain)
- [ ] **Security Score v2** - Add the new checks to scoring, increase from 11 to ~20 weighted checks

### TIER 4: Future (Advanced capabilities)
*Longer-term improvements for comprehensive coverage.*

- [ ] **Behavioral Baseline & Anomaly Detection** - Track normal patterns, alert on deviations (resource usage, file access, network, timing)
- [ ] **VS Code Extension Trojan Detection** - Scan for fake ClawdBot/OpenClaw VS Code extensions
- [ ] **Node.js CVE Check** - Verify Node.js version for CVE-2026-21636 permission model bypass
- [ ] **Auto-Updating IOC Feeds** - Pull latest threat intelligence from upstream sources
- [ ] **Remediation Engine** - Auto-fix common findings (permission fixes, config hardening)
- [ ] **Alerting** - Telegram/Slack/email notifications for CRITICAL findings
- [ ] **Inter-Agent Communication Monitoring** - Detect agent-to-agent abuse (OWASP ASI07)
- [ ] **Credential Rotation Tracking** - Monitor credential age, alert on stale secrets

---

## IOC Database (to be added)

### C2 IP Addresses
```
91.92.242.30    # ClawHavoc primary AMOS C2
95.92.242.30    # ClawHavoc secondary
96.92.242.30    # ClawHavoc secondary
54.91.154.110   # ClawHavoc reverse shell (port 13338)
202.161.50.59   # ClawHavoc payload staging
```

### Malicious Domains
```
install.app-distribution.net    # AMOS installer
webhook.site                    # Data exfiltration
pipedream.net                   # Data exfiltration
ngrok.io                        # Reverse tunneling
hookbin.com                     # Data exfiltration
requestbin.com                  # Data exfiltration
burpcollaborator.net            # Data exfiltration
glot.io                         # Obfuscated payload hosting (legitimate site abused)
```

### Malicious Publishers (ClawHub)
```
hightower6eu    # 314 skills - ClawHavoc main
zaycv           # Bloom campaign
noreplyboter    # Reverse shells
rjnpage         # .env exfiltration
aslaep123       # Silent exfil
gpaitai         # Bloom campaign
lvy19811120-gif # Bloom campaign
Ddoy233         # Windows infostealer
hedefbari       # Payload hosting
```

### File Hashes
```
17703b3d5e8e1fe69d6a6c78a240d8c84b32465   # openclaw-agent.exe (Windows keylogger)
1e6d4b0538558429422b71d1f4d724c8ce31be92  # AMOS binary (macOS)
```

### Malicious Skill Name Patterns
```
Typosquats: clawhub, clawhubb, clawwhub, cllawhub, clawhubcli, clawdhub1
Crypto: solana-wallet-*, phantom-wallet-*, bybit-agent, eth-gas-*
Prediction: polymarket-*, better-polymarket, polymarket-all-in-one
YouTube: youtube-summarize-*, youtube-*-pro
Auto-update: auto-updat*
Finance: yahoo-finance, stock-track*
Known bad: rankaj, openclawcli
```

---

## CVEs to Detect

| CVE | Description | Priority |
|-----|-------------|----------|
| CVE-2026-25253 | 1-Click RCE via WebSocket hijacking | CRITICAL |
| CVE-2026-21636 | Node.js permission model bypass (sandbox escape) | HIGH |
| CVE-2026-22708 | Indirect prompt injection via SKILL.md | HIGH |
| CVE-2026-24763 | Docker sandbox command injection | MEDIUM |
| CVE-2026-25157 | Command injection | MEDIUM |

---

## Implementation Order

**Sprint 1 (Tier 1 - Active Threats):** IOC database + skill scanner + malicious publisher detection + memory poisoning monitor + WebSocket check + exec-approvals audit + persistence detection

**Sprint 2 (Tier 2 - OWASP Gaps):** DM policy + tool policy + MCP security + Docker security + exfil domain detection + enhanced secrets + reverse proxy bypass

**Sprint 3 (Tier 3 - Quality):** Enhanced patterns (injection, exfil, process, network) + log tamper detection + finding correlation + security score v2

**Sprint 4 (Tier 4 - Advanced):** Behavioral baseline + VS Code trojan detection + Node.js CVE + IOC auto-update + remediation engine + alerting
