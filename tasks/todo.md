# OpenClaw Audit Tool - Implementation TODO

## Phase 1: Foundation
- [x] Create `pyproject.toml` with project metadata and 3 deps (watchdog, psutil, jinja2)
- [x] Create `src/openclaw_audit/__init__.py`
- [x] Create `models.py` - Finding, Severity, ModuleResult dataclasses
- [x] Create `config.py` - OpenClaw paths, permission expectations, insecure config rules
- [x] Create `db.py` - SQLite schema, queries, deduplication

## Phase 2: Core Infrastructure
- [x] Create `monitors/base.py` - Abstract BaseMonitor
- [x] Create `sweeps/base.py` - Abstract BaseSweep
- [x] Create `engine.py` - Orchestrator: loads modules, runs schedules
- [x] Create `daemon.py` - PID file, fork, signal handling

## Phase 3: Always-On Monitors (v1)
- [x] Create `monitors/config_watcher.py` - Watch openclaw.json for insecure settings
- [x] Create `monitors/permission_monitor.py` - Track file permission changes
- [x] Create `monitors/credential_guard.py` - SHA-256 hash credential files, detect changes
- [x] Create `monitors/process_monitor.py` - Track child processes, flag suspicious spawns
- [x] Create `monitors/network_monitor.py` - Track outbound connections
- [x] Create `monitors/session_analyzer.py` - Parse transcripts for injection/exfil patterns

## Phase 4: Periodic Deep Sweeps (v1)
- [x] Create `sweeps/permission_audit.py` - Full recursive permission scan
- [x] Create `sweeps/plugin_integrity.py` - Hash extensions, compare baseline
- [x] Create `sweeps/log_forensics.py` - Parse logs for anomalies
- [x] Create `sweeps/network_forensics.py` - Snapshot listening/established connections
- [x] Create `sweeps/security_score.py` - 0-100 weighted score, A-F grade

## Phase 5: Reporting + CLI
- [x] Create `templates/report.html.j2` - HTML report template
- [x] Create `report.py` - Jinja2 HTML report generator
- [x] Create `cli.py` - CLI: start/stop/status/sweep/report
- [x] Create `__main__.py` - python -m support

## Phase 6: Verification (v1)
- [x] `pip install -e .` succeeds
- [x] `openclaw-audit sweep` runs and prints findings
- [x] `openclaw-audit report` generates HTML report
- [x] `openclaw-audit start` / `status` / `stop` work

---

## Upgrade Sprint: Threat Intelligence & Active Threat Coverage

### IOC Database & Config Enhancements
- [x] Create `ioc.py` - C2 IPs, malicious domains, file hashes, publisher blacklists, skill patterns, AMOS indicators, reverse shell patterns
- [x] Update `config.py` - Add OPENCLAW_WORKSPACE, SKILLS, EXEC_APPROVALS, MCP_CONFIG, MEMORY_FILES paths
- [x] Enhance SECRET_PATTERNS - Added Azure, GCP, HuggingFace, Telegram, Discord, database URLs, Stripe, SendGrid, Twilio
- [x] Enhance SUSPICIOUS_PROCESS_PATTERNS - Added socat, perl, ruby shells, SSH tunnels, Gatekeeper bypass, persistence patterns
- [x] Enhance INJECTION_PATTERNS - Added context manipulation, instruction injection, base64/ROT13 bypass, control tokens, prompt extraction
- [x] Enhance EXFIL_PATTERNS - Added keychain access, SCP/rsync, compression, SSH config, /proc access, browser/wallet data

### Tier 1: Active Threat Sweeps
- [x] Create `sweeps/skill_scanner.py` - Scan skills for C2 IPs, AMOS, reverse shells, exfil endpoints, SKILL.md injection, base64 obfuscation
- [x] Create `sweeps/websocket_security.py` - CVE-2026-25253 WebSocket origin validation check
- [x] Create `sweeps/exec_approvals_audit.py` - Check exec-approvals.json for unsafe permissions
- [x] Create `sweeps/persistence_detection.py` - LaunchAgents, crontabs, systemd services
- [x] Create `monitors/memory_poisoning_monitor.py` - SOUL.md, MEMORY.md, IDENTITY.md injection detection

### Tier 2: OWASP Gap Closure
- [x] Create `sweeps/dm_policy_audit.py` - Channel DM policy checks (open, wildcard allowFrom)
- [x] Create `sweeps/tool_policy_audit.py` - Elevated tools with wildcard access, empty deny lists
- [x] Create `sweeps/mcp_security.py` - MCP server restrictions, tool description injection
- [x] Create `sweeps/docker_security.py` - Root containers, Docker socket, privileged mode
- [x] Create `sweeps/reverse_proxy_audit.py` - Localhost trust bypass, missing trustedProxies

### Tier 3: Detection Quality Improvements
- [x] Enhance `network_forensics.py` - C2 IP matching from IOC database
- [x] Enhance `network_monitor.py` - Real-time C2 IP and exfil domain detection
- [x] Enhance `log_forensics.py` - Log tamper detection (out-of-order timestamps)
- [x] Rewrite `security_score.py` - Expanded to 17 checks, 135 points, new grade thresholds

### Tier 4: Advanced Capabilities
- [x] Create `sweeps/node_cve_check.py` - CVE-2026-21636 Node.js permission model bypass
- [x] Create `sweeps/vscode_trojan_check.py` - Fake ClawdBot/OpenClaw VS Code extension detection
- [x] Update `engine.py` - Register all 7 monitors + 16 sweeps

### Verification (v2)
- [x] `pip install -e .` succeeds with all new modules
- [x] `openclaw-audit sweep` runs 16 sweeps, 22 findings
- [x] `openclaw-audit report` generates report with all findings
- [x] `openclaw-audit start/status/stop` daemon lifecycle works
- [x] All 7 monitors registered
- [x] All 16 sweeps registered and passing

---

## Sprint 3: Intelligence & Automation

### Finding Correlation Engine
- [x] Create `sweeps/correlation.py` - 6 attack chain patterns: Active Breach, Privilege Escalation, Supply Chain Compromise, Data Exfiltration, Coordinated Attack, Escalating Threat
- [x] Register CorrelationSweep in engine.py

### Alerting System
- [x] Create `alerting.py` - Alerter class with 4 backends: Telegram, Slack webhook, macOS notification, file log
- [x] Cooldown deduplication per finding hash
- [x] Hook Alerter into engine._on_finding callback
- [x] Config via `~/.openclaw/.audit/alerts.json`

### IOC Auto-Updater
- [x] Create `ioc_updater.py` - IOCUpdater with URL and file feed ingestion
- [x] Merges external IOCs into `~/.openclaw/.audit/ioc-custom.json`
- [x] Add `openclaw-audit update-ioc` CLI command (--url, --file flags)

### Remediation Engine
- [x] Create `remediate.py` - RemediationEngine with dry_run support
- [x] Permission tightening (only tightens, never loosens)
- [x] Config hardening (gateway bind, auth, sandbox, log redaction)
- [x] Malicious skill quarantine (moved to quarantine dir, not deleted)
- [x] Add `openclaw-audit fix` CLI command (--dry-run flag)

### Enhanced Session Analyzer
- [x] Rewrite `monitors/session_analyzer.py` with multi-turn injection tracking (sliding window)
- [x] Encoding bypass detection (base64, hex, unicode obfuscation)
- [x] Premise shifting detection (context-establishing + role language)
- [x] Tool call abuse monitoring (dangerous tools, sensitive paths)
- [x] Rate limiting (>30 msgs/min flood, >5 injections/5min sustained attack)
- [x] File truncation/rotation handling

### Verification (v3)
- [x] `pip install -e .` succeeds with all new modules
- [x] `openclaw-audit sweep` runs 17 sweeps, 24 findings (including correlation)
- [x] `openclaw-audit fix --dry-run` shows remediation actions
- [x] `openclaw-audit update-ioc` shows IOC database stats
- [x] `openclaw-audit report` generates report with all findings
- [x] `openclaw-audit start/status/stop` daemon lifecycle works
- [x] All 7 monitors registered
- [x] All 17 sweeps registered and passing

---

## Review (Sprint 3)

### Final Stats
- **43 source files** (42 .py + 1 .j2)
- **7 always-on monitors**: config_watcher, permission_monitor, credential_guard, process_monitor, network_monitor, session_analyzer (enhanced), memory_poisoning_monitor
- **17 periodic sweeps**: permission_audit, plugin_integrity, log_forensics, network_forensics, security_score, skill_scanner, websocket_security, exec_approvals_audit, persistence_detection, dm_policy_audit, tool_policy_audit, mcp_security, docker_security, reverse_proxy_audit, node_cve_check, vscode_trojan_check, correlation
- **1 IOC database** (hardcoded + auto-updatable custom feeds)
- **1 alerting system** (4 backends: Telegram, Slack, macOS, file)
- **1 remediation engine** (permissions, config, skill quarantine)
- **7 CLI commands**: start, stop, status, sweep, report, fix, update-ioc

### New Capabilities
- **Attack chain detection**: 6 correlation patterns that detect multi-indicator attacks
- **Real-time alerting**: Critical findings trigger notifications (configurable backends)
- **Auto-fix**: Permission tightening, config hardening, malicious skill quarantine
- **IOC feeds**: Merge external threat intel from URLs or local files
- **Advanced session analysis**: Multi-turn tracking, encoding bypass detection, tool abuse monitoring, rate limiting

---

## Sprint 4: Final Coverage

### Behavioral Baseline & Anomaly Detection
- [x] Create `sweeps/behavioral_baseline.py` - BehavioralBaselineSweep
- [x] Establishes baselines: process count, connection count, listening ports, extension/credential/skill counts
- [x] Detects anomalies: 3x+ process spike (WARNING), new listening ports (CRITICAL), credential file count change (CRITICAL), extension count >20% change (WARNING), 5x+ connection spike (WARNING)
- [x] Rolling baseline updates after each run
- [x] Registered in engine.py

### Credential Rotation Tracking
- [x] Create `sweeps/credential_rotation.py` - CredentialRotationSweep
- [x] Tracks: .env, credentials/*, auth-profiles.json, ~/.ssh/id_*
- [x] Alerts: >180 days stale (CRITICAL), >90 days aging (WARNING), modified <1 hour (INFO)
- [x] Stores ages in baselines/credential-ages.json
- [x] Registered in engine.py

### Inter-Agent Communication Monitoring (OWASP ASI07)
- [x] Create `sweeps/agent_comm_audit.py` - AgentCommAuditSweep
- [x] Agent discovery from OPENCLAW_AGENTS directory
- [x] Session transcript analysis: cross-agent messaging, credential leakage, high-volume sessions, permission escalation
- [x] Config checks: agent isolation, inter-agent policy, wildcard peer access
- [x] Caps file reading at 10,000 lines for safety
- [x] Registered in engine.py

### Verification (v4)
- [x] `pip install -e .` succeeds
- [x] `openclaw-audit sweep` runs 20 sweeps, 34 findings
- [x] All 7 monitors + 20 sweeps registered
- [x] Behavioral baseline, credential rotation, and agent comm audit all producing findings

---

## Final Review

### Project Stats
- **46 source files** (45 .py + 1 .j2)
- **7 always-on monitors**: config_watcher, permission_monitor, credential_guard, process_monitor, network_monitor, session_analyzer, memory_poisoning_monitor
- **20 periodic sweeps**: permission_audit, plugin_integrity, log_forensics, network_forensics, security_score, skill_scanner, websocket_security, exec_approvals_audit, persistence_detection, dm_policy_audit, tool_policy_audit, mcp_security, docker_security, reverse_proxy_audit, node_cve_check, vscode_trojan_check, behavioral_baseline, credential_rotation, agent_comm_audit, correlation
- **1 IOC database** (hardcoded + auto-updatable custom feeds)
- **1 alerting system** (4 backends: Telegram, Slack, macOS, file)
- **1 remediation engine** (permissions, config, skill quarantine)
- **7 CLI commands**: start, stop, status, sweep, report, fix, update-ioc

### OWASP Agentic Top 10 Coverage (Final)
| Risk | Coverage |
|------|----------|
| ASI01 Agent Goal Hijack | ~70% (session_analyzer + memory_poisoning + enhanced patterns + multi-turn detection) |
| ASI02 Tool Misuse | ~60% (process_monitor + tool_policy_audit + exec_approvals + session tool abuse) |
| ASI03 Identity & Privilege Abuse | ~70% (perms + creds + secrets + credential_rotation) |
| ASI04 Supply Chain | ~70% (skill_scanner + plugin_integrity + IOC database + mcp_security) |
| ASI05 Code Execution | ~50% (process_monitor + exec_approvals + docker_security + behavioral_baseline) |
| ASI06 Memory Poisoning | ~70% (memory_poisoning_monitor + security_score check) |
| ASI07 Inter-Agent Comms | ~60% (agent_comm_audit + network_monitor + session_analyzer) |
| ASI08 Cascading Failures | ~30% (log_forensics + behavioral_baseline + correlation) |
| ASI09 Human-Agent Trust | ~50% (dm_policy_audit + tool_policy_audit) |
| ASI10 Rogue Agents | ~60% (network + process + persistence + behavioral_baseline + correlation) |

---

## Code Quality & Completeness Audit

### CRITICAL Issues (Will crash or produce wrong results)

#### C1. report.py score parsing is broken
**File**: `/Users/kevinbadinger/Projects/openClawAudit/src/openclaw_audit/report.py` line 43
**Issue**: `score = int(f["title"].split(":")[0])` attempts to parse "Security Score" as an integer, which will always raise `ValueError`. The title from `security_score.py` is formatted as `"Security Score: {score}/135 (Grade: {grade})"`, so `split(":")[0]` yields `"Security Score"`, not a number. The `try/except` catches it silently, so the report will always show "?" for the score instead of the actual grade.
**Fix**: Change to `int(f["title"].split(":")[1].strip().split("/")[0])` or parse with a regex.

#### C2. report.py grade thresholds are inconsistent with security_score.py
**File**: `/Users/kevinbadinger/Projects/openClawAudit/src/openclaw_audit/report.py` lines 49-58
**File**: `/Users/kevinbadinger/Projects/openClawAudit/src/openclaw_audit/sweeps/security_score.py` lines 48-57
**Issue**: `report.py` uses thresholds of 90/80/70/60 (out of 100), while `security_score.py` uses thresholds of 120/100/80/60 (out of 135). The grade computed in the report will differ from the grade shown in the security_score finding. Even if C1 is fixed, a score of 105 would be grade "B" per security_score.py but grade "A" per report.py.
**Fix**: Use the same `_grade()` function from security_score.py, or embed the grade in the finding and just extract it.

#### C3. report.html.j2 shows "score/100" but actual max is 135
**File**: `/Users/kevinbadinger/Projects/openClawAudit/src/openclaw_audit/templates/report.html.j2` line 174
**Issue**: The template displays `{{ score }}/100` but the actual maximum score is 135. This misleads users.
**Fix**: Change to `{{ score }}/135` or pass the max score as a template variable.

#### C4. security_score.py docstring says "0-100" but max is 135
**File**: `/Users/kevinbadinger/Projects/openClawAudit/src/openclaw_audit/sweeps/security_score.py` line 1
**Issue**: Module docstring says "Compute a weighted 0-100 security score" but the 17 checks sum to 135 points. This is a documentation/code mismatch introduced when new checks were added.

#### C5. daemon.py `os.fork()` will crash on Windows
**File**: `/Users/kevinbadinger/Projects/openClawAudit/src/openclaw_audit/daemon.py` line 55
**Issue**: `os.fork()` is Unix-only and does not exist on Windows. The `daemonize()` function will raise `AttributeError: module 'os' has no attribute 'fork'` on Windows. While this project primarily targets macOS/Linux, there is no guard or error message.
**Fix**: Add a `platform.system()` check at the top of `daemonize()` or catch `AttributeError` with a clear error message.

#### C6. daemon.py resource leak in `daemonize()`
**File**: `/Users/kevinbadinger/Projects/openClawAudit/src/openclaw_audit/daemon.py` line 69
**Issue**: `devnull = open(os.devnull, "r+b")` is never closed. The file descriptor leaks. While not a crash, it is a resource leak in a long-running daemon.
**Fix**: After the `dup2` calls, `devnull.close()`.

### WARNING Issues (Functional problems)

#### W1. CorrelationSweep creates its own FindingsDB -- potential SQLite locking
**File**: `/Users/kevinbadinger/Projects/openClawAudit/src/openclaw_audit/sweeps/correlation.py` line 27
**Issue**: `CorrelationSweep.run()` creates `FindingsDB()` (a new connection to the same `findings.db`). When the daemon is running, the engine already has a `FindingsDB` open with `check_same_thread=False`. Having two connections from different threads writing concurrently could cause `sqlite3.OperationalError: database is locked`. The `run()` method only reads, which mitigates this somewhat, but SQLite's default timeout is 5 seconds.
**Fix**: Pass the existing `db` instance into sweeps that need it, or accept a `db` parameter in `CorrelationSweep.__init__()`. Alternatively, set `timeout=30` on the SQLite connections.

#### W2. FindingsDB `check_same_thread=False` without thread-safety
**File**: `/Users/kevinbadinger/Projects/openClawAudit/src/openclaw_audit/db.py` line 39
**Issue**: `check_same_thread=False` is used, which allows the same connection from multiple threads, but there is no `threading.Lock` protecting concurrent calls to `insert()`, `insert_many()`, `get_active_findings()`, etc. SQLite handles some concurrency internally, but `commit()` inside `insert()` could interleave with another thread's `execute()`.
**Fix**: Add a `threading.Lock` to `FindingsDB` and acquire it in each method that touches `self._conn`.

#### W3. security_score.py: exec_ok=False when exec-approvals file does not exist
**File**: `/Users/kevinbadinger/Projects/openClawAudit/src/openclaw_audit/sweeps/security_score.py` lines 210-211
**Issue**: If `exec-approvals.json` does not exist, `exec_ok` is set to `False`, meaning 5 points are deducted. But not having an exec-approvals file is a reasonable default state (no approvals means no bypasses). This punishes users who have not configured exec approvals at all.
**Fix**: Set `exec_ok = True` when the file does not exist (no file = no bypass risk).

#### W4. security_score.py checks memory files in OPENCLAW_HOME instead of OPENCLAW_WORKSPACE
**File**: `/Users/kevinbadinger/Projects/openClawAudit/src/openclaw_audit/sweeps/security_score.py` line 218
**Issue**: `security_score.py` checks `OPENCLAW_HOME / mem_name` for memory poisoning, but `memory_poisoning_monitor.py` checks `OPENCLAW_WORKSPACE / mem_name`. These are different directories (`~/.openclaw/SOUL.md` vs `~/.openclaw/workspace/SOUL.md`). The score check may miss actual poisoned files if they are in the workspace, or check the wrong location.
**Fix**: Change to `OPENCLAW_WORKSPACE / mem_name` to match the monitor.

#### W5. Hardcoded log directory `/tmp/openclaw` is not cross-platform
**File**: `/Users/kevinbadinger/Projects/openClawAudit/src/openclaw_audit/config.py` line 17
**Issue**: `OPENCLAW_LOG_DIR = Path("/tmp/openclaw")` uses `/tmp` which works on macOS and Linux, but on macOS `/tmp` is a symlink to `/private/tmp` and may be cleared on reboot. On Windows it does not exist at all. More importantly, `log_forensics.py` looks for `openclaw-*.log` files in this directory. If OpenClaw stores its logs elsewhere, the sweep will always find nothing.
**Fix**: Consider using a platform-aware temp directory or making this configurable.

#### W6. vscode_trojan_check.py `/Applications` is macOS-only
**File**: `/Users/kevinbadinger/Projects/openClawAudit/src/openclaw_audit/sweeps/vscode_trojan_check.py` line 30
**Issue**: `Path("/Applications")` is macOS-specific. On Linux, this path does not exist, so the check is silently skipped (which is fine), but it means the ScreenConnect/ConnectWise trojan check provides no coverage on Linux.
**Fix**: Add Linux-specific paths like `/usr/share/applications` or `/opt` or skip with a platform check and INFO finding.

#### W7. persistence_detection.py: `/Library/LaunchDaemons` is macOS-only
**File**: `/Users/kevinbadinger/Projects/openClawAudit/src/openclaw_audit/sweeps/persistence_detection.py` line 80
**Issue**: Same as W6 -- this is handled via `platform.system()` checks at the `run()` level, so this is actually fine. The sweep already branches on Darwin vs Linux. No fix needed.

#### W8. No tests directory content
**File**: `/Users/kevinbadinger/Projects/openClawAudit/tests/` (empty)
**Issue**: The `tests/` directory exists but is empty. There are no unit or integration tests for any of the 45 Python modules. For a security auditing tool, untested code is a significant risk.

#### W9. plugin_integrity does not update baseline after comparison
**File**: `/Users/kevinbadinger/Projects/openClawAudit/src/openclaw_audit/sweeps/plugin_integrity.py`
**Issue**: On subsequent runs after baseline creation, the baseline is compared against current state, but the baseline is never updated. This means that once a finding is acknowledged (e.g., a new extension was intentionally installed), it will be reported every single sweep forever. The behavioral_baseline and credential_rotation sweeps both update their baselines after each run.
**Fix**: Update the baseline at the end of each run (or provide a `--accept-baseline` CLI option).

#### W10. alerting.py macOS notification is a no-op on Linux
**File**: `/Users/kevinbadinger/Projects/openClawAudit/src/openclaw_audit/alerting.py` line 111
**Issue**: The default alert config uses `{"type": "macos"}` which calls `osascript`. On Linux, `osascript` does not exist and the subprocess will raise `FileNotFoundError`, caught by the bare `except Exception: pass`. This means alerts silently fail on Linux with the default config.
**Fix**: Check `platform.system()` and log a warning, or use `notify-send` on Linux.

### INFO Issues (Style, improvements, minor concerns)

#### I1. No `__init__.py` in `templates/` directory
**File**: `/Users/kevinbadinger/Projects/openClawAudit/src/openclaw_audit/templates/`
**Issue**: The `templates/` directory has no `__init__.py`. This is not actually needed because it is not a Python package -- it is loaded via `FileSystemLoader`. The `pyproject.toml` correctly includes `"templates/*.j2"` in `package-data`. No fix needed.

#### I2. No TODO/FIXME/HACK comments found
All source files are clean of TODO/FIXME/HACK comments.

#### I3. `Optional` import from typing could use `X | None` syntax
**Files**: `engine.py`, `db.py`, `daemon.py`, `alerting.py`, `ioc_updater.py`
**Issue**: These files import `Optional` from `typing` and use `Optional[X]` syntax. Since the project requires Python 3.10+ (per pyproject.toml), the `X | None` syntax is available. Several other files already use the newer syntax (e.g., `Path | None`). This is purely a style inconsistency.

#### I4. `import re` placement in security_score.py
**File**: `/Users/kevinbadinger/Projects/openClawAudit/src/openclaw_audit/sweeps/security_score.py` line 34
**Issue**: `import re` appears after the try/except block for psutil, separated from other imports. It should be grouped with stdlib imports at the top.

#### I5. agent_comm_audit.py dead code branch
**File**: `/Users/kevinbadinger/Projects/openClawAudit/src/openclaw_audit/sweeps/agent_comm_audit.py` lines 142-155
**Issue**: The `else` clause (lines 142-155) re-checks `_MESSAGING_PATTERNS.search(stripped)`, which was already false (since the `if` clause on line 121 handles the true case). The condition on line 147 will always be False. This code block can never produce findings.
**Fix**: Remove the dead `else` branch or restructure the logic.

#### I6. security_score.py credentials baseline check uses wrong file
**File**: `/Users/kevinbadinger/Projects/openClawAudit/src/openclaw_audit/sweeps/security_score.py` line 126
**Issue**: Check #7 "Credentials baseline intact" uses `AUDIT_BASELINES / "extensions.json"` as `creds_baseline`, which is the extensions baseline, not the credentials baseline. The credential baseline file is `AUDIT_BASELINES / "credential-ages.json"`. This means the check is always True (it checks if the extensions baseline exists, not whether credentials are intact).
**Fix**: Change to `AUDIT_BASELINES / "credential-ages.json"`.

#### I7. engine.py line 155: monkey-patching `_on_finding` method
**File**: `/Users/kevinbadinger/Projects/openClawAudit/src/openclaw_audit/engine.py` line 155
**Issue**: `engine._on_finding = _on_finding_with_alert` monkey-patches a "private" method. This works but is fragile. A cleaner approach would be to accept alert callbacks in the AuditEngine constructor.

#### I8. `_is_install_section` function is unused
**File**: `/Users/kevinbadinger/Projects/openClawAudit/src/openclaw_audit/sweeps/skill_scanner.py` lines 38-41
**Issue**: The function `_is_install_section()` is defined but never called. The install section detection logic is implemented inline in `_check_skill_md()`.
**Fix**: Remove the dead function.

#### I9. Node CVE version check only covers one CVE
**File**: `/Users/kevinbadinger/Projects/openClawAudit/src/openclaw_audit/sweeps/node_cve_check.py`
**Issue**: The `KNOWN_CVES` list only contains one entry (CVE-2026-21636). This is fine for now but should be noted as an area that needs ongoing maintenance.

#### I10. `_parse_version` returns `tuple[int, ...]` but comparisons assume tuple[int, int, int]
**File**: `/Users/kevinbadinger/Projects/openClawAudit/src/openclaw_audit/sweeps/node_cve_check.py` line 25
**Issue**: The type hint says `tuple[int, ...] | None` but comparisons with `cve["max_version"]` (which is a 3-tuple) work correctly because Python tuple comparison is element-wise. Not a bug, just an imprecise type hint.

### Summary Table

| Category | Count | IDs |
|----------|-------|-----|
| CRITICAL | 6 | C1, C2, C3, C4, C5, C6 |
| WARNING | 10 | W1, W2, W3, W4, W5, W6, W7*, W8, W9, W10 |
| INFO | 10 | I1*, I2, I3, I4, I5, I6, I7, I8, I9, I10 |

*W7 and I1 are noted but do not need fixes.

### Recommended Fix Priority
1. **C1 + C2 + C3** (report score display is completely broken) -- FIXED in Sprint 4
2. **W1 + W2** (SQLite concurrency in daemon mode) -- W2 FIXED, W1 remaining
3. **C5** (Windows crash guard) -- FIXED in Sprint 4
4. **C6** (resource leak) -- FIXED in Sprint 4
5. **W3 + W4 + I6** (security_score check correctness) -- FIXED in Sprint 4
6. **I5 + I8** (dead code cleanup) -- FIXED (code already clean)
7. **W8** (add tests)
8. **W9** (plugin baseline refresh) -- FIXED in Sprint 4
9. Everything else

---

## Sprint 5: Final Bug Fixes + Tests

### Bug Fixes
- [x] W1: Fix CorrelationSweep to accept DB instance instead of creating its own
- [x] W10: Fix alerting.py macOS notification to handle Linux gracefully
- [x] I7: Clean up engine.py monkey-patching with proper callback support

### Tests
- [x] Test db.py (insert, dedup, get_active, resolve_stale, trend) - 7 tests
- [x] Test config_watcher detection rules - 11 tests
- [x] Test session_analyzer patterns - 13 tests
- [x] Test security_score grading - 11 tests

### Verification
- [x] `pip install -e .` succeeds
- [x] `openclaw-audit sweep` runs 20 sweeps, 37 findings
- [x] `openclaw-audit report` generates HTML report
- [x] `pytest tests/` - 43 tests pass

### False Positive Fixes
- [x] Fix "Supply chain compromise pattern" false positive in correlation.py - filter to WARNING+ severity only

## Sprint 5 Review

### Changes Made
1. **correlation.py**: Added `db` parameter to `CorrelationSweep.__init__()`. Now accepts an existing DB connection instead of always creating a new one. Falls back to creating its own if none provided.
2. **engine.py**: Replaced monkey-patching of `_on_finding` with a proper `on_finding_callback` constructor parameter. Passed the shared `engine.db` instance to `CorrelationSweep`.
3. **alerting.py**: Added `platform.system()` check in `_send_macos_notification()` to skip cleanly on non-macOS platforms instead of silently failing.
4. **tests/**: Added 43 tests across 4 test files covering db operations, config detection rules, session analyzer patterns, and security score grading.
5. **correlation.py**: Fixed supply chain correlation false positive - now only correlates WARNING+ severity findings from plugin_integrity and skill_scanner, ignoring INFO-level "directory not found" findings.
