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

---

## Sprint 6: Source-Informed Security Checks

### Tasks
- [x] 1. **config.py** — Add `OPENCLAW_IDENTITY` path and `identity/device-auth.json` to `SENSITIVE_FILE_PATTERNS`
- [x] 2. **memory_poisoning_monitor.py** — Add `memory.extraPaths` traversal check (flag paths containing `..` that escape workspace)
- [x] 3. **reverse_proxy_audit.py** — Add Tailscale auth mode + empty trustedProxies header spoofing warning
- [x] 4. **permission_audit.py** — Detect orphaned `.tmp` files older than 1 hour during existing walk
- [x] 5. **security_score.py** — Add check #18: memory.extraPaths has no path traversal (weight: 5), update max to 140
- [x] 6. Run tests (`python3 -m pytest tests/ -q`) — 43 passed

### Review

**Files modified (7):**
1. `config.py` — Added `OPENCLAW_IDENTITY` path, added `identity/device-auth.json` to sensitive file patterns
2. `memory_poisoning_monitor.py` — Added `_check_extra_paths()` method that reads `memory.extraPaths` from config and flags any path resolving outside workspace (CRITICAL)
3. `reverse_proxy_audit.py` — Added check: if `gateway.auth.mode == "tailscale"` and `trustedProxies` is empty, emit WARNING about header spoofing
4. `permission_audit.py` — During existing `os.walk`, collects `.tmp` files older than 1 hour and emits aggregated WARNING
5. `security_score.py` — Added check #17 "Memory extraPaths safe" (weight: 5), bumped max to 140, adjusted grade thresholds proportionally
6. `report.py` + `report.html.j2` — Updated score display from /135 to /140
7. `tests/test_security_score.py` — Updated grade thresholds and check count (17→18) to match

**All changes are minimal additions to existing modules — no new files created.**

---

## Research: Best-in-Class Security Audit Tool Patterns (2025-2026)

### Status: Complete

---

### R1. What Makes Semgrep, Trivy, Falco, OSSEC/Wazuh, and Snyk Industry-Standard

**Semgrep -- The Programmable SAST Engine**
- Core differentiator: YAML-based rule authoring that mirrors target language syntax. Security engineers can write a useful rule in minutes.
- Architecture: Parses code via tree-sitter into a language-agnostic AST. Rules use metavariables (`$X`) and ellipsis operators (`...`) for pattern matching. Pro Engine adds cross-file/cross-function taint tracking.
- Speed: Scans complete in 10-30 seconds in CI. Single binary, zero external dependencies.
- Rule ecosystem: 3,000+ community rules + 20,000+ proprietary Pro rules.
- What makes it "industry standard": Open-source core (LGPL-2.1) + commercial platform. Free for 10 contributors. Custom rule authoring is best-in-class. Every finding is traceable to a readable YAML rule.

**Snyk -- The Developer Security Platform**
- Core differentiator: Breadth. SCA + SAST + Container + IaC + DAST in one platform. Gartner Magic Quadrant Leader 2024-2025.
- SCA flagship: Monitors 15M+ packages. Auto-generates fix PRs with dependency upgrades. Reachability analysis for Java/JS/TS.
- SAST: DeepCode AI semantic analysis. Real-time IDE scanning (VS Code, JetBrains, Eclipse, Cursor).
- What makes it "industry standard": Automated remediation (fix PRs), unified dashboard, Forrester Wave Leader for SCA (Q4 2024).

**Trivy -- The Zero-Config Open-Source Scanner**
- Core differentiator: Single CLI binary, zero-config, completely free with no feature gates.
- Coverage: SCA, container images, IaC (Terraform/K8s/Dockerfiles), Kubernetes security, SBOM generation, secrets detection.
- K8s native: Operator-based deployment with CRD reports.
- What makes it "industry standard": Zero cost, zero friction. Pair with Semgrep for SAST = fully free security stack.

**Falco -- Runtime Syscall-Level Security**
- Core differentiator: eBPF-based kernel-level visibility into every system call. Detects runtime compromise, not just static vulnerabilities.
- Architecture: Hooks into Linux kernel via eBPF probe. Rules evaluate against syscall events in real time. DaemonSet pattern for K8s.
- Detection: Unexpected process execution, container privilege escalation, sensitive file access, shell spawns, crypto mining, unexpected outbound connections.
- Output routing: Falcosidekick forwards alerts to Elasticsearch, S3, Kafka, Slack, PagerDuty.
- What makes it "industry standard": CNCF graduated project. Fills the "runtime" gap. Rule-based YAML syntax.

**Wazuh (successor to OSSEC) -- Open-Source SIEM/XDR**
- Core differentiator: Unified HIDS + SIEM + XDR in one open-source platform. Forked from OSSEC in 2015.
- Architecture (v5.0): New engine replacing Analysisd bottleneck. eBPF-based FIM. OpenSearch indexer with clustering. Agent-server model scales to thousands of endpoints.
- Capabilities: File integrity monitoring, vulnerability detection, log analysis, intrusion detection, active response (10-15 auto-response scripts), configuration assessment, container/K8s/cloud security.
- Compliance: Built-in dashboards for PCI DSS, GDPR, HIPAA, NIST 800-53. Pre-built rules and reports.
- What makes it "industry standard": Enterprise-grade at zero cost. Integrates with Falco. API-first (RESTful). MITRE ATT&CK mapping built in.

---

### R2. Output Formats Best Security Tools Support

**SARIF (Static Analysis Results Interchange Format)**
- Standard: OASIS SARIF v2.1.0 (errata 01, Aug 2023). v2.2 in development.
- Purpose: Universal interchange format for static analysis results. Required by GitHub Code Scanning. Supported by SonarQube, CodeQL, Semgrep, and most major tools.
- Key fields: `runs[].tool.driver.name`, `runs[].results[]` with `message.text`, `locations[].physicalLocation` (file/line/column), `rules[]` with severity.
- Recommendation: **Must-have**. Emit SARIF v2.1.0 for every scan.

**STIX 2.1 (Structured Threat Information eXpression)**
- Purpose: Machine-readable threat intelligence sharing. Used by MITRE ATT&CK and ATLAS for their data.
- Key objects: Indicators, Observed Data, Attack Patterns, Malware, Threat Actors, Relationships.
- Tooling: MITRE ATT&CK Data Model (TypeScript/Zod), TAXII 2.1 API, MISP-STIX library.
- Recommendation: **Important for IOC sharing**. IOC database should be exportable as STIX 2.1 bundles.

**MITRE ATT&CK Mapping**
- Every finding should include `technique_id` (e.g., T1558.003), `tactic` (e.g., Credential Access).
- YAML mapping separating technique IDs from query language. IDs are stable; queries change.
- Navigator layers: Export coverage maps as ATT&CK Navigator JSON.
- Recommendation: **Must-have**. Every finding should carry ATT&CK technique IDs.

**MITRE ATLAS Mapping (for AI-specific threats)**
- 15 tactics, 66 techniques, 46 sub-techniques as of October 2025.
- Data available in STIX 2.1 format.
- Recommendation: **Must-have**. AI/agent-specific findings should map to ATLAS technique IDs (AML.Txxxx).

**Additional Formats**
- CycloneDX / SPDX: SBOM generation.
- JSON/JSONL: Streaming to SIEM (Wazuh, Splunk, Elastic).
- CSV: Non-technical stakeholders.
- HTML: Standalone reports (already implemented).

---

### R3. openclaw-security-monitor (by adibirzu)

**What it does**: Host-level security scanner that runs OUTSIDE the OpenClaw agent as independent monitoring. 59-point security scan covering C2 infrastructure, credential theft, memory poisoning, WebSocket hijacking, and 50+ additional attack vectors.

**Detection capabilities**:
- ClawHavoc campaign (824+ malicious skills across ClawHub)
- AMOS/Atomic Stealer, Vidar infostealer
- CVE-2026-25253 (WebSocket), CVE-2026-28363 (safeBins bypass, CVSS 9.9)
- 35+ CVEs and 40+ GHSAs
- Memory poisoning via SOUL.md/MEMORY.md injection
- MCP tool poisoning, SANDWORM worm propagation
- Hidden Unicode injection in rules files

**Architecture**: Shell-script based (scan.sh, remediate.sh). IOC files (C2 IPs, domains, hashes, publisher blacklists). Node.js dashboard (zero npm deps). Daily scans with Telegram alerting.

**Key differences from openClawAudit**:
- adibirzu: Shell-script scanner, IOC-focused, no daemon, no structured output formats, installs as OpenClaw skill
- openClawAudit: Python daemon, continuous monitoring, structured Finding model, SQLite persistence, sweep+monitor architecture, behavioral baselines, security scoring, remediation engine

---

### R4. OWASP Agentic AI Top 10 (2026)

Released December 2025. Peer-reviewed by 100+ researchers. Endorsed by Microsoft, NVIDIA, AWS, GoDaddy.

| ID | Risk | Description |
|---|---|---|
| ASI01 | Agent Goal Hijack | Attackers redirect agent's entire planning via malicious text |
| ASI02 | Tool Misuse & Exploitation | Agent uses authorized tools destructively |
| ASI03 | Identity & Privilege Abuse | Agents inherit/escalate/share credentials without scoping |
| ASI04 | Supply Chain Vulnerabilities | Malicious tools, MCP servers, agent cards, registries |
| ASI05 | Unexpected Code Execution | Agent-generated code bypasses traditional controls |
| ASI06 | Memory & Context Poisoning | Persistent corruption of agent memory/embeddings |
| ASI07 | Insecure Inter-Agent Communication | Weaknesses in agent-to-agent protocols |
| ASI08 | Cascading Failures | Single fault propagates across agents into system-wide harm |
| ASI09 | Human-Agent Trust Exploitation | Anthropomorphism/authority bias weaponized |
| ASI10 | Rogue Agents | Behavioral drift, collusion, self-replication |

**Three Core Principles**:
1. Least Agency: Don't deploy agentic behavior where not needed.
2. Human-in-the-Loop: Require human approval for high-impact/irreversible actions.
3. Comprehensive Observability: Immutable, signed audit logs of ALL agent actions.

**Defense-in-Depth Architecture**:
- Layer 1: Input Validation (prompt firewalls, sanitization, rate limiting)
- Layer 2: Agent Sandbox (isolated execution, resource limits, no direct prod access)
- Layer 3: Tool Security (parameterized calls, tool-level auth, I/O validation)
- Layer 4: Monitoring & Audit (immutable logs, behavioral anomaly detection, alerting)

---

### R5. MITRE ATLAS (Adversarial Threat Landscape for AI Systems)

- Extension of MITRE ATT&CK for AI/ML systems.
- As of October 2025: **15 tactics, 66 techniques, 46 sub-techniques, 26 mitigations, 33 case studies**.
- Data in STIX 2.1 format for machine-readable integration.
- ~70% of ATLAS mitigations map to existing security controls.
- Complements OWASP LLM Top 10 and NIST AI RMF -- use all three.

**October 2025 update** (with Zenity Labs): Added 14 new agentic AI techniques covering AI Service API exploitation (AML.T0096), tool-use manipulation, prompt injection at orchestration layer, memory manipulation, delegated authority persistence.

**MITRE ATLAS OpenClaw Investigation (Feb 2026)**: MITRE conducted rapid investigation of OpenClaw specifically, mapping critical incidents to ATLAS TTPs, identifying high-risk attack chains. Published at mitre.org.

---

### R6. Security Tools Specifically for AI Agents / LLM Applications (2026)

**Red Teaming**: Giskard, PyRIT (Microsoft), Promptfoo, DeepTeam (MITRE ATLAS-mapped)
**Guardrails**: NVIDIA NeMo Guardrails, Guardrails AI, LLM Guard, AgentWard, Akto AgentGuard, Lakera Guard, Datadog AI Guard
**Identity/Access**: Keycloak, Open Policy Agent (OPA), Casbin
**Observability**: Langfuse, OpenTelemetry, Arize AI, WhyLabs, Datadog LLM Observability
**Supply Chain**: Sigstore, Trivy, Protect AI

**AgentWard** (Apache 2.0, Feb 2026) -- most relevant comparison:
- Permission control plane for AI agents, sits between agents and tools
- Enforces least-privilege in code, outside the LLM context window
- Already has OpenClaw gateway integration: `agentward inspect --gateway openclaw`
- Regulatory compliance: HIPAA, SOX, GDPR, PCI-DSS v4.0

**2026 consensus**: Guardrails + Runtime Monitoring > Everything else. Agentic systems are dynamic; security must be dynamic too.

---

### R7. What Separates "Good" from "Industry Standard" -- Actionable Patterns

**Architecture**: Rule-as-code (every detection is readable/versionable YAML), agent-server model, plugin/module architecture, API-first, event-driven pipeline.

**Output & Integration**: SARIF output, STIX 2.1 export, ATT&CK/ATLAS technique IDs, JSON streaming to SIEM, webhook alerting, Navigator layer export.

**Detection**: Static scanning + runtime monitoring (not either/or), behavioral baselines, IOC matching, taint tracking, reachability analysis.

**Compliance**: Built-in compliance dashboards (PCI DSS, GDPR, HIPAA, NIST 800-53, ISO 42001), OWASP Agentic Top 10 mapping, SBOM generation, immutable audit logs, security scoring, maturity model.

**Developer Experience**: Sub-30s scans, IDE integration, PR/MR comments, auto-fix PRs, free/open-source core, CLI-first with optional web dashboard.

**openClawAudit gaps to close for "industry standard"**:
- [ ] SARIF v2.1.0 output format
- [ ] MITRE ATT&CK technique IDs on every finding
- [ ] MITRE ATLAS technique IDs on AI-specific findings
- [ ] OWASP Agentic Top 10 (ASI01-ASI10) mapping on findings
- [ ] STIX 2.1 export for IOC sharing
- [ ] JSON/JSONL streaming output for SIEM integration
- [ ] YAML-based custom rule authoring (user-extensible rules)
- [ ] Webhook alerting expansion (already have Slack/Telegram -- need generic webhook)
- [ ] CycloneDX SBOM generation for agent dependencies
- [ ] Compliance framework mapping (EU AI Act, NIST AI RMF, ISO 42001)
- [ ] ATT&CK/ATLAS Navigator layer export
- [ ] API endpoint for programmatic access

---

## Sprint 7: Self-Learning Cycle

**Goal:** Make the tool get smarter over time. Every human triage action improves future detection quality. Findings carry confidence scores that calibrate automatically based on true/false positive rates.

### Tasks

- [x] 1. **models.py** — Enrich `Finding` with: `confidence` (float 0.0-1.0, default 0.5), `triage_status` (None/"confirmed"/"false_positive"/"dismissed"), `mitre_attack` (str, optional), `owasp_asi` (str, optional), `remediation` (str, optional)
- [x] 2. **db.py** — Add columns: `confidence REAL`, `triage_status TEXT`, `triage_timestamp REAL`, `mitre_attack TEXT`, `owasp_asi TEXT`, `remediation TEXT`. Auto-migrate existing DBs via `ALTER TABLE`.
- [x] 3. **db.py** — Add `triage()` method (sets status + timestamp), `get_precision_stats()` (returns confirmed/fp counts per module+title), `get_triageable()` (active findings for triage UI)
- [x] 4. **learner.py** (new) — `PrecisionTracker`: loads triage stats from DB, calculates precision per (module, title). Stores to `baselines/precision.json`. Method `calibrate(finding) -> float` returns adjusted confidence = base × precision_multiplier. Multiplier: 1.0 for no data, scales linearly with precision rate.
- [x] 5. **profile.py** (new) — `EnvironmentProfiler`: detects Docker installed, MCP config present, skill count, proxy config, OS. Stores to `baselines/environment.json`. Method `is_relevant(check_name) -> bool` so sweeps can skip irrelevant checks.
- [x] 6. **behavioral_baseline.py** — Rolling window: store last 7 snapshots instead of single snapshot. Anomaly thresholds = mean ± 2σ instead of hardcoded 3x/5x multipliers.
- [x] 7. **ioc.py** — Add `last_matched` timestamp tracking per IOC. After 90 days unmatched → lower confidence. After 180 days → mark stale.
- [x] 8. **engine.py** — Load `PrecisionTracker` on startup. Apply `calibrate()` to every finding before insert. Pass `EnvironmentProfiler` to sweeps. Skip alerts for findings with confidence < 0.2.
- [x] 9. **cli.py** — Add `triage` command: `openclaw-audit triage` (list findings), `openclaw-audit triage <id> --confirm|--fp|--dismiss`. After triage, re-run learner to update precision scores.
- [x] 10. **alerting.py** — Respect confidence: only alert findings with confidence ≥ 0.5 (configurable). Include confidence score and MITRE mapping in alert messages.
- [x] 11. **Tests** — 18 new tests in test_learning_cycle.py (models, DB triage, precision stats, calibration math)
- [x] 12. **Review** — see below

### Review

**Files modified (7):**
1. `models.py` — Added 5 fields: confidence, triage_status, mitre_attack, owasp_asi, remediation
2. `db.py` — Added 6 columns with auto-migration, insert writes new fields, added triage(), get_precision_stats(), get_triageable()
3. `engine.py` — Loads PrecisionTracker + EnvironmentProfiler, calibrates confidence on all findings, skips irrelevant sweeps, gates alerting at confidence < 0.2
4. `cli.py` — Added `triage` command with list/confirm/fp/dismiss modes
5. `alerting.py` — Confidence gate (min_alert_confidence config), enriched messages with MITRE/OWASP tags
6. `behavioral_baseline.py` — Rewritten: rolling window of 7 snapshots, mean ± 2σ anomaly detection, auto-migrates old format
7. `ioc.py` — Added IOC aging: record_ioc_match(), ioc_confidence(), stale at 90d (0.3), very stale at 180d (0.1)

**Files created (3):**
1. `learner.py` — PrecisionTracker: calibrates confidence from triage feedback, MIN_SAMPLES=3, multiplier floors at 0.2
2. `profile.py` — EnvironmentProfiler: detects Docker/MCP/skills/gateway/OS, is_relevant() for sweep gating
3. `tests/test_learning_cycle.py` — 18 tests covering models, DB, triage, precision, calibration

**Test results:** 61 passed (43 existing + 18 new), 0.17s
**CLI verified:** `openclaw-audit triage` lists findings, `openclaw-audit sweep` runs with learning cycle wired in

---

## Sprint 7b: Finding Enrichment, IOC Aging Wiring, Report Upgrade

### Tasks
- [x] 1. **mappings.py** (new) — 110-entry mapping table: (module, title_prefix) → {confidence, mitre_attack, owasp_asi, remediation}. `enrich()` function does prefix matching and fills fields centrally.
- [x] 2. **engine.py** — Call `enrich(finding)` before `calibrate(finding)` in both `_on_finding()` and `run_all_sweeps()`. Load IOC matches on init, save after sweep cycles.
- [x] 3. **skill_scanner.py, network_monitor.py, network_forensics.py** — Call `record_ioc_match()` when C2 IPs, C2 ports, or exfil domains match. IOC aging is now live.
- [x] 4. **report.html.j2** — Added confidence bars (green/yellow/red), MITRE ATT&CK tags (blue), OWASP ASI tags (purple), triage status badges, remediation blocks with green border.
- [x] 5. **db.py** — Dedup UPDATE now backfills mitre_attack, owasp_asi, remediation via COALESCE.
- [x] 6. **tests/test_mappings.py** — 16 new tests covering enrich() for all major finding types, IOC aging confidence, prefix matching edge cases.

### Review

**Files modified (6):**
1. `engine.py` — Added `enrich()` call + `load_ioc_matches()`/`save_ioc_matches()` lifecycle
2. `db.py` — Dedup UPDATE now backfills MITRE/OWASP/remediation fields
3. `network_monitor.py` — Added `record_ioc_match()` on C2 IP and C2 port matches
4. `network_forensics.py` — Added `record_ioc_match()` on C2 IP, C2 port, and exfil domain matches
5. `skill_scanner.py` — Added `record_ioc_match()` on C2 IP and exfil domain matches
6. `report.html.j2` — New CSS + rendering for confidence, MITRE tags, OWASP tags, triage badges, remediation blocks

**Files created (2):**
1. `mappings.py` — 110-entry centralized enrichment table with `enrich()` function
2. `tests/test_mappings.py` — 16 tests for enrichment and IOC aging

**Test results:** 77 passed (43 original + 18 learning cycle + 16 mappings), 0.17s
**Enrichment verified:** 6/15 latest sweep findings fully enriched (remaining 9 are INFO-level with no attack technique mapping, which is correct)
**Report verified:** HTML report renders 72 new UI elements (confidence bars, MITRE tags, OWASP tags, remediation blocks)

---

## Sprint 8: Output Formats, Missing CVEs & Detection Gaps

**Goal:** Close the biggest gaps blocking industry credibility: standard output formats (SARIF, JSONL), missing critical CVE coverage, generic webhook alerting, and MCP rug-pull detection (differentiator).

### Tasks

- [x] 1. **sarif.py** (new) — SARIF v2.1.0 output formatter
- [x] 2. **export.py** (new) — Unified export: SARIF, JSONL, CSV
- [x] 3. **cli.py** — Added `export` command with --format and --output flags
- [x] 4. **alerting.py** — Added `webhook` backend (POST JSON to any URL with custom headers)
- [x] 5. **sweeps/safebins_bypass.py** (new) — CVE-2026-28363 safeBins bypass detection (CVSS 9.9)
- [x] 6. **sweeps/mcp_rugpull.py** (new) — MCP tool definition mutation detection (rug-pull attacks)
- [x] 7. **mappings.py** — Added 10 enrichment entries for safebins_bypass and mcp_rugpull
- [x] 8. **engine.py** — Registered SafeBinsBypassSweep and MCPRugPullSweep
- [x] 9. **Tests** — 41 new tests: test_sarif.py (12), test_export.py (9), test_safebins.py (11), test_mcp_rugpull.py (9)
- [x] 10. **Verification** — pip install ✓, 22 sweeps ✓, export works ✓, 118 tests pass ✓

### Review

**Files created (8):**
1. `sarif.py` — SARIF v2.1.0 formatter with severity mapping, rule dedup, location/tags/help
2. `export.py` — Unified export: SARIF, JSONL, CSV with file/stdout output
3. `sweeps/safebins_bypass.py` — CVE-2026-28363: dangerous bins, bypass patterns, symlinks, relative paths
4. `sweeps/mcp_rugpull.py` — Tool description hash baseline + mutation detection
5. `tests/test_sarif.py` — 12 tests
6. `tests/test_export.py` — 9 tests
7. `tests/test_safebins.py` — 11 tests
8. `tests/test_mcp_rugpull.py` — 9 tests

**Files modified (4):**
1. `cli.py` — Added `export` command with --format and --output flags
2. `alerting.py` — Added `webhook` backend (POST JSON to any URL with custom headers)
3. `mappings.py` — Added 10 enrichment entries for safebins_bypass and mcp_rugpull
4. `engine.py` — Registered SafeBinsBypassSweep and MCPRugPullSweep

**Test results:** 118 passed (77 existing + 41 new), 0.27s
**Sweep results:** 22 sweeps, 17 findings (both new sweeps producing findings)
**Export verified:** SARIF (58 results), JSONL (58 lines), CSV (58 rows)

### Updated Project Stats
- **51 source files** (50 .py + 1 .j2)
- **7 always-on monitors**
- **22 periodic sweeps** (+2: safebins_bypass, mcp_rugpull)
- **9 CLI commands** (+1: export)
- **5 alert backends** (+1: webhook)
- **3 export formats** (new: SARIF v2.1.0, JSONL, CSV)
- **118 tests** (+41 new)

---

## Sprint 9: Detection Hardening

**Goal:** Close detection gaps — hidden Unicode injection, SANDWORM worm propagation, cascading failure detection (ASI08), social engineering patterns (ASI09), and MCP IOC cross-referencing.

### Tasks
- [x] 1. **sweeps/unicode_injection.py** (new) — Scan config/memory/skill files for invisible Unicode (zero-width, bidi overrides, tag chars, homoglyphs)
- [x] 2. **sweeps/worm_propagation.py** (new) — Detect self-replicating agent patterns (skill-to-skill writes, pipe-to-shell, auto-install config, cross-skill references)
- [x] 3. **correlation.py** — Added 2 new cascade patterns: cascading_failure (4+ modules failing + crashes), resource_exhaustion_chain (spikes + crashes)
- [x] 4. **session_analyzer.py** — Added 6 social engineering patterns: urgency manipulation, false authority, secrecy pressure, security disabling, dangerous command coaching, anthropomorphic trust exploitation
- [x] 5. **mcp_security.py** — Added IOC cross-reference: check tool descriptions + server args against C2 IPs, malicious domains, abused services from IOC database
- [x] 6. **mappings.py** — Added 15 enrichment entries for new sweeps and enhanced detections
- [x] 7. **engine.py** — Registered UnicodeInjectionSweep and WormPropagationSweep
- [x] 8. **Tests** — 32 new tests: test_unicode_injection.py (10), test_worm_propagation.py (9), test_social_engineering.py (13)
- [x] 9. **Verification** — pip install ✓, 24 sweeps ✓, 150 tests pass ✓

### Review

**Files created (5):**
1. `sweeps/unicode_injection.py` — 9 invisible char types, 11 bidi chars, tag range, 12 homoglyph pairs
2. `sweeps/worm_propagation.py` — 7 code patterns, 3 metadata patterns, 3 config indicators, cross-skill detection
3. `tests/test_unicode_injection.py` — 10 tests
4. `tests/test_worm_propagation.py` — 9 tests
5. `tests/test_social_engineering.py` — 13 tests

**Files modified (4):**
1. `correlation.py` — Added cascading_failure + resource_exhaustion_chain patterns
2. `session_analyzer.py` — Added 6 social engineering detection patterns
3. `mcp_security.py` — Added IOC cross-reference for C2 IPs + malicious domains in tool descriptions + server args
4. `mappings.py` — Added 15 enrichment entries
5. `engine.py` — Registered 2 new sweeps

**Test results:** 150 passed (118 existing + 32 new), 0.29s
**Sweep results:** 24 sweeps registered, 7 monitors

### Updated OWASP Coverage
| Risk | Before | After | Change |
|------|--------|-------|--------|
| ASI01 Agent Goal Hijack | ~70% | ~80% | +unicode injection detection |
| ASI04 Supply Chain | ~70% | ~80% | +MCP IOC cross-ref, rug-pull |
| ASI05 Code Execution | ~50% | ~65% | +safeBins bypass (CVE-2026-28363) |
| ASI08 Cascading Failures | ~30% | ~55% | +cascade + resource exhaustion correlation |
| ASI09 Human-Agent Trust | ~50% | ~65% | +social engineering patterns |
| ASI10 Rogue Agents | ~60% | ~75% | +worm propagation detection |

### Updated Project Stats
- **56 source files** (55 .py + 1 .j2)
- **7 always-on monitors**
- **24 periodic sweeps** (+4: safebins_bypass, mcp_rugpull, unicode_injection, worm_propagation)
- **9 CLI commands**
- **5 alert backends**
- **3 export formats** (SARIF v2.1.0, JSONL, CSV)
- **150 tests**

---

## Sprint 10: Ecosystem Integration

**Goal:** Make the tool extensible and interoperable — YAML custom rules, ATT&CK Navigator layer export, STIX 2.1 threat intel sharing, CycloneDX SBOM generation.

### Tasks
- [x] 1. **rules.py** (new) — YAML custom rule engine with minimal YAML parser (no PyYAML dependency). Three targets: file_content, config_value, file_exists. Loaded from ~/.openclaw/.audit/rules/*.yaml.
- [x] 2. **navigator.py** (new) — ATT&CK Navigator layer export. Maps technique IDs to severity colors (red/yellow/blue), generates importable JSON for Navigator v5.1.
- [x] 3. **stix.py** (new) — STIX 2.1 export. Findings as Indicator objects, IOC database as separate bundle with C2 IPs, domains, hashes, threat actors.
- [x] 4. **sbom.py** (new) — CycloneDX 1.5 SBOM. Scans skills, MCP servers, extensions with version/author/license metadata.
- [x] 5. **export.py + cli.py** — Added 4 new export formats: navigator, stix, stix-ioc, sbom. Total: 7 formats.
- [x] 6. **engine.py** — Registered CustomRulesSweep (25 sweeps total).
- [x] 7. **Tests** — 38 new tests: test_rules.py (7), test_navigator.py (9), test_stix.py (11), test_sbom.py (7), plus 4 more in test_export.py updates.
- [x] 8. **Verification** — pip install ✓, 25 sweeps ✓, 7 export formats ✓, 188 tests pass ✓

### Review

**Files created (8):**
1. `rules.py` — YAML rule engine with built-in parser, 3 rule targets, auto-load from rules dir
2. `navigator.py` — ATT&CK Navigator layer with severity colors, scores, legends, gradient
3. `stix.py` — STIX 2.1 bundles for findings + IOCs (C2 IPs, domains, hashes, threat actors)
4. `sbom.py` — CycloneDX 1.5 SBOM for skills, MCP servers, extensions
5. `tests/test_rules.py` — 7 tests
6. `tests/test_navigator.py` — 9 tests
7. `tests/test_stix.py` — 11 tests
8. `tests/test_sbom.py` — 7 tests

**Files modified (4):**
1. `export.py` — Added export_navigator, export_stix, export_stix_ioc, export_sbom
2. `cli.py` — Extended --format choices to 7 formats
3. `engine.py` — Registered CustomRulesSweep
4. `mappings.py` — Added custom_rules mapping entry

**Test results:** 188 passed (150 existing + 38 new), 0.31s
**Export verified:** SARIF, JSONL, CSV, Navigator (4 techniques), STIX (60 objects), STIX-IOC (26 objects), SBOM

### Final Project Stats (Sprints 8+9+10)
- **60 source files** (59 .py + 1 .j2)
- **7 always-on monitors**
- **25 periodic sweeps** (+5 since Sprint 7b)
- **9 CLI commands**
- **5 alert backends** (+1: webhook)
- **7 export formats** (+7 new: SARIF, JSONL, CSV, Navigator, STIX, STIX-IOC, SBOM)
- **1 custom rule engine** (YAML-based, no dependencies)
- **188 tests** (+111 new across 3 sprints)
