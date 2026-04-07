"""Centralized MITRE ATT&CK, OWASP ASI, confidence, and remediation mappings.

Maps (module, title_prefix) -> enrichment metadata for all findings.
Called by the engine to enrich every Finding before storage/alerting.
"""

from __future__ import annotations

from .models import Finding

# Each entry: (module, title_prefix, confidence, mitre_attack, owasp_asi, remediation)
# title_prefix is matched with str.startswith(). "*" matches all titles for that module.
# More specific prefixes should come before broader ones per module.

_MAPPING_TABLE: list[tuple[str, str, float, str | None, str | None, str | None]] = [

    # =========================================================================
    # MONITORS
    # =========================================================================

    # --- config_watcher ---
    ("config_watcher", "Gateway bound to non-loopback", 0.95, "T1190", "ASI03",
     "Set gateway.bind to 127.0.0.1 in openclaw.json."),
    ("config_watcher", "Authentication disabled", 0.95, "T1556", "ASI03",
     "Set gateway.auth.enabled to true in openclaw.json."),
    ("config_watcher", "Open DM policy enabled", 0.85, "T1071.001", "ASI09",
     "Set gateway.auth.allowOpenDM to false in openclaw.json."),
    ("config_watcher", "Device authentication disabled", 0.90, "T1556", "ASI03",
     "Set gateway.auth.deviceAuth to true in openclaw.json."),
    ("config_watcher", "Insecure Control UI auth", 0.90, "T1556", "ASI03",
     "Set gateway.controlUi.allowInsecureAuth to false."),
    ("config_watcher", "Device authentication completely disabled", 0.95, "T1556", "ASI03",
     "Set gateway.controlUi.dangerouslyDisableDeviceAuth to false."),
    ("config_watcher", "Sandbox disabled", 0.70, "T1562.001", "ASI05",
     "Enable sandbox in openclaw.json for restricted execution."),
    ("config_watcher", "Log secret redaction disabled", 0.65, "T1552.001", "ASI03",
     "Set logging.redactSecrets to true in openclaw.json."),
    ("config_watcher", "Full mDNS broadcast", 0.50, "T1018", "ASI03",
     "Set network.mdns.broadcast to false to prevent network discovery."),
    ("config_watcher", "Hardcoded secret in config", 0.90, "T1552.001", "ASI03",
     "Move secrets to environment variables or a credential manager."),

    # --- permission_monitor ---
    ("permission_monitor", "Overly permissive", 0.70, "T1222.002", "ASI03",
     "Tighten file permissions: chmod 600 for files, 700 for directories."),
    ("permission_monitor", "Sensitive file too open", 0.80, "T1222.002", "ASI03",
     "Set sensitive file permissions to 600: chmod 600 <file>."),

    # --- credential_guard ---
    ("credential_guard", "Credential file deleted", 0.85, "T1070.004", "ASI03",
     "Investigate who deleted the credential file. Check audit logs."),
    ("credential_guard", "Credential file modified", 0.80, "T1098", "ASI03",
     "Verify credential file change was authorized. Rotate if compromised."),
    ("credential_guard", "New credential file", 0.55, "T1552.001", "ASI03",
     "Review new credential file origin and permissions."),
    ("credential_guard", "Hardcoded secret", 0.90, "T1552.001", "ASI03",
     "Move secrets to environment variables or a credential manager."),

    # --- process_monitor ---
    ("process_monitor", "Suspicious process", 0.85, "T1059.004", "ASI05",
     "Kill the suspicious process and investigate its origin."),
    ("process_monitor", "Deep process tree", 0.50, "T1059", "ASI05",
     "Review process tree for unexpected child processes."),
    ("process_monitor", "Excessive child processes", 0.55, "T1059", "ASI10",
     "Investigate why OpenClaw is spawning many child processes."),
    ("process_monitor", "Non-node child process", 0.35, "T1059", "ASI05",
     "Review non-Node.js child process for legitimacy."),

    # --- network_monitor ---
    ("network_monitor", "Known C2 IP", 0.95, "T1071.001", "ASI10",
     "Block the C2 IP immediately. Investigate compromised skill/extension."),
    ("network_monitor", "Known C2 port", 0.70, "T1571", "ASI10",
     "Investigate connection on known C2 port. May be legitimate."),
    ("network_monitor", "Listening on all interfaces", 0.75, "T1190", "ASI03",
     "Bind to 127.0.0.1 instead of 0.0.0.0."),
    ("network_monitor", "Excessive network connections", 0.55, "T1071", "ASI10",
     "Review active connections for data exfiltration or C2 beaconing."),
    ("network_monitor", "LAN connection", 0.45, "T1021", "ASI07",
     "Verify LAN connection is expected. May indicate lateral movement."),
    ("network_monitor", "Non-standard port", 0.35, "T1571", "ASI10",
     "Review connection purpose. Non-standard ports may indicate C2."),

    # --- session_analyzer ---
    ("session_analyzer", "Prompt injection", 0.80, "T1059", "ASI01",
     "Review session for malicious input. Consider blocking the source."),
    ("session_analyzer", "Exfiltration attempt", 0.85, "T1567", "ASI02",
     "Block exfiltration target. Review what data was accessed."),
    ("session_analyzer", "Multi-turn injection chain", 0.90, "T1059", "ASI01",
     "Active multi-turn attack. Terminate session and review transcript."),
    ("session_analyzer", "Premise shifting", 0.75, "T1059", "ASI01",
     "Context manipulation detected. Review session for goal hijacking."),
    ("session_analyzer", "Sustained injection attack", 0.90, "T1059", "ASI01",
     "Persistent attack. Block the source and review all affected sessions."),
    ("session_analyzer", "Encoded content in session", 0.55, "T1027", "ASI01",
     "Review encoded content for hidden commands or data exfiltration."),
    ("session_analyzer", "Dangerous tool call", 0.75, "T1059.004", "ASI02",
     "Review tool call context. Restrict dangerous tool access."),
    ("session_analyzer", "Rapid tool execution", 0.55, "T1059", "ASI02",
     "Unusual tool call rate. Review for automated abuse."),
    ("session_analyzer", "Message flood", 0.50, "T1498", "ASI10",
     "Rate limit the session source. May indicate automated probing."),

    # --- memory_poisoning_monitor ---
    ("memory_poisoning_monitor", "Memory extraPaths escapes workspace", 0.95, "T1565.001", "ASI06",
     "Remove path traversal from memory.extraPaths in config immediately."),
    ("memory_poisoning_monitor", "Injection pattern in", 0.85, "T1565.001", "ASI06",
     "Remove injected content from memory file. Audit who modified it."),
    ("memory_poisoning_monitor", "Injection marker in", 0.80, "T1565.001", "ASI06",
     "Remove injection markers from memory file. Review file history."),

    # =========================================================================
    # SWEEPS
    # =========================================================================

    # --- skill_scanner ---
    ("skill_scanner", "Malicious skill name pattern", 0.85, "T1195.002", "ASI04",
     "Quarantine the skill immediately: openclaw-audit fix."),
    ("skill_scanner", "Malicious publisher", 0.90, "T1195.002", "ASI04",
     "Uninstall all skills from this publisher. They are known-malicious."),
    ("skill_scanner", "C2 IP address found", 0.95, "T1071.001", "ASI04",
     "Quarantine skill immediately. Block the C2 IP at firewall level."),
    ("skill_scanner", "AMOS stealer indicator", 0.95, "T1555", "ASI04",
     "Quarantine skill. Scan system for AMOS stealer artifacts."),
    ("skill_scanner", "Reverse shell pattern", 0.90, "T1059.004", "ASI04",
     "Quarantine skill. Check for active reverse shell connections."),
    ("skill_scanner", "Exfiltration domain found", 0.90, "T1567", "ASI04",
     "Quarantine skill. Block the exfiltration domain."),
    ("skill_scanner", "Suspicious skill name", 0.55, "T1195.002", "ASI04",
     "Review skill source and publisher. May be a typosquat."),
    ("skill_scanner", "Base64-encoded string", 0.50, "T1027", "ASI04",
     "Decode and review base64 content for hidden payloads."),
    ("skill_scanner", "Binary download with password", 0.70, "T1204.002", "ASI04",
     "Review skill for malware distribution. Password-protected binaries are suspicious."),
    ("skill_scanner", "Shell command in SKILL.md", 0.60, "T1059.004", "ASI04",
     "Review install commands for malicious payloads."),

    # --- websocket_security ---
    ("websocket_security", "Insecure auth allows WebSocket", 0.95, "T1190", "ASI03",
     "Disable allowInsecureAuth. This enables CVE-2026-25253 exploitation."),
    ("websocket_security", "Device auth disabled", 0.95, "T1556", "ASI03",
     "Re-enable device auth. This allows full unauthenticated WebSocket control."),
    ("websocket_security", "WebSocket origin not validated", 0.70, "T1190", "ASI03",
     "Update OpenClaw to a version with origin validation (CVE-2026-25253 fix)."),

    # --- exec_approvals_audit ---
    ("exec_approvals_audit", "Unrestricted exec approval", 0.85, "T1059", "ASI02",
     "Restrict exec approval scope to specific owners/commands."),
    ("exec_approvals_audit", "Approval bypass", 0.85, "T1548", "ASI02",
     "Set ask to 'always' for sensitive exec approvals."),
    ("exec_approvals_audit", "Exec approvals file permissions too loose", 0.65, "T1222.002", "ASI03",
     "chmod 600 exec-approvals.json."),

    # --- persistence_detection ---
    ("persistence_detection", "OpenClaw LaunchAgent", 0.65, "T1547.011", "ASI10",
     "Review LaunchAgent. Remove if not intentionally installed."),
    ("persistence_detection", "OpenClaw LaunchDaemon", 0.70, "T1543.004", "ASI10",
     "Review LaunchDaemon. Root-level persistence is high risk."),
    ("persistence_detection", "OpenClaw systemd unit", 0.65, "T1543.002", "ASI10",
     "Review systemd unit. Remove if not intentionally installed."),
    ("persistence_detection", "OpenClaw crontab entry", 0.65, "T1053.003", "ASI10",
     "Review crontab entry. Remove if not intentionally scheduled."),

    # --- dm_policy_audit ---
    ("dm_policy_audit", "Global DM policy is open", 0.85, "T1071.001", "ASI09",
     "Set dmPolicy to 'restricted' in openclaw.json."),
    ("dm_policy_audit", "Channel", 0.65, "T1071.001", "ASI09",
     "Restrict channel DM policy and allowFrom list."),

    # --- tool_policy_audit ---
    ("tool_policy_audit", "Elevated tools allow all callers", 0.85, "T1548", "ASI02",
     "Restrict elevated tools to specific callers via allowFrom."),
    ("tool_policy_audit", "Elevated tools do not require approval", 0.80, "T1548", "ASI02",
     "Set requireApproval to true for elevated tools."),
    ("tool_policy_audit", "Elevated mode with no restrictions", 0.90, "T1548", "ASI02",
     "Add allowFrom, requireApproval, or deny list to elevated tool config."),
    ("tool_policy_audit", "No tool deny list", 0.55, "T1059", "ASI02",
     "Add a tools.deny list to block dangerous tools."),

    # --- mcp_security ---
    ("mcp_security", "All project MCP servers enabled", 0.85, "T1195.002", "ASI04",
     "Disable enableAllProjectMcpServers. Whitelist MCP servers explicitly."),
    ("mcp_security", "Injection pattern in MCP tool", 0.85, "T1565.001", "ASI04",
     "Review MCP tool description for prompt injection. Report to provider."),
    ("mcp_security", "MCP server", 0.50, "T1195.002", "ASI04",
     "Pin MCP server versions and restrict network access."),

    # --- docker_security ---
    ("docker_security", "Container", 0.75, "T1610", "ASI05",
     "Harden container: non-root user, read-only rootfs, drop capabilities."),
    ("docker_security", "Docker socket mounted", 0.90, "T1611", "ASI05",
     "Remove Docker socket mount. This allows container escape."),

    # --- reverse_proxy_audit ---
    ("reverse_proxy_audit", "Reverse proxy bypass risk", 0.85, "T1557", "ASI03",
     "Configure trustedProxies or bind gateway to 127.0.0.1."),
    ("reverse_proxy_audit", "Device authentication disabled (dangerous", 0.95, "T1556", "ASI03",
     "Re-enable device authentication immediately."),
    ("reverse_proxy_audit", "Gateway bound to LAN without proxy", 0.80, "T1190", "ASI03",
     "Add trustedProxies config or bind to 127.0.0.1."),
    ("reverse_proxy_audit", "Tailscale auth without", 0.60, "T1557", "ASI03",
     "Configure trustedProxies to prevent header spoofing."),
    ("reverse_proxy_audit", "Tailscale funnel reference", 0.55, "T1190", "ASI03",
     "Verify Tailscale Funnel is intentional. It exposes the gateway to the internet."),

    # --- node_cve_check ---
    ("node_cve_check", "CVE-", 0.95, "T1203", "ASI05",
     "Update Node.js to a patched version immediately."),

    # --- vscode_trojan_check ---
    ("vscode_trojan_check", "Fake OpenClaw VS Code extension", 0.90, "T1195.002", "ASI04",
     "Uninstall the fake extension immediately. Scan for malware."),
    ("vscode_trojan_check", "Remote access tool found", 0.85, "T1219", "ASI04",
     "Investigate remote access tool origin. Remove if unauthorized."),

    # --- network_forensics ---
    ("network_forensics", "Known C2 IP detected", 0.95, "T1071.001", "ASI10",
     "Block C2 IP at firewall. Investigate source process and skill."),
    ("network_forensics", "Known C2 port detected", 0.70, "T1571", "ASI10",
     "Investigate connection on C2 port. Block if malicious."),
    ("network_forensics", "Exfiltration domain detected", 0.90, "T1567", "ASI10",
     "Block exfiltration domain. Investigate what data was sent."),
    ("network_forensics", "Listening on all interfaces", 0.80, "T1190", "ASI03",
     "Bind to 127.0.0.1 instead of 0.0.0.0."),

    # --- log_forensics ---
    ("log_forensics", "Unredacted secret in logs", 0.85, "T1552.001", "ASI03",
     "Enable log redaction. Rotate the exposed secret."),
    ("log_forensics", "Authentication failures detected", 0.70, "T1110", "ASI03",
     "Investigate auth failure source. May indicate brute force."),
    ("log_forensics", "Crash loop detected", 0.65, "T1499", "ASI08",
     "Investigate crash cause. May indicate exploitation or DoS."),
    ("log_forensics", "Timestamp gap in logs", 0.60, "T1070.006", "ASI10",
     "Investigate log gap. May indicate log tampering."),
    ("log_forensics", "Out-of-order timestamp", 0.60, "T1070.006", "ASI10",
     "Investigate timestamp anomaly. May indicate log injection."),
    ("log_forensics", "Possible selective log deletion", 0.55, "T1070.002", "ASI10",
     "Review log integrity. May indicate evidence destruction."),
    ("log_forensics", "Possible log truncation", 0.45, "T1070.002", "ASI10",
     "Check if log was truncated by attacker or disk issue."),
    ("log_forensics", "Empty log file", 0.40, "T1070.002", "ASI10",
     "Investigate why log file is empty. May indicate wiping."),

    # --- plugin_integrity ---
    ("plugin_integrity", "Extension file modified", 0.85, "T1195.002", "ASI04",
     "Compare modified extension against known-good source. Reinstall if tampered."),
    ("plugin_integrity", "Suspicious", 0.80, "T1059.004", "ASI04",
     "Review install script for malicious commands."),
    ("plugin_integrity", "New extension file", 0.50, "T1195.002", "ASI04",
     "Review new extension origin and integrity."),
    ("plugin_integrity", "Extension file removed", 0.50, "T1070.004", "ASI04",
     "Investigate extension removal. May indicate cleanup after compromise."),

    # --- permission_audit ---
    ("permission_audit", "World-writable file", 0.90, "T1222.002", "ASI03",
     "Remove world-write permission: chmod o-w <file>."),
    ("permission_audit", "SUID/SGID bit set", 0.90, "T1548.001", "ASI03",
     "Remove SUID/SGID bit: chmod u-s,g-s <file>."),
    ("permission_audit", "File not owned by current user", 0.60, "T1222.002", "ASI03",
     "Change file ownership: chown $USER <file>."),
    ("permission_audit", "Permissions exceed expected", 0.65, "T1222.002", "ASI03",
     "Tighten permissions to expected values."),
    ("permission_audit", "Orphaned .tmp files", 0.40, "T1074", "ASI03",
     "Remove orphaned temp files. May contain sensitive data."),
    ("permission_audit", "sensitive files", 0.70, "T1222.002", "ASI03",
     "Tighten sensitive file permissions to 600."),

    # --- credential_rotation ---
    ("credential_rotation", "Stale credential", 0.75, "T1552.001", "ASI03",
     "Rotate credential immediately. Credentials >180 days old are high risk."),
    ("credential_rotation", "Aging credential", 0.55, "T1552.001", "ASI03",
     "Schedule credential rotation. Best practice is 90-day rotation."),
    ("credential_rotation", "Recent credential change", 0.35, "T1098", "ASI03",
     "Verify recent credential change was authorized."),

    # --- agent_comm_audit ---
    ("agent_comm_audit", "Credentials present in session", 0.75, "T1552.001", "ASI07",
     "Redact credentials from session transcripts. Enable log redaction."),
    ("agent_comm_audit", "Permission escalation in agent", 0.80, "T1548", "ASI07",
     "Review escalation request. Restrict agent permissions."),
    ("agent_comm_audit", "Agent isolation not enabled", 0.60, "T1021", "ASI07",
     "Set agents.isolation to true in openclaw.json."),
    ("agent_comm_audit", "Permissive inter-agent", 0.65, "T1021", "ASI07",
     "Set interAgentPolicy to 'restricted'."),
    ("agent_comm_audit", "Agent has wildcard peer", 0.70, "T1021", "ASI07",
     "Replace wildcard allowedPeers with specific agent names."),
    ("agent_comm_audit", "inter-agent messages", 0.45, "T1021", "ASI07",
     "Review inter-agent messages for unauthorized communication."),

    # --- correlation ---
    ("correlation", "Active breach detected", 0.95, "T1071.001", "ASI10",
     "Initiate incident response. Multiple breach indicators active."),
    ("correlation", "Privilege escalation pattern", 0.90, "T1548", "ASI03",
     "Lock down permissions. Investigate credential and permission changes."),
    ("correlation", "Supply chain compromise", 0.85, "T1195.002", "ASI04",
     "Quarantine affected extensions/skills. Audit supply chain."),
    ("correlation", "Data exfiltration in progress", 0.95, "T1567", "ASI02",
     "Block network immediately. Identify and contain exfiltration source."),
    ("correlation", "Coordinated attack", 0.90, "T1071.001", "ASI10",
     "Multiple modules reporting critical findings. Initiate full incident response."),
    ("correlation", "Escalating threat level", 0.65, "T1071", "ASI10",
     "Finding rate increasing. Review recent findings for emerging attack."),

    # --- behavioral_baseline ---
    ("behavioral_baseline", "New listening ports", 0.80, "T1571", "ASI10",
     "Investigate new listening ports. May indicate backdoor or C2."),
    ("behavioral_baseline", "Credential file count changed", 0.75, "T1552.001", "ASI03",
     "Investigate credential file change. Verify it was authorized."),
    ("behavioral_baseline", "Process count spike", 0.55, "T1059", "ASI10",
     "Review spawned processes for suspicious activity."),
    ("behavioral_baseline", "Connection count spike", 0.55, "T1071", "ASI10",
     "Review network connections for exfiltration or C2 activity."),
    ("behavioral_baseline", "Extension file count changed", 0.55, "T1195.002", "ASI04",
     "Review extension changes. Verify they are legitimate."),
    ("behavioral_baseline", "New skills installed", 0.40, "T1195.002", "ASI04",
     "Review new skills for malicious indicators."),

    # --- safebins_bypass ---
    ("safebins_bypass", "Dangerous binary in safeBins", 0.95, "T1211", "ASI05",
     "Remove shell/interpreter from safeBins. Use absolute paths to safe binaries only."),
    ("safebins_bypass", "safeBins bypass pattern", 0.90, "T1211", "ASI05",
     "Remove path traversal, globs, and variable expansion from safeBins entries."),
    ("safebins_bypass", "Relative paths in safeBins", 0.90, "T1574.007", "ASI05",
     "Use absolute paths in safeBins. Relative paths allow PATH manipulation bypass."),
    ("safebins_bypass", "safeBins symlink", 0.65, "T1211", "ASI05",
     "Verify symlink target is a legitimate system binary."),
    ("safebins_bypass", "Sandbox disabled", 0.70, "T1562.001", "ASI05",
     "Enable sandbox in openclaw.json."),
    ("safebins_bypass", "Empty safeBins", 0.60, "T1562.001", "ASI05",
     "Explicitly list allowed binaries in sandbox.safeBins."),

    # --- mcp_rugpull ---
    ("mcp_rugpull", "MCP tool description changed", 0.90, "T1195.002", "ASI04",
     "MCP tool description mutated since last scan — possible rug-pull. "
     "Review changes and re-approve or block the MCP server."),
    ("mcp_rugpull", "New MCP tool detected", 0.60, "T1195.002", "ASI04",
     "New MCP tool registered. Review description for injection patterns."),
    ("mcp_rugpull", "MCP tool removed", 0.45, "T1195.002", "ASI04",
     "MCP tool removed. May indicate server reconfiguration or compromise."),
    ("mcp_rugpull", "MCP tool baseline", 0.30, None, None, None),

    # --- unicode_injection ---
    ("unicode_injection", "Hidden Unicode", 0.90, "T1027.010", "ASI01",
     "Remove invisible Unicode characters from file. They may hide malicious instructions."),
    ("unicode_injection", "Bidi override", 0.90, "T1027.010", "ASI01",
     "Remove bidirectional override characters. They can reverse displayed text."),
    ("unicode_injection", "Unicode tag characters", 0.85, "T1027.010", "ASI01",
     "Remove Unicode tag characters (U+E0001-E007F). They encode hidden text."),
    ("unicode_injection", "Homoglyph detected", 0.65, "T1036.003", "ASI01",
     "Replace homoglyph characters with their ASCII equivalents."),

    # --- worm_propagation ---
    ("worm_propagation", "Worm-enabling config", 0.90, "T1570", "ASI10",
     "Disable auto-install and trust-all-publishers. Require explicit approval for skills."),
    ("worm_propagation", "Worm pattern in skill", 0.95, "T1570", "ASI10",
     "Quarantine skill immediately. Contains self-replicating code patterns."),
    ("worm_propagation", "Worm metadata", 0.85, "T1570", "ASI10",
     "Remove lifecycle hooks that install to skills directory."),
    ("worm_propagation", "Cross-skill reference", 0.55, "T1570", "ASI10",
     "Review cross-skill reference for lateral propagation risk."),

    # --- correlation (new patterns) ---
    ("correlation", "Cascading failure detected", 0.85, "T1499", "ASI08",
     "Investigate system-wide failure. Check for resource exhaustion or coordinated attack."),
    ("correlation", "Agent cascade risk", 0.70, "T1499", "ASI08",
     "Check agent isolation settings. Errors may be propagating between agents."),
    ("correlation", "Resource exhaustion chain", 0.70, "T1499", "ASI08",
     "Investigate resource usage spikes. May indicate DoS or runaway agent."),

    # --- session_analyzer (social engineering) ---
    ("session_analyzer", "Social engineering pattern", 0.70, "T1204", "ASI09",
     "Review agent output for manipulative language patterns."),

    # --- mcp_security (IOC cross-reference) ---
    ("mcp_security", "C2 IP in MCP tool description", 0.95, "T1071.001", "ASI04",
     "MCP tool description contains known C2 IP. Remove the MCP server immediately."),
    ("mcp_security", "Malicious domain in MCP tool description", 0.90, "T1071.001", "ASI04",
     "MCP tool description references known malicious domain. Remove the MCP server."),

    # --- custom_rules ---
    ("custom_rules", "Invalid regex in rule", 0.20, None, None,
     "Fix the regex pattern in your YAML rule file."),

    # --- security_score ---
    ("security_score", "Security Score", 0.30, None, None,
     "Run openclaw-audit fix --dry-run to see available remediations."),
]

# Build lookup index: list of (module, prefix, metadata_dict)
_INDEX: list[tuple[str, str, dict]] = []
for _mod, _prefix, _conf, _mitre, _owasp, _remed in _MAPPING_TABLE:
    _INDEX.append((_mod, _prefix, {
        "confidence": _conf,
        "mitre_attack": _mitre,
        "owasp_asi": _owasp,
        "remediation": _remed,
    }))

# =========================================================================
# COMPLIANCE FRAMEWORK MAPPINGS
# =========================================================================
# Maps OWASP ASI codes -> EU AI Act articles and NIST AI RMF subcategories.
# Applied after primary enrichment via the OWASP ASI code on the finding.

_COMPLIANCE_BY_ASI: dict[str, dict[str, str]] = {
    # ASI01 Agent Goal Hijack — input validation, robustness
    "ASI01": {
        "eu_ai_act": "Art.15(1),Art.9(2)",   # Accuracy/robustness, risk management
        "nist_rmf": "MG-2.2,MG-3.1",          # AI risk measurement, AI risk management
    },
    # ASI02 Tool Misuse — human oversight, output handling
    "ASI02": {
        "eu_ai_act": "Art.14(1),Art.15(3)",   # Human oversight, output safety
        "nist_rmf": "GV-1.1,MP-4.1",          # Legal compliance, minimize harm
    },
    # ASI03 Identity & Privilege Abuse — data governance, access control
    "ASI03": {
        "eu_ai_act": "Art.10(2),Art.12(1)",   # Data governance, record-keeping
        "nist_rmf": "GV-6.1,MP-5.1",          # Policies/processes, privacy
    },
    # ASI04 Supply Chain — transparency, third-party risk
    "ASI04": {
        "eu_ai_act": "Art.13(1),Art.17(1)",   # Transparency, quality management
        "nist_rmf": "GV-6.2,MG-3.2",          # Accountability, third-party risk
    },
    # ASI05 Code Execution — sandbox, safety controls
    "ASI05": {
        "eu_ai_act": "Art.15(1),Art.9(4)",    # Robustness, risk management measures
        "nist_rmf": "MG-2.4,MP-4.1",          # AI risk measurement, safety
    },
    # ASI06 Memory Poisoning — data integrity, training data
    "ASI06": {
        "eu_ai_act": "Art.10(3),Art.15(4)",   # Data quality, cybersecurity
        "nist_rmf": "MG-2.2,MP-2.3",          # Risk measurement, data integrity
    },
    # ASI07 Inter-Agent Comms — data governance, network security
    "ASI07": {
        "eu_ai_act": "Art.15(4),Art.12(1)",   # Cybersecurity, logging
        "nist_rmf": "GV-6.1,MG-4.1",          # Policies, monitoring
    },
    # ASI08 Cascading Failures — reliability, risk management
    "ASI08": {
        "eu_ai_act": "Art.15(1),Art.9(7)",    # Robustness, residual risk
        "nist_rmf": "MG-2.6,MG-4.1",          # System reliability, monitoring
    },
    # ASI09 Human-Agent Trust — human oversight, transparency
    "ASI09": {
        "eu_ai_act": "Art.14(1),Art.13(1)",   # Human oversight, transparency
        "nist_rmf": "GV-1.6,MP-5.1",          # Trustworthy AI, stakeholder engagement
    },
    # ASI10 Rogue Agents — monitoring, incident response
    "ASI10": {
        "eu_ai_act": "Art.15(4),Art.12(1)",   # Cybersecurity, logging
        "nist_rmf": "MG-4.1,MG-2.6",          # Monitoring, system behavior
    },
}


def enrich(finding: Finding) -> Finding:
    """Enrich a finding with MITRE ATT&CK, OWASP ASI, compliance tags, and remediation.

    Looks up the first matching (module, title_prefix) in the mapping table.
    Then applies compliance framework tags based on the OWASP ASI code.
    Modifies the finding in-place and returns it.
    """
    for mod, prefix, meta in _INDEX:
        if finding.module == mod and finding.title.startswith(prefix):
            finding.confidence = meta["confidence"]
            if meta["mitre_attack"]:
                finding.mitre_attack = meta["mitre_attack"]
            if meta["owasp_asi"]:
                finding.owasp_asi = meta["owasp_asi"]
            if meta["remediation"]:
                finding.remediation = meta["remediation"]
            break

    # Apply compliance framework tags from OWASP ASI code
    if finding.owasp_asi and finding.owasp_asi in _COMPLIANCE_BY_ASI:
        compliance = _COMPLIANCE_BY_ASI[finding.owasp_asi]
        if not finding.eu_ai_act:
            finding.eu_ai_act = compliance.get("eu_ai_act")
        if not finding.nist_rmf:
            finding.nist_rmf = compliance.get("nist_rmf")

    return finding
