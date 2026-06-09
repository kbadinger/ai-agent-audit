# Changelog

All notable changes to ai-agent-audit are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## [0.3.0] - 2026-06-08 — Threat-Landscape Currency Refresh (Sprint 12)

### Added
- **Real IOC feed (abuse.ch ThreatFox)** — `ioc_updater` can fetch the no-auth
  ThreatFox recent-IOC export and merge it into the IOC database. New
  `ai-agent-audit update-ioc --threatfox`; `--url`/`--file` now auto-detect the
  ThreatFox schema alongside the native schema.
- **`agent_version_check` sweep** — version-gated CVE detection. Covers the
  OpenClaw "Claw Chain" cluster (CVE-2026-44112/44113/44115/44118, patched in
  2026.4.22) and Hermes core CVEs (CVE-2026-9368, CVE-2026-10548). Resolves the
  installed version from the agent config `version` key or the profile's
  version command.
- **`hermes_hardening` sweep** — Hermes-specific default-posture checks: unset
  `HERMES_WRITE_SAFE_ROOT`, container approval auto-bypass, `--yolo` mode, and
  agent-writable skill manifests declaring `setup.commands`.
- **Promptware / C2-brainworm detection** — `memory_poisoning_monitor` now flags
  memory/context-file instructions that make the agent register with, beacon to,
  or phone home to an external controller.
- **Indirect-injection patterns** — shared `INJECTION_PATTERNS` gains AI-targeted
  indirect injection, tool-result injection, and conceal-from-user markers
  (flow to `session_analyzer` and `mcp_security`).
- **GitHub Actions CI** (`.github/workflows/ci.yml`) — runs the test suite on
  Python 3.10–3.12, then self-scans the repo and uploads SARIF to Code Scanning.
- Per-agent `version_command` and `skills_relpath` on `AgentProfile`.
- **Live IOC feed in the daemon** — the ThreatFox feed auto-refreshes on the
  sweep cycle (default every 6h; disable with `AI_AGENT_AUDIT_IOC_AUTOREFRESH=0`,
  tune with `AI_AGENT_AUDIT_IOC_REFRESH_HOURS`). Fail-safe: network errors are
  logged and never break a sweep.

### Changed
- `AgentProfile.skills_path` is now profile-relative (`workspace/skills` for
  OpenClaw, `skills` for Hermes, per the published Hermes layout).
- New mapping entries (MITRE/OWASP/remediation) for every new finding type.
- Version bumped 0.2.0 → 0.3.0.

### Fixed
- `MemoryPoisoningMonitor.name` was `memory_poisoning` but the enrichment table
  keyed on `memory_poisoning_monitor`, so real memory-poisoning findings were
  never enriched with MITRE/OWASP/remediation tags. Renamed to match.
- **Fed IOCs never reached detection.** `update-ioc` (`--url`/`--file`/`--threatfox`)
  wrote `ioc-custom.json`, but the sweeps/monitors import the hardcoded `ioc.*`
  sets directly and nothing loaded the custom file into them — so no fetched
  indicator ever participated in matching. New `ioc.load_custom_iocs()` merges the
  file into those sets in place (incl. the `EXFIL_DOMAINS` snapshot) at engine
  startup and after each refresh. Verified live: 5,493 ThreatFox indicators became
  matchable.
