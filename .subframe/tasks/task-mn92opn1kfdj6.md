---
id: task-mn92opn1kfdj6
title: "Expand test coverage beyond 6 test files"
description: "Only 6 test files exist covering db, config_watcher, session_analyzer, security_score, learning_cycle, and mappings. The 20 sweeps, 5 remaining monitors, remediation engine, alerting, daemon, report generator, IOC updater, and environment profiler all lack dedicated tests. Prioritize tests for remediate.py (destructive operations), alerting.py (notification dispatch), and the correlation sweep (attack chain logic)."
userRequest: "Suggested by AI onboarding analysis"
acceptanceCriteria: ""
status: completed
priority: high
category: test
createdAt: 2026-03-27T15:45:11.629Z
updatedAt: 2026-07-19T23:46:08Z
completedAt: 2026-07-19T23:46:08Z
blockedBy: []
blocks: []
---

Only 6 test files exist covering db, config_watcher, session_analyzer, security_score, learning_cycle, and mappings. The 20 sweeps, 5 remaining monitors, remediation engine, alerting, daemon, report generator, IOC updater, and environment profiler all lack dedicated tests. Prioritize tests for remediate.py (destructive operations), alerting.py (notification dispatch), and the correlation sweep (attack chain logic).

## Notes

[2026-07-19] Resumed for the approved correctness refresh, prioritizing current agent-config parsing, remediation safety, permission-denied visibility, advisory matching, IOC expiry, and engine lifecycle behavior.

[2026-07-19] Completed with dedicated adapter, current-schema sweep, advisory, remediation, native-audit, IOC lifecycle, and engine integration test files. The suite expanded to 264 tests and branch coverage increased from 35% to 43%, with a 40% regression floor enforced in CI.

## Steps

- [x] Add current OpenClaw and Hermes configuration tests
- [x] Add remediation safety tests
- [x] Add engine lifecycle and degraded-visibility tests
- [x] Add advisory and IOC expiry tests
