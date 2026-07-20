---
id: task-mn92opn192t5d
title: "Add integration test for full sweep cycle"
description: "No test exercises the AuditEngine.run_all_sweeps() path end-to-end with real monitor/sweep registration, enrichment, calibration, and storage. An integration test with a temp SQLite DB and a few representative sweeps would catch pipeline regressions."
userRequest: "Suggested by AI onboarding analysis"
acceptanceCriteria: ""
status: completed
priority: medium
category: test
createdAt: 2026-03-27T15:45:11.629Z
updatedAt: 2026-07-19T23:46:08Z
completedAt: 2026-07-19T23:46:08Z
blockedBy: []
blocks: []
---

No test exercises the AuditEngine.run_all_sweeps() path end-to-end with real monitor/sweep registration, enrichment, calibration, and storage. An integration test with a temp SQLite DB and a few representative sweeps would catch pipeline regressions.

## Notes

[2026-07-19] Started as part of the approved 0.4.0 correctness refresh. The integration coverage will exercise scan status, alert dispatch, persistence, and stale-finding resolution.

[2026-07-19] Completed with end-to-end engine tests covering successful storage and alert delivery, clean-scan stale resolution, degraded-scan evidence retention, and explicit exception results.

## Steps

- [x] Exercise successful sweep storage and alerts
- [x] Exercise degraded/error sweep reporting
- [x] Exercise stale-finding resolution
