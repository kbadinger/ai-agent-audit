---
id: task-mn92opn1jj74d
title: "Add triage CLI command for feedback loop"
description: "The PrecisionTracker and Finding model support triage_status (confirmed/false_positive/dismissed), but there's no CLI command to actually triage findings. Add 'openclaw-audit triage' to list active findings and mark them, enabling the confidence calibration feedback loop to function."
userRequest: "Suggested by AI onboarding analysis"
acceptanceCriteria: ""
status: completed
priority: high
category: feature
createdAt: 2026-03-27T15:45:11.629Z
updatedAt: 2026-07-19T23:46:08Z
completedAt: 2026-07-19T23:46:08Z
blockedBy: []
blocks: []
---

The PrecisionTracker and Finding model support triage_status (confirmed/false_positive/dismissed), but there's no CLI command to actually triage findings. Add 'openclaw-audit triage' to list active findings and mark them, enabling the confidence calibration feedback loop to function.

## Notes

[2026-07-19] Reconciled as already completed: `ai-agent-audit triage` lists findings and supports `--confirm`, `--fp`, and `--dismiss`, refreshing precision scores after feedback.

## Steps

- [x] List triageable active findings
- [x] Record confirm/false-positive/dismissed status
- [x] Refresh precision calibration
