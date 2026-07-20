---
id: task-mn92opn265ad4
title: "Extract hardcoded IOC data to external file"
description: "The ioc.py module contains hardcoded C2 IPs, domains, and publisher lists inline. Moving the built-in IOC data to a bundled JSON file (e.g., data/ioc-builtin.json) would make updates cleaner and separate data from code, while keeping the ioc_confidence/aging logic in Python."
userRequest: "Suggested by AI onboarding analysis"
acceptanceCriteria: ""
status: pending
priority: low
category: refactor
createdAt: 2026-03-27T15:45:11.629Z
updatedAt: 2026-03-27T15:45:11.629Z
completedAt: null
blockedBy: []
blocks: []
---

The ioc.py module contains hardcoded C2 IPs, domains, and publisher lists inline. Moving the built-in IOC data to a bundled JSON file (e.g., data/ioc-builtin.json) would make updates cleaner and separate data from code, while keeping the ioc_confidence/aging logic in Python.
