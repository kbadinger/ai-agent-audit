<!-- SUBFRAME AUTO-GENERATED FILE -->
<!-- Purpose: Quick onboarding guide for developers and AI assistants -->
<!-- For Claude: Read this FIRST to quickly understand how to work with this project. Contains setup instructions, common commands, and key files to know. -->
<!-- Last Updated: 2026-07-19 -->

# ai-agent-audit - Quick Start Guide

## Setup

```bash
# Clone and create an isolated development environment
git clone <repo-url>
cd ai-agent-audit
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Common Commands

```bash
# One-shot scan
ai-agent-audit sweep

# Strict scan for CI/automation
ai-agent-audit sweep --fail-on degraded

# Test
pytest tests/ -q

# Coverage regression check
coverage run -m pytest tests/ -q
coverage report

# Critical lint checks used by CI
ruff check --select E9,F63,F7,F82 .
```

## Key Files

| File | Purpose |
|------|---------|
| `.subframe/STRUCTURE.json` | Module map and architecture |
| `.subframe/PROJECT_NOTES.md` | Decisions and context |
| `.subframe/tasks/*.md` | Sub-Task files (markdown + YAML frontmatter) |
| `.subframe/tasks.json` | Sub-Task index (auto-generated) |
| `.subframe/QUICKSTART.md` | This file |
| `.subframe/docs-internal/` | Internal documentation |

## Project Structure

```
ai-agent-audit/
├── .subframe/              # SubFrame project files
│   ├── config.json         # Project configuration
│   ├── STRUCTURE.json      # Module map
│   ├── PROJECT_NOTES.md    # Session notes
│   ├── tasks/              # Sub-Task markdown files
│   │   └── <id>.md         # Individual task (YAML frontmatter)
│   ├── tasks.json          # Sub-Task index (auto-generated)
│   ├── QUICKSTART.md       # This file
│   └── docs-internal/      # Internal documentation
├── AGENTS.md               # AI instructions (tool-agnostic)
├── CLAUDE.md               # Claude Code instructions
├── src/ai_agent_audit/     # Python package
├── tests/                  # Pytest suite
├── pyproject.toml          # Package, dependencies, and tooling
└── README.md               # User-facing documentation
```

## For AI Assistants (Claude)

1. **First**: Read `.subframe/STRUCTURE.json` for architecture overview
2. **Then**: Check `.subframe/PROJECT_NOTES.md` for current context and decisions
3. **Check**: `.subframe/tasks.json` for pending sub-tasks
4. **Follow**: Existing code patterns and conventions
5. **Update**: These files as you make changes

## Quick Context

Python 3.10+ security audit daemon for OpenClaw and Hermes. Version 0.4.0
parses current OpenClaw JSON5 and Hermes YAML, combines native product audits
with independent monitors/sweeps, reports scan completeness explicitly, and
exports findings in seven automation-friendly formats.
