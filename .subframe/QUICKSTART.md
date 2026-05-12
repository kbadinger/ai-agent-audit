<!-- SUBFRAME AUTO-GENERATED FILE -->
<!-- Purpose: Quick onboarding guide for developers and AI assistants -->
<!-- For Claude: Read this FIRST to quickly understand how to work with this project. Contains setup instructions, common commands, and key files to know. -->
<!-- Last Updated: 2026-03-27 -->

# ai-agent-audit - Quick Start Guide

## Setup

```bash
# Clone and install
git clone <repo-url>
cd ai-agent-audit
npm install  # or appropriate package manager
```

## Common Commands

```bash
# Development
npm run dev

# Build
npm run build

# Test
npm test
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
├── src/                    # Source code
└── ...
```

## For AI Assistants (Claude)

1. **First**: Read `.subframe/STRUCTURE.json` for architecture overview
2. **Then**: Check `.subframe/PROJECT_NOTES.md` for current context and decisions
3. **Check**: `.subframe/tasks.json` for pending sub-tasks
4. **Follow**: Existing code patterns and conventions
5. **Update**: These files as you make changes

## Quick Context

*Add a brief summary of what this project does and its current state here*
