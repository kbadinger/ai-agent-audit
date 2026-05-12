# ai-agent-audit - Internal Documentation

This directory is for **internal project documentation** — architecture decisions, API references, setup guides, and anything that helps developers (human or AI) understand the project.

## What goes here

- **Architecture Decision Records (ADRs)** — why we chose X over Y
- **API documentation** — internal/external API notes, endpoint specs
- **Setup & deployment guides** — environment setup, deploy procedures
- **Design specs** — feature designs, data models, flow diagrams
- **Third-party references** — integration notes, credential structures, env var docs
- **Troubleshooting** — known issues, debugging guides, gotchas

## What does NOT go here

- Public-facing docs (use `docs/` for GitHub Pages or similar)
- AI session context (use `.subframe/PROJECT_NOTES.md`, `.subframe/STRUCTURE.json`, `.subframe/tasks.json`)
- Temporary notes or scratch files

## Suggested structure

```
docs-internal/
├── README.md          # This file
├── architecture.md    # System architecture overview
├── adr/               # Architecture Decision Records
│   └── 001-example.md
├── api/               # API documentation
├── setup/             # Setup and deployment guides
└── refs/              # Third-party references and integration notes
```

---

*Created by SubFrame project initialization.*
