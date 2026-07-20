# Contributing

Thanks for helping improve ai-agent-audit. Bug reports, focused fixes, tests,
documentation improvements, and new agent-specific detection research are
welcome.

## Before You Start

- Search existing issues before opening a duplicate.
- Keep changes focused; avoid mixing behavior changes with unrelated refactors.
- Do not include credentials, private session content, live victim data, or
  weaponized payloads in issues, tests, or pull requests.
- Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Development Setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest tests/ -v
coverage run -m pytest tests/ -q
coverage report
ruff check --select E9,F63,F7,F82 .
```

The supported Python versions are 3.10 through 3.14. CI currently runs on
Linux; macOS is a primary runtime target and should be exercised for changes
that touch process, network, notification, permissions, or daemon behavior.

## Pull Requests

Explain what changed, why it is needed, its user impact, and how it was tested.
Add or update tests for behavior changes. Update the README or changelog when a
public interface, installation step, supported platform, or detection claim
changes.

New threat-intelligence claims must link to a durable primary source such as an
upstream security advisory, NVD record, or original research publication.
