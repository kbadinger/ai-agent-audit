# Security Policy

## Supported Versions

Security fixes are provided for the latest minor release line.

| Version | Supported |
|---------|-----------|
| 0.4.x   | Yes       |
| < 0.4   | No        |

## Reporting a Vulnerability

Please do not disclose suspected vulnerabilities in a public issue, discussion,
or pull request. Use GitHub's private vulnerability reporting form:

https://github.com/kbadinger/ai-agent-audit/security/advisories/new

Include the affected version, operating system, agent profile, reproduction
steps, impact, and any suggested mitigation. Remove API keys, tokens, session
content, and other sensitive data from logs or examples.

You should receive an acknowledgment within three business days. We will
validate the report, coordinate remediation and disclosure with the reporter,
and publish an advisory when users need to take action. Please allow a
reasonable remediation window before public disclosure.

This process covers vulnerabilities in ai-agent-audit itself. Vulnerabilities
in OpenClaw, Hermes, or another integrated product should also be reported to
that upstream project's security contact.
