# Security Policy

AgentOps Watchtower handles local traces, MCP configuration, tool descriptors, and security reports. Treat those artifacts as sensitive.

## Supported Versions

Security fixes target the latest `main` branch and the latest published major version.

## Reporting A Vulnerability

Please do not open a public issue with exploit details, real secrets, private traces, or private MCP config.

Use a private GitHub security advisory when available, or contact the maintainer directly through the GitHub profile linked from this repository.

Include:

- affected command or module;
- minimal reproduction using fake secrets and fake MCP tools;
- expected impact;
- whether local files, environment variables, or network calls are involved.

## Project Security Defaults

- Core commands are local-first.
- No paid API or cloud service is required.
- Secret-looking fields are redacted during import.
- MCP server inventory does not execute configured servers.
- `protect-mcp` writes a protected copy by default and writes a backup before in-place changes.
- Evidence bundles can be signed and later verified for tampering.

## Out Of Scope

This project cannot guarantee that an arbitrary third-party MCP server is safe. Watchtower provides deterministic local inspection, policy gates, runtime proxying for supported stdio flows, and reproducible evidence to support human review.
